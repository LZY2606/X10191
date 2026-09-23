package compass.dwarf

import compass.binary.ByteReader
import compass.binary.DwarfCorruptException
import compass.elf.ElfFile

/**
 * Bounded DWARF parser. Unknown forms and out-of-range references are isolated per
 * compilation unit: the unit is marked corrupt at the failing offset and already
 * decoded DIEs stay available with a warning. The cursor never resumes after an
 * unknown form (that would silently desync and manufacture DIEs).
 */
class DwarfParser(private val maxDies: Int = 500_000) {

    fun parse(elf: ElfFile): DwarfBundle {
        val sections = DwarfSections.fromElf(elf)
        val warnings = mutableListOf<String>()
        val r = { name: String -> sections[name]?.let { ByteReader(it, elf.littleEndian) } }

        val abbrevInfo = sections[infoSectionName(sections)]?.let { ByteReader(it, elf.littleEndian) }
        val abbrevs = LinkedHashMap<Long, List<AbbrevEntry>>()
        if (abbrevInfo != null) {
            try {
                parseAbbrevSection(abbrevInfo, abbrevs)
            } catch (e: DwarfCorruptException) {
                warnings.add(".debug_abbrev truncated at ${e.message}")
            }
        }

        val units = mutableListOf<CompileUnit>()
        val info = sections[infoSectionName(sections)]
        if (info != null) {
            parseUnits(ByteReader(info, elf.littleEndian), sections, elf, abbrevs, units, warnings)
        } else {
            warnings.add(if (sections.names.isEmpty()) "no DWARF sections present" else "no .debug_info section")
        }

        val lineHeaders = mutableListOf<LineHeader>()
        val programs = mutableListOf<LineSequence>()
        parseAllLinePrograms(sections, elf, lineHeaders, programs, warnings)

        return DwarfBundle(sections, elf.littleEndian, units, programs, lineHeaders, abbrevs, warnings)
    }

    private fun infoSectionName(s: DwarfSections): String =
        if (s[".debug_info"] != null) ".debug_info" else ".debug_info.dwo"

    private fun abbrevSectionName(s: DwarfSections): String =
        if (s[".debug_abbrev"] != null) ".debug_abbrev" else ".debug_abbrev.dwo"

    // ---------------------------------------------------------------- units

    private fun parseAllLinePrograms(
        sections: DwarfSections,
        elf: ElfFile,
        headers: MutableList<LineHeader>,
        programs: MutableList<LineSequence>,
        warnings: MutableList<String>
    ) {
        val names = listOf(".debug_line", ".debug_line.dwo")
        for (name in names) {
            if (sections[name] == null) continue
            parseAllLineProgramsInSection(name, sections, elf.littleEndian, headers, programs, warnings)
        }
        // Resolve string references in line headers after all programs are known.
        val strResolver = DwarfStringResolver(sections, elf.littleEndian)
        for (h in headers) resolveLineHeaderStrings(h, strResolver, warnings)
    }

    private fun parseUnits(
        reader: ByteReader,
        sections: DwarfSections,
        elf: ElfFile,
        abbrevs: Map<Long, List<AbbrevEntry>>,
        out: MutableList<CompileUnit>,
        warnings: MutableList<String>
    ) {
        while (reader.remaining > 0) {
            val unitStart = reader.pos
            try {
                val unit = parseOneUnit(reader, sections, elf, abbrevs)
                out.add(unit)
                unit.warnings.forEach { warnings.add("CU@0x${unit.offset.toString(16)}: $it") }
            } catch (e: DwarfCorruptException) {
                warnings.add("CU@0x${unitStart.toString(16)} abandoned: ${e.message}")
                // Cannot resync safely: length header itself was unreadable.
                if (reader.remaining == reader.data.size - unitStart && unitStart == reader.pos) break
                break
            }
        }
    }

    private fun parseOneUnit(
        reader: ByteReader,
        sections: DwarfSections,
        elf: ElfFile,
        abbrevs: Map<Long, List<AbbrevEntry>>
    ): CompileUnit {
        val unitOffset = reader.pos.toLong()
        val lengthFirst = reader.u32()
        val dwarf64: Boolean
        val unitLength: Long
        when (lengthFirst) {
            0xffffffffL -> {
                dwarf64 = true
                unitLength = reader.u64()
            }
            in 0..0xfffffff0L -> {
                dwarf64 = false
                unitLength = lengthFirst
            }
            else -> throw DwarfCorruptException("reserved 32-bit unit length 0x${lengthFirst.toString(16)}")
        }
        val afterLength = reader.pos
        val unitEnd = afterLength.toLong() + unitLength
        if (unitEnd > reader.data.size) {
            throw DwarfCorruptException("unit at 0x${unitOffset.toString(16)} overruns section " +
                "(end 0x${unitEnd.toString(16)} > ${reader.data.size})")
        }
        val version = reader.u16()
        if (version !in 2..5) throw DwarfCorruptException("unsupported DWARF version $version")

        var unitType = 0
        if (version >= 5) unitType = reader.u8()
        val addressSize = if (version >= 5) reader.u8() else -1
        val abbrevOffset = if (dwarf64) reader.u64() else reader.u32()
        val finalAddressSize = if (version >= 5) addressSize else reader.u8()

        if (version >= 5 && (unitType == 0x01 || unitType == 0x04 || unitType == 0x02 || unitType == 0x03)) {
            // DW_UT_compile/skeleton/split_compile/split_type: signature/dwo_id field follows for split variants
            if (unitType == 0x04 || unitType == 0x02 || unitType == 0x03) reader.word(if (dwarf64) 8 else 4)
        }
        val headerSize = reader.pos - afterLength

        val abbrevSection = sections[abbrevSectionName(sections)]
            ?: throw DwarfCorruptException("missing ${abbrevSectionName(sections)}")
        val abbrevTable = abbrevs[abbrevOffset]
            ?: parseAbbrevAt(ByteReader(abbrevSection, elf.littleEndian), abbrevOffset)
                .also { (abbrevs as MutableMap)[abbrevOffset] = it }

        val ctx = ParseContext(sections, elf, version, finalAddressSize, dwarf64, unitOffset, unitEnd, this)
        val flat = mutableListOf<Die>()
        val unitWarnings = mutableListOf<String>()
        var corruptAfter: Long? = null
        var root: Die? = null
        try {
            root = parseDieTree(reader, abbrevTable, ctx, flat, 0)
        } catch (e: DwarfCorruptException) {
            corruptAfter = reader.pos.toLong()
            unitWarnings.add("DIE parsing stopped at 0x${reader.pos.toString(16)}: ${e.message}")
        }
        val dwoId = root?.attr(DW.AT_dwo_id)?.let { (it.value as? AttrValue.Constant)?.value }
            ?: root?.attr(DW.AT_GNU_dwo_id)?.let { (it.value as? AttrValue.Constant)?.value }
        val skeleton = unitType == 0x04 || root?.attr(DW.AT_dwo_name) != null ||
            root?.attr(DW.AT_GNU_dwo_name) != null
        return CompileUnit(
            offset = unitOffset,
            version = version,
            unitType = unitType,
            addressSize = finalAddressSize,
            dwarf64 = dwarf64,
            headerSize = headerSize,
            endOffset = unitEnd,
            root = root ?: Die(unitOffset, 0),
            dies = flat,
            dwoId = dwoId,
            isSkeleton = skeleton,
            corruptAfter = corruptAfter,
            warnings = unitWarnings
        ).also {
            if (reader.pos.toLong() != unitEnd) reader.seek(unitEnd.toInt())
        }
    }

    internal class ParseContext(
        val sections: DwarfSections,
        val elf: ElfFile,
        val version: Int,
        val addressSize: Int,
        val dwarf64: Boolean,
        val unitOffset: Long,
        val unitEnd: Long,
        val parser: DwarfParser
    )

    private fun parseDieTree(
        reader: ByteReader,
        table: List<AbbrevEntry>,
        ctx: ParseContext,
        flat: MutableList<Die>,
        depth: Int
    ): Die {
        if (depth > 256) throw DwarfCorruptException("DIE nesting exceeds 256 levels")
        if (flat.size >= maxDies) throw DwarfCorruptException("DIE count limit reached")
        val dieOffset = reader.pos.toLong()
        val code = reader.uleb()
        if (code == 0L) throw DwarfCorruptException("expected root DIE but found null entry at 0x${dieOffset.toString(16)}")
        val entry = table.firstOrNull { it.code == code }
            ?: throw DwarfCorruptException("abbrev code $code not present in table")
        val die = Die(dieOffset, entry.tag)
        for ((name, form) in entry.specs) {
            val value = readAttributeValue(reader, form, ctx, entry)
            die.attributes.add(Attribute(name, form, value))
        }
        flat.add(die)
        if (entry.hasChildren) {
            parseChildren(reader, table, ctx, flat, die, depth + 1)
        }
        return die
    }

    private fun parseChildren(
        reader: ByteReader,
        table: List<AbbrevEntry>,
        ctx: ParseContext,
        flat: MutableList<Die>,
        parent: Die,
        depth: Int
    ) {
        while (reader.pos.toLong() < ctx.unitEnd) {
            val dieOffset = reader.pos.toLong()
            val code = reader.uleb()
            if (code == 0L) return
            if (flat.size >= maxDies) throw DwarfCorruptException("DIE count limit reached")
            if (depth > 256) throw DwarfCorruptException("DIE nesting exceeds 256 levels")
            val entry = table.firstOrNull { it.code == code }
                ?: throw DwarfCorruptException("abbrev code $code not present in table")
            val die = Die(dieOffset, entry.tag)
            for ((name, form) in entry.specs) {
                val value = readAttributeValue(reader, form, ctx, entry)
                die.attributes.add(Attribute(name, form, value))
            }
            die.parent = parent
            parent.children.add(die)
            flat.add(die)
            if (entry.hasChildren) parseChildren(reader, table, ctx, flat, die, depth + 1)
        }
        throw DwarfCorruptException("unterminated DIE children before unit end")
    }

    internal fun resolveReference(raw: Long, cuLocal: Boolean, ctx: ParseContext): Long =
        if (cuLocal) ctx.unitOffset + raw else raw

    companion object {
        internal fun readAttributeValue(
            reader: ByteReader,
            form: Int,
            ctx: ParseContext,
            entry: AbbrevEntry? = null
        ): AttrValue = DwarfFormReader.read(reader, form, ctx, entry)
    }
}
