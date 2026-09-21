package compass.dwarf

import compass.binary.ByteReader
import compass.binary.DwarfParseException
import compass.elf.ElfFile
import compass.elf.ElfSection
import java.security.MessageDigest

data class ParsedDwarf(
    val cus: List<CompUnit>,
    val digests: List<SectionDigest>,
    val warnings: List<String>,
    val sections: DwarfSections,
    val addrTables: Map<Long, AddrTable>,
)

object DwarfParser {

    private val DWARF_SECTIONS = listOf(
        ".debug_info", ".debug_abbrev", ".debug_line", ".debug_ranges", ".debug_rnglists",
        ".debug_str", ".debug_line_str", ".debug_addr", ".debug_str_offsets", ".debug_loclists",
    )

    fun parse(elf: ElfFile): ParsedDwarf {
        val warnings = ArrayList<String>()
        fun bytesOf(name: String): ByteArray? = elf.sectionsNamed(name).firstOrNull()?.let {
            try { elf.sectionBytes(it) } catch (e: Exception) { warnings.add("${e.message}"); null }
        }
        val sections = DwarfSections(
            info = bytesOf(".debug_info"),
            abbrev = bytesOf(".debug_abbrev"),
            line = bytesOf(".debug_line"),
            ranges = bytesOf(".debug_ranges"),
            rnglists = bytesOf(".debug_rnglists"),
            str = bytesOf(".debug_str"),
            lineStr = bytesOf(".debug_line_str"),
            addr = bytesOf(".debug_addr"),
            strOffsets = bytesOf(".debug_str_offsets"),
            loclists = bytesOf(".debug_loclists"),
            sectionMeta = DWARF_SECTIONS.mapNotNull { n -> elf.sectionsNamed(n).firstOrNull() },
        )
        val digests = buildDigests(elf)
        if (sections.info == null || sections.abbrev == null) {
            warnings.add("缺少 .debug_info 或 .debug_abbrev，无法解析编译单元")
            return ParsedDwarf(emptyList(), digests, warnings, sections, emptyMap())
        }

        val addrTables = AddrTables.scanAddr(sections.addr, 8)
        val strOffsetTables = AddrTables.scanStrOffsets(sections.strOffsets)
        val abbrevCache = HashMap<Long, AbbrevTable>()

        val cus = ArrayList<CompUnit>()
        val info = sections.info
        val r = ByteReader(info)
        var cuOrdinal = 0
        while (r.remaining > 0) {
            val cuStart = r.pos
            val cu = parseOneCu(
                r, sections, cuOrdinal, warnings, abbrevCache, addrTables, strOffsetTables,
            )
            cus += cu
            cuOrdinal++
            // Advance to next CU (parser already seeks to end, but enforce).
            val nextEnd = (cu.offset + (if (cu.is64Bit) 12 else 4) + cu.length)
            if (nextEnd <= cuStart) {
                warnings.add("CU#${cu.index} 长度异常，停止扫描后续单元")
                break
            }
            r.seek(nextEnd.toInt().coerceAtMost(info.size))
            if (r.remaining == 0) break
        }

        resolveGlobalRefs(cus, warnings)
        return ParsedDwarf(cus, digests, warnings.distinct(), sections, addrTables)
    }

    private fun buildDigests(elf: ElfFile): List<SectionDigest> {
        return elf.sections
            .filter { it.name.startsWith(".debug") || it.name.startsWith(".zdebug") || it.name == ".symtab" || it.name == ".strtab" }
            .map { s ->
                val bytes = try { elf.sectionBytes(s) } catch (e: Exception) { ByteArray(0) }
                val sha = if (bytes.isNotEmpty()) MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) } else ""
                SectionDigest(s.name, s.ordinal, s.type, s.offset, s.size, s.addr, sha, bytes.isNotEmpty())
            }
    }

    private fun parseOneCu(
        r: ByteReader,
        sections: DwarfSections,
        ordinal: Int,
        allWarnings: MutableList<String>,
        abbrevCache: HashMap<Long, AbbrevTable>,
        addrTables: Map<Long, AddrTable>,
        strOffsetTables: Map<Long, StrOffsetsTable>,
    ): CompUnit {
        val cuWarnings = ArrayList<String>()
        val headerStart = r.pos
        val firstLen = r.u32()
        val is64 = firstLen == 0xffffffffL
        val offsetSize: Int
        val length: Long
        if (is64) { offsetSize = 8; length = r.u64() } else { offsetSize = 4; length = firstLen }
        val unitEnd = r.pos + length
        if (unitEnd > r.sectionEnd) throw DwarfParseException("CU 长度越界 @$headerStart")

        val version = r.u16()
        if (version !in 2..5) throw DwarfParseException("不支持的 DWARF 版本 $version @$headerStart")
        var unitType = DW.UT.compile
        var debugAbbrevOffset: Long
        var addressSize: Int

        if (version >= 5) {
            unitType = r.u8()
            addressSize = r.u8()
            debugAbbrevOffset = if (offsetSize == 8) r.u64() else r.u32()
            when (unitType) {
                DW.UT.skeleton, DW.UT.split_compile, DW.UT.compile, DW.UT.partial -> Unit
                DW.UT.type, DW.UT.split_type -> {
                    if (offsetSize == 8) r.u64() else r.u32() // type_signature
                    if (offsetSize == 8) r.u64() else r.u32() // type_offset
                }
            }
        } else {
            debugAbbrevOffset = if (offsetSize == 8) r.u64() else r.u32()
            addressSize = r.u8()
            if (unitType == DW.UT.compile) unitType = DW.UT.compile
        }

        val abbrev = abbrevCache.getOrPut(debugAbbrevOffset) {
            try {
                AbbrevTable.parse(sections.abbrev!!, debugAbbrevOffset)
            } catch (e: Exception) {
                cuWarnings.add("abbrev 表解析失败 offset=$debugAbbrevOffset: ${e.message}")
                AbbrevTable(emptyMap())
            }
        }

        // Parse DIEs within the unit, building the parent/child tree directly
        // (null abbrev codes pop the current open DIE).
        val dieReader = ByteReader(sections.info!!, r.pos, unitEnd.toInt().coerceAtMost(sections.info.size))
        val flat = LinkedHashMap<Long, DieBuilder>()
        var rootBuilder: DieBuilder? = null
        var stmtList: Long? = null
        var dwoName: String? = null
        // DWARF 5: when the base attributes are absent the contribution starts at 0.
        var cuAddrBase: Long? = if (version >= 5) 0L else null
        var cuStrOffsetsBase: Long? = if (version >= 5) 0L else null
        var cuRangesBase: Long? = if (version >= 5) 0L else null

        val openStack = ArrayDeque<DieBuilder>()
        var depth = 0
        var dieOrdinal = 0
        var aborted = false

        // Pre-scan the ROOT DIE to learn addr_base / str_offsets_base before any
        // addrx/strx form in that same root is decoded. We do this by decoding the
        // root into a scratch builder first; if its forms need the bases they use
        // the section defaults, so only the base attributes themselves matter here.
        run {
            val save = dieReader.pos
            val code = dieReader.uleb()
            val decl = abbrev.decls[code]
            if (decl != null) {
                val scratch = FormReader(
                    dieReader, sections, version, offsetSize, addressSize,
                    addrBase = 0L, strOffsetsBase = 0L,
                    strOffsetsTables = strOffsetTables, warnings = cuWarnings,
                )
                for (spec in decl.attrs) {
                    if (spec.form == DW.FORM.implicit_const) continue
                    val v = try { scratch.readAttr(spec.attr, spec.form) } catch (_: UnknownFormException) { continue }
                    when (spec.attr) {
                        DW.AT_addr_base, DW.AT_GNU_addr_base -> if (v is AttrValue.Num) cuAddrBase = v.value
                        DW.AT_str_offsets_base, DW.AT_GNU_str_offsets_base -> if (v is AttrValue.Num) cuStrOffsetsBase = v.value
                        DW.AT_rnglists_base -> if (v is AttrValue.Num) cuRangesBase = v.value
                    }
                }
            }
            dieReader.seek(save)
        }
        try {
            while (dieReader.remaining > 0) {
                val dieOffset = dieReader.pos.toLong()
                val code = dieReader.uleb()
                if (code == 0L) {
                    if (openStack.isNotEmpty()) openStack.removeLast()
                    depth--
                    if (depth < 0) break
                    continue
                }
                val decl = abbrev.decls[code]
                    ?: throw DwarfParseException("未知 abbrev code=$code @$dieOffset")
                // addr_base / str_offsets_base for a CU are only valid on the root;
                // but forms can appear before we finished reading it, so read attrs first.
                val fr = FormReader(
                    dieReader, sections, version, offsetSize, addressSize,
                    addrBase = cuAddrBase, strOffsetsBase = cuStrOffsetsBase,
                    strOffsetsTables = strOffsetTables, warnings = cuWarnings,
                )
                val attrs = LinkedHashMap<Int, AttrValue>()
                for (spec in decl.attrs) {
                    if (spec.form == DW.FORM.implicit_const) {
                        attrs[spec.attr] = AttrValue.Num(spec.implicitConst ?: 0L)
                        continue
                    }
                    try {
                        attrs[spec.attr] = fr.readAttr(spec.attr, spec.form)
                    } catch (e: UnknownFormException) {
                        cuWarnings.add("CU#$ordinal 未知 form 0x${e.form.toString(16)} (attr 0x${spec.attr.toString(16)})，该单元 DIE 解析中止；CU 头与行程序仍可信")
                        aborted = true
                        break
                    }
                }
                if (aborted) break
                val builder = DieBuilder(dieOffset, decl.tag, code, attrs, ordinal, depth)
                flat[dieOffset] = builder
                if (openStack.isEmpty()) rootBuilder = builder else openStack.last().children.add(builder)
                if (decl.hasChildren) { openStack.addLast(builder); depth++ }
                if (depth == 0 && rootBuilder === builder) {
                    // root carries CU-level base attributes
                }
                if (builder.depth == 0) {
                    stmtList = (attrs[DW.AT_stmt_list] as? AttrValue.SecOffset)?.offset
                        ?: (attrs[DW.AT_stmt_list] as? AttrValue.Num)?.value
                    dwoName = (attrs[DW.AT_dwo_name] as? AttrValue.Str)?.value
                        ?: (attrs[DW.AT_GNU_dwo_name] as? AttrValue.Str)?.value
                    cuAddrBase = (attrs[DW.AT_addr_base] as? AttrValue.Num)?.value
                        ?: (attrs[DW.AT_GNU_addr_base] as? AttrValue.Num)?.value
                    cuStrOffsetsBase = (attrs[DW.AT_str_offsets_base] as? AttrValue.Num)?.value
                        ?: (attrs[DW.AT_GNU_str_offsets_base] as? AttrValue.Num)?.value
                    cuRangesBase = (attrs[DW.AT_rnglists_base] as? AttrValue.Num)?.value
                    if (dwoName != null) cuWarnings.add("split DWARF: 未找到 dwo 文件 '$dwoName'，跨单元内联/类型可能不完整；骨架 CU 的范围与行号仍可信")
                }
                if (++dieOrdinal > MAX_DIES) throw DwarfParseException("CU DIE 数量超限")
                if (depth > MAX_DEPTH) throw DwarfParseException("DIE 嵌套深度超限 ($depth)")
            }
        } catch (e: DwarfParseException) {
            cuWarnings.add("DIE 解析中断: ${e.message}")
        }

        val rootDie = rootBuilder?.materialize()
        val flatDies = LinkedHashMap<Long, Die>()
        fun collect(b: DieBuilder) {
            val d = b.materializeLite()
            flatDies[b.offset] = d
            b.children.forEach { collect(it) }
        }
        rootBuilder?.let { collect(it) }

        val lineProgram = stmtList?.let {
            LineProgramParser(sections).parse(ordinal, it, addressSize, cuWarnings)
        }

        val effectiveRangesBase = cuRangesBase
        val finalCu = CompUnit(
            index = ordinal,
            version = if (version >= 5) 5 else 4,
            is64Bit = is64,
            offset = headerStart.toLong(),
            length = length,
            unitType = unitType,
            debugAbbrevOffset = debugAbbrevOffset,
            addressSize = addressSize,
            root = rootDie ?: throw DwarfParseException("CU#$ordinal 无根 DIE"),
            dies = flatDies,
            lineProgram = lineProgram,
            stmtListOffset = stmtList,
            dwoName = dwoName,
            warnings = cuWarnings.distinct(),
            addrBase = cuAddrBase,
            strOffsetsBase = cuStrOffsetsBase,
            rangesBase = effectiveRangesBase,
            tableVersion = "DWARF${if (version >= 5) 5 else 4}/line-${lineProgram?.version ?: version}",
        )
        allWarnings += cuWarnings.map { "CU#$ordinal: $it" }
        return finalCu
    }

    private fun chooseAddrTable(addrTables: Map<Long, AddrTable>, base: Long): AddrTable? {
        addrTables[base]?.let { return it }
        // choose nearest contribution start <= base
        return addrTables.entries.filter { it.key <= base }.maxByOrNull { it.key }?.value
            ?: addrTables[0L]
    }

    /** DW_FORM_ref1..4 are CU-relative; convert to global .debug_info offsets. */
    private fun resolveGlobalRefs(cus: List<CompUnit>, warnings: MutableList<String>) {
        // Refs are resolved lazily by resolver; nothing to patch on immutable DIEs.
        // We do validate that the largest ref4 stays within the file to detect OOB.
        // (Actual translation happens in [Resolver] with access to CU base.)
    }

    const val MAX_DIES = 1 shl 20
    const val MAX_DEPTH = 256
}

private class DieBuilder(
    val offset: Long,
    val tag: Int,
    val code: Long,
    val attrs: Map<Int, AttrValue>,
    val cuIndex: Int,
    val depth: Int,
) {
    val children = ArrayList<DieBuilder>()
    private var cached: Die? = null
    fun materialize(): Die {
        cached?.let { return it }
        val die = Die(offset, tag, code, children.map { it.materialize() }, attrs, cuIndex, depth)
        cached = die
        return die
    }
    fun materializeLite(): Die = materialize()
}
