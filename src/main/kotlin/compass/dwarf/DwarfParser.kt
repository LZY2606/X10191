package compass.dwarf

import compass.elf.ElfFile
import java.security.MessageDigest

class DwarfParseAbort(message: String) : RuntimeException(message)

class DwarfParser(private val elf: ElfFile) {
    private val info = elf.reader(".debug_info")
    private val abbrevSection = elf.reader(".debug_abbrev")
        ?: elf.reader(".debug_abbrev.dwo")
    private val addrSection = elf.reader(".debug_addr") ?: elf.reader(".debug_addr.dwo")
    private val abbrevTables = AbbreviationTables(abbrevSection)
    private val addrTable = AddrTable(addrSection)
    private val formReader = FormReader(elf, abbrevTables, addrTable)

    val warnings = mutableListOf<String>()

    fun parse(): ParsedSections {
        val cus = ArrayList<CompileUnit>()
        val dieByOffset = LinkedHashMap<Long, DieNode>()
        val cuByOffset = LinkedHashMap<Long, CompileUnit>()

        if (info == null) {
            return ParsedSections(cus, dieByOffset, cuByOffset,
                listOf("missing .debug_info section"), sectionSummaries(), )
        }

        var cuId = 0
        val r = info.subReader(info.base, info.limit)
        while (r.remaining() > 0) {
            val unitStart = r.sectionOffset()
            try {
                val cu = parseCu(r, cuId, unitStart)
                cus.add(cu)
                cuByOffset[cu.sectionOffset] = cu
                for (die in cu.dies) dieByOffset[die.offset] = die
                cuId++
            } catch (e: DwarfParseAbort) {
                warnings.add("CU at 0x${unitStart.toString(16)} skipped: ${e.message}")
                break
            } catch (e: BoundsException) {
                warnings.add("CU at 0x${unitStart.toString(16)} truncated: ${e.message}")
                break
            }
        }

        return ParsedSections(cus, dieByOffset, cuByOffset, warnings, sectionSummaries())
    }

    private fun parseCu(r: ByteReader, cuId: Int, unitStart: Long): CompileUnit {
        val (length, d64) = r.initialLength()
        if (length <= 0) throw DwarfParseAbort("non-positive unit length")
        val end = r.sectionOffset() + length
        if (end > r.limit - r.base) throw BoundsException("CU overruns .debug_info")
        val version = r.u16().toInt()
        if (version !in 2..5) throw DwarfParseAbort("unsupported DWARF version $version")

        var unitType = 0
        var addressSize = 8
        var abbrevOffset = 0L
        if (version >= 5) {
            unitType = r.u8()
            addressSize = r.u8()
            abbrevOffset = r.dwarfOffset()
        } else {
            abbrevOffset = r.dwarfOffset()
            addressSize = r.u8()
            unitType = if (unitType == 0) 1 else unitType
        }

        val cuWarnings = mutableListOf<String>()
        val dies = ArrayList<DieNode>()
        val abbrevMap = abbrevTables.table(abbrevOffset)
        if (abbrevMap == null) {
            cuWarnings.add("abbreviation table at 0x${abbrevOffset.toString(16)} is missing or corrupt; DIEs not parsed")
        }

        var parsedUntil = end
        if (abbrevMap != null) {
            parsedUntil = parseDies(r, end, cuId, unitStart, version, d64, addressSize,
                abbrevMap, dies, cuWarnings)
        }

        val root = dies.firstOrNull()
        fun num(name: Int): Long? = (root?.attr(name)?.value as? AttrValue.Num)?.v
        fun str(name: Int): String? = (root?.attr(name)?.value as? AttrValue.Str)?.v

        val dwoName = str(Attr.DW_AT_dwo_name) ?: str(Attr.DW_AT_GNU_DWO_NAME)
        val dwoId = num(Attr.DW_AT_GNU_DWO_ID)
        val isSkeleton = root?.tag == Tag.COMPILE_UNIT && dwoName != null

        val lowPc = when (val v = root?.attr(Attr.LOW_PC)?.value) {
            is AttrValue.Addr -> v.v
            is AttrValue.Indexed -> resolveAddrIndex(v, null, version, addressSize)
            else -> null
        }
        val stmtList = (root?.attr(Attr.STMT_LIST)?.value as? AttrValue.SecOffset)?.v
        val strBase = num(Attr.STR_OFFSETS_BASE)
        val addrBaseAttr = root?.attr(Attr.ADDR_BASE) ?: root?.attr(Attr.GNU_ADDR_BASE)
        val addrBase = (addrBaseAttr?.value as? AttrValue.Num)?.v
            ?: (addrBaseAttr?.value as? AttrValue.SecOffset)?.v

        // Move reader to end in case DIE parsing stopped early.
        r.seek(end)

        return CompileUnit(
            id = cuId,
            sectionOffset = unitStart,
            length = (end - unitStart),
            version = version,
            dwarf64 = d64,
            addressSize = addressSize,
            unitType = unitType,
            debugAbbrevOffset = abbrevOffset,
            name = str(Attr.COMP_NAME),
            compDir = str(Attr.COMP_DIR),
            compName = str(Attr.COMP_NAME),
            lowPc = lowPc,
            stmtListOffset = stmtList,
            dwoName = dwoName,
            dwoId = dwoId,
            isSkeleton = isSkeleton,
            dwoVersionId = null,
            dies = dies,
            ranges = emptyList(),
            lineProgram = null,
            warnings = cuWarnings,
            parsedUntil = parsedUntil,
            strOffsetsBase = strBase,
            addrBase = addrBase,
            rnglistsBase = 0L,
        )
    }

    private fun parseDies(
        r: ByteReader, end: Long, cuId: Int, cuStart: Long, version: Int,
        d64: Boolean, addressSize: Int, abbrevMap: Map<Long, Abbreviation>,
        out: MutableList<DieNode>, warnings: MutableList<String>
    ): Long {
        val parentStack = ArrayDeque<Pair<Long, Int>>()
        var depth = 0
        val ctxBase = FormReader.CuContext(version, d64, addressSize, cuStart, null, null, null)
        var guard = 0
        while (r.sectionOffset() < end) {
            if (++guard > 5_000_000) {
                warnings.add("DIE limit reached; remainder of CU ignored")
                return r.sectionOffset()
            }
            val off = r.sectionOffset()
            val code = r.uleb()
            if (code == 0L) {
                if (parentStack.isNotEmpty()) {
                    parentStack.removeLast()
                    depth--
                }
                continue
            }
            val abbr = abbrevMap[code]
            if (abbr == null) {
                warnings.add("abbreviation code $code at 0x${off.toString(16)} not found; remainder of CU ignored to avoid cursor drift")
                return off
            }
            val attrs = ArrayList<DAttribute>(abbr.attrs.size)
            try {
                val strBase = out.firstOrNull()?.let { root ->
                    (root.attr(Attr.STR_OFFSETS_BASE)?.value as? AttrValue.Num)?.v
                }
                val addrBase = out.firstOrNull()?.let { root ->
                    val a = root.attr(Attr.ADDR_BASE) ?: root.attr(Attr.GNU_ADDR_BASE)
                    (a?.value as? AttrValue.Num)?.v ?: (a?.value as? AttrValue.SecOffset)?.v
                }
                val ctx = FormReader.CuContext(version, d64, addressSize, cuStart, strBase, addrBase)
                for (a in abbr.attrs) {
                    val value = if (a.form == Form.IMPLICIT_CONST)
                        AttrValue.Num(a.implicitConst)
                    else formReader.read(a.form, a.implicitConst, r, ctx)
                    attrs.add(DAttribute(a.name, a.form, value))
                }
            } catch (e: UnknownFormException) {
                warnings.add("unknown form 0x${e.form.toString(16)} at offset 0x${off.toString(16)}; CU DIE parsing stops there (no further speculative DIEs emitted)")
                return off
            } catch (e: BoundsException) {
                warnings.add("attribute at 0x${off.toString(16)} ran past section bounds: ${e.message}; remainder ignored")
                return off
            }

            val parentOffset = parentStack.lastOrNull()?.first ?: -1L
            val node = DieNode(off, abbr.tag, abbr.hasChildren, attrs, parentOffset, depth, cuId)
            out.add(node)
            if (abbr.hasChildren) {
                parentStack.addLast(off to depth)
                depth++
            }
        }
        return end
    }

    fun resolveAddrIndex(v: AttrValue.Indexed, addrBase: Long?, version: Int, addressSize: Int): Long? {
        if (v.kind != AttrValue.IndexKind.ADDRX) return null
        return addrTable.resolve(addrBase, v.idx, addressSize, version)
    }

    private fun sectionSummaries(): Map<String, SectionSummary> {
        val interesting = setOf(
            ".debug_info", ".debug_abbrev", ".debug_line", ".debug_str", ".debug_ranges",
            ".debug_rnglists", ".debug_addr", ".debug_str_offsets", ".debug_line_str",
            ".debug_info.dwo", ".debug_abbrev.dwo", ".debug_rnglists.dwo", ".debug_str.dwo",
            ".debug_str_offsets.dwo", ".debug_addr.dwo"
        )
        val out = LinkedHashMap<String, SectionSummary>()
        for (s in elf.sections) {
            if (s.name !in interesting) continue
            val digest = s.bytes?.let {
                MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { b -> "%02x".format(b) }
            }
            out[s.name] = SectionSummary(s.name, s.type, s.address, s.fileOffset, s.size, digest, null)
        }
        return out
    }
}
