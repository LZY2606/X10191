package compass.dwarf

import compass.elf.ElfFile
import compass.elf.ParseException

/** Entry point: parse all DWARF sections of an ELF, with an optional .dwo companion. */
object DwarfParser {

    fun parse(elf: ElfFile, splitElf: ElfFile? = null, sourceName: String = ""): DebugInfo {
        val splitSections = splitElf?.let { DebugSections.fromElf(it, null, it.toString()) }
        val sections = DebugSections.fromElf(elf, splitSections, sourceName)

        val main = InfoParser(sections, useSplit = false).parseAll()
        var splitUnits = emptyList<CompilationUnit>()
        var splitIssues = emptyList<SectionIssue>()
        var splitStatus = SplitStatus.NONE

        val wantsDwo = main.first.any { it.dwoName != null }
        val hasDwo = sections.infoDwo != null
        if (wantsDwo) splitStatus = if (hasDwo) SplitStatus.RESOLVED else SplitStatus.MISSING_DWO
        if (hasDwo) {
            val r = InfoParser(sections, useSplit = true).parseAll()
            splitUnits = r.first; splitIssues = r.second
        }

        val allUnits = main.first + splitUnits
        val enriched = allUnits.map { cu -> enrich(cu, sections) }

        return DebugInfo(
            units = enriched,
            issues = main.second + splitIssues,
            splitStatus = splitStatus
        )
    }

    private fun enrich(base: CompilationUnit, sections: DebugSections): CompilationUnit {
        val issues = base.issues
        val ci = CuInfo(
            version = base.version, dwarf64 = base.dwarf64, addressSize = base.addressSize,
            unitType = base.unitType, isSplit = base.isSplit,
            strOffsetsBase = base.strOffsetsBase, addrBase = base.addrBase,
            rnglistsBase = base.rnglistsBase
        )
        val addrAt = { idx: Long -> readAddrIndex(sections, base, idx) }

        // Attach line program to the root CU DIE's DW_AT_stmt_list.
        var line: LineProgram? = null
        base.root?.attrs?.get(DW_AT_stmt_list)?.let { at ->
            val off = (at.value as? AttrValue.SecOffset)?.offset
                ?: (at.value as? AttrValue.Num)?.v
            if (off != null) {
                try { line = LinePrograms.parse(sections, ci, off) }
                catch (e: ParseException) { issues.add("line 程序解析失败: ${e.message}") }
            }
        }

        // Resolve ranges on every DIE (functions and inlined instances).
        base.root?.let { resolveDieRanges(it, sections, base, ci, addrAt, issues) }

        return CompilationUnit(
            base.offset, base.length, base.version, base.dwarf64, base.isSplit,
            base.unitType, base.abbrevOffset, base.addressSize, base.segmentSize,
            base.dwoId, base.dwoName, base.compDir, base.name, base.root,
            line, base.ranges, issues, base.strOffsetsBase, base.addrBase, base.rnglistsBase
        )
    }

    private fun resolveDieRanges(
        die: Die, sections: DebugSections, cu: CompilationUnit, ci: CuInfo,
        addrAt: (Long) -> Long, issues: MutableList<String>
    ) {
        val ranges = try { dieRanges(die, sections, cu, ci, addrAt) }
            catch (e: ParseException) { issues.add("DIE@${die.globalOffset} 范围解析失败: ${e.message}"); emptyList() }
        DieRanges.put(die, ranges)
        for (c in die.children) resolveDieRanges(c, sections, cu, ci, addrAt, issues)
    }

    private fun dieRanges(
        die: Die, sections: DebugSections, cu: CompilationUnit, ci: CuInfo,
        addrAt: (Long) -> Long
    ): List<PcRange> {
        val low = die.num(DW_AT_low_pc)
        val highAttr = die.attrs[DW_AT_high_pc]?.value
        if (low != null && highAttr != null) {
            val high = when (highAttr) {
                is AttrValue.Num -> low + highAttr.v  // constant form: size
                else -> return emptyList()
            }
            // DWARF2/3 high_pc may be an address; GCC emits constant from DWARF4. Distinguish:
            // If the form is data*, it is an offset. If addr-form, absolute address.
            val absoluteHigh = when (die.attrs[DW_AT_high_pc]?.form) {
                DW_FORM_addr -> (highAttr as AttrValue.Num).v
                else -> high
            }
            return listOf(PcRange(low, absoluteHigh, low == absoluteHigh))
        }
        val rangesAttr = die.attrs[DW_AT_ranges]?.value ?: return emptyList()
        return when (rangesAttr) {
            is AttrValue.SecOffset -> {
                val baseForV4 = low ?: 0L
                if (cu.version >= 5 && sections.rnglists != null) {
                    RangeLists.readV5(sections.rnglists.slice(), rangesAttr.offset, null,
                        cu.addressSize, cu.dwarf64, addrAt)
                } else if (sections.ranges != null) {
                    RangeLists.readV4(sections.ranges.slice(), rangesAttr.offset,
                        cu.addressSize, baseForV4, addrAt)
                } else emptyList()
            }
            is AttrValue.RngIndex -> {
                val rl = sections.rnglists ?: throw ParseException("rnglistx 缺少 .debug_rnglists")
                RangeLists.readV5(rl.slice(), cu.rnglistsBase, rangesAttr.index,
                    cu.addressSize, cu.dwarf64, addrAt)
            }
            else -> emptyList()
        }
    }

    private fun readAddrIndex(sections: DebugSections, cu: CompilationUnit, idx: Long): Long {
        val sec = sections.addr ?: throw ParseException("addrx 缺少 .debug_addr")
        val p = cu.addrBase + idx * cu.addressSize
        if (p < 0 || p + cu.addressSize > sec.len) throw ParseException("addrx 越界 idx=$idx")
        val r = compass.elf.ByteReader(sec.data, sec.off + p.toInt())
        return r.readAddr(cu.addressSize)
    }
}

/** Stores resolved PC ranges per DIE (ranges come from attrs, not held in Die itself). */
object DieRanges {
    private val map = HashMap<Long, List<PcRange>>()
    fun put(die: Die, ranges: List<PcRange>) { map[dieKey(die)] = ranges }
    fun of(die: Die): List<PcRange> = map[dieKey(die)] ?: emptyList()
    private fun dieKey(die: Die): Long =
        die.globalOffset xor ((die.cu.offset + 1) * 0x9E3779B97F4A7C15uL.toLong())
}
