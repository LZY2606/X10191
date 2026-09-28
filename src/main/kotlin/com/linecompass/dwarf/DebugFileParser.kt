package com.linecompass.dwarf

import com.linecompass.elf.ElfFile
import com.linecompass.elf.ElfReader
import com.linecompass.elf.ElfSection
import com.linecompass.io.Hashes

/**
 * Entry point: ELF section extraction -> DWARF decode. The parser never shells
 * out to addr2line or any system debugger; everything is decoded locally.
 */
object DebugFileParser {

    private val DEBUG_SECTIONS = setOf(
        ".debug_info", ".debug_abbrev", ".debug_line", ".debug_str",
        ".debug_line_str", ".debug_str_offsets", ".debug_addr",
        ".debug_ranges", ".debug_rnglists",
        ".debug_cu_index", ".debug_tu_index",
        ".debug_info.dwo", ".debug_abbrev.dwo", ".debug_line.dwo",
        ".debug_str.dwo", ".debug_str_offsets.dwo", ".debug_addr.dwo",
        ".debug_rnglists.dwo", ".debug_cu_index", ".debug_tu_index"
    )

    fun parse(raw: ByteArray): ParsedDebugFile {
        val issues = mutableListOf<ParseIssue>()
        val sectionSummary = LinkedHashMap<String, String>()
        val blobs = LinkedHashMap<String, SectionBlob>()

        val elf = try {
            ElfReader.parse(raw)
        } catch (e: Exception) {
            issues += ParseIssue("elf", "ERROR", "ELF_PARSE_FAILED", e.message ?: "ELF parse failed")
            null
        }

        if (elf != null) collectElfSections(elf, blobs, sectionSummary)
        val fileSummary = Hashes.rawSummary(raw)

        val strings = StringTables(
            blobs[".debug_str"]?.bytes ?: blobs[".debug_str.dwo"]?.bytes,
            blobs[".debug_line_str"]?.bytes ?: blobs[".debug_line.dwo"]?.bytes,
            blobs[".debug_str_offsets"]?.bytes ?: blobs[".debug_str_offsets.dwo"]?.bytes,
            issues
        )
        val addrs = AddrTableReader(blobs[".debug_addr"]?.bytes ?: blobs[".debug_addr.dwo"]?.bytes, issues)

        val infoBytes = blobs[".debug_info"]?.bytes ?: blobs[".debug_info.dwo"]?.bytes
        val abbrevBytes = blobs[".debug_abbrev"]?.bytes ?: blobs[".debug_abbrev.dwo"]?.bytes

        val units = if (infoBytes == null) {
            issues += ParseIssue(".debug_info", "ERROR", "NO_DEBUG_INFO", "section .debug_info missing")
            emptyList()
        } else {
            if (abbrevBytes == null) {
                issues += ParseIssue(".debug_abbrev", "ERROR", "NO_DEBUG_ABBREV",
                    "section .debug_abbrev missing; DIE trees cannot be decoded")
            }
            val ip = InfoParser(infoBytes, abbrevBytes, strings, addrs, issues)
            ip.parse()
            ip.units
        }

        val rangeParser = RangeListParser(blobs[".debug_ranges"]?.bytes, blobs[".debug_rnglists"]?.bytes, addrs, issues)
        val lineSection = blobs[".debug_line"]?.bytes ?: blobs[".debug_line.dwo"]?.bytes
        val lineParser = if (lineSection != null) LineProgramParser(lineSection, strings, issues) else null

        val rangeIndex = mutableListOf<AddressRange>()
        for (cu in units) {
            val lp = cu.stmtListOffset?.let { off -> lineParser?.parse(off, cu) }
            cu.lineProgram = lp
            val cuRanges = mutableListOf<AddressRange>()

            // Root / DIE ranges
            cu.root?.let { root -> collectDieRanges(root, cu, cuRanges, rangeParser) }

            // Line-program ranges (one per sequence), widest and lowest priority.
            lp?.sequences?.forEach { seq ->
                cuRanges += AddressRange(seq.startAddress, seq.endAddress, seq.segment,
                    RangeKind.LINE_TABLE, null, cu, explicitPriority = 5)
            }
            cu.ranges = cuRanges
            rangeIndex += cuRanges
        }

        pairSplitUnits(units, issues)

        return ParsedDebugFile(
            sections = DebugSections(blobs, elf),
            cus = units,
            issues = issues,
            rangeIndex = rangeIndex,
            rawSectionSummary = sectionSummary,
            fileSummary = fileSummary
        )
    }

    private fun collectElfSections(
        elf: ElfFile, blobs: MutableMap<String, SectionBlob>, summary: MutableMap<String, String>
    ) {
        for (s: ElfSection in elf.sections) {
            if (s.name in DEBUG_SECTIONS && s.bytes != null) {
                blobs[s.name] = SectionBlob(s.name, s.bytes, s.addr)
                summary[s.name] = Hashes.rawSummary(s.bytes)
            }
        }
    }

    private fun collectDieRanges(
        die: DieNode,
        cu: CompilationUnit,
        out: MutableList<AddressRange>,
        rangeParser: RangeListParser
    ) {
        if (die.tag == DW.TAG_subprogram || die.tag == DW.TAG_inlined_subroutine) {
            val kind = if (die.isInline) RangeKind.INLINED else RangeKind.SUBPROGRAM
            val priority = if (die.isInline) 4 else 2
            val rangesAttr = die.attr(DW.AT_ranges)?.value
            if (rangesAttr is AttrValue.SectionOffset) {
                val decoded = if (cu.version >= 5) rangeParser.parseRangesV5(rangesAttr.value, cu)
                else rangeParser.parseRangesV4(rangesAttr.value, cu)
                decoded.forEach { out += it.copy(die = die, kind = kind, explicitPriority = 1) }
            } else {
                val low = die.addr(DW.AT_low_pc)
                if (low != null) {
                    val highAttr = die.attr(DW.AT_high_pc)?.value
                    val high = when (highAttr) {
                        is AttrValue.Addr -> highAttr.value // constant address form
                        is AttrValue.Number -> low + highAttr.value // DWARF: offset from low_pc
                        else -> low
                    }
                    out += AddressRange(low, high, 0, kind, die, cu, explicitPriority = priority)
                }
            }
        }
        die.children.forEach { collectDieRanges(it, cu, out, rangeParser) }
    }

    private fun pairSplitUnits(units: List<CompilationUnit>, issues: MutableList<ParseIssue>) {
        val skeletons = units.filter { it.kind == CuKind.SKELETON }
        val splits = units.filter { it.kind == CuKind.SPLIT_COMPILE }
        // dwo_id: DWARF 5 carries it in the skeleton root as DW_AT_dwo_id.
        fun dwoId(cu: CompilationUnit): Long? = cu.root?.num(DW.AT_dwo_id)
            ?: cu.root?.num(DW.AT_GNU_dwo_id)
        val splitById = splits.mapNotNull { cu -> dwoId(cu)?.let { it to cu } }.toMap()
        for (skel in skeletons) {
            val id = dwoId(skel)
            val split = id?.let { splitById[it] }
            if (split != null) {
                skel.splitCu = split
                split.splitCu = skel
            } else {
                skel.splitMissing = true
                issues += ParseIssue(".debug_info", "WARNING", "DWO_MISSING",
                    "skeleton CU ${skel.name} (0x${skel.offset.toString(16)}) references " +
                        "${skel.root?.text(DW.AT_dwo_name) ?: skel.root?.text(DW.AT_GNU_dwo_name) ?: "a .dwo"} " +
                        "which was not imported; skeleton ranges/line tables remain trustworthy, inline data may be incomplete",
                    cuOffset = skel.offset)
            }
        }
    }
}
