package compass.dwarf

import compass.dwarf.DW.AT_GNU_dwo_id
import compass.dwarf.DW.AT_GNU_dwo_name
import compass.dwarf.DW.AT_abstract_origin
import compass.dwarf.DW.AT_call_column
import compass.dwarf.DW.AT_call_file
import compass.dwarf.DW.AT_call_line
import compass.dwarf.DW.AT_decl_column
import compass.dwarf.DW.AT_decl_file
import compass.dwarf.DW.AT_decl_line
import compass.dwarf.DW.AT_dwo_id
import compass.dwarf.DW.AT_dwo_name
import compass.dwarf.DW.AT_explicit_priority
import compass.dwarf.DW.AT_high_pc
import compass.dwarf.DW.AT_linkage_name
import compass.dwarf.DW.AT_low_pc
import compass.dwarf.DW.AT_MIPS_linkage_name
import compass.dwarf.DW.AT_name
import compass.dwarf.DW.AT_ranges
import compass.dwarf.DW.AT_rnglists_base
import compass.dwarf.DW.AT_segment
import compass.dwarf.DW.AT_specification
import compass.dwarf.DW.AT_stmt_list
import compass.dwarf.DW.TAG_inlined_subroutine
import compass.dwarf.DW.TAG_skeleton_unit
import compass.dwarf.DW.TAG_subprogram
import compass.dwarf.DW.TAG_compile_unit
import compass.elf.ElfParser
import compass.model.AddrRange
import compass.model.AttrValue
import compass.model.BoundsException
import compass.model.CompilationUnit
import compass.model.Die
import compass.model.ElfFile
import compass.model.LineProgram
import compass.model.ParseIssue
import compass.model.ParsedDebugFile
import compass.model.unsignedCompare

/** A concrete (possibly inlined) code range described by a DIE. */
data class CodeSymbol(
    val cuHeaderOffset: Long,
    val dieOffset: Long,
    val tag: Int,
    val name: String?,
    val linkageName: String?,
    val ranges: List<AddrRange>,
    val depth: Int,
    val isInline: Boolean,
    val callFile: Int?,
    val callLine: Int?,
    val callColumn: Int?,
    val explicitPriority: Long?,
    val abstractRoot: Die?,
)

class DwarfFileParser(private val elf: ElfFile) {
    private val sections = DebugSections(elf)
    private val issues = ArrayList<ParseIssue>()
    private val rangeResolver = RangeResolver(sections)

    fun parse(): ParsedDebugFile {
        // Section-level sanity first.
        sections.compressed.forEach {
            issues += ParseIssue("WARNING", "COMPRESSED", "$it is zlib-compressed and is not decoded; related conclusions are limited", it)
        }
        listOf(".debug_info", ".debug_abbrev", ".debug_line", ".debug_str", ".debug_ranges", ".debug_rnglists", ".debug_addr", ".debug_str_offsets")
            .filter { elf.section(it) != null && elf.section(it)!!.size == 0L }
            .forEach { issues += ParseIssue("WARNING", "EMPTY_SECTION", "$it exists but has zero length", it) }

        val infoParser = InfoParser(sections)
        val units = infoParser.parse()
        issues += infoParser.issuesView
        val lineParser = LineParser(sections)
        val linePrograms = lineParser.parseAll()
        issues += lineParser.issues
        issues += rangeResolver.issues

        validateLinePrograms(units, linePrograms)
        validateReferences(units)

        val dwoUnits = HashMap<Long, CompilationUnit>()
        units.filter { it.isSplit && it.dwoId != null }.forEach { dwoUnits[it.dwoId!!] = it }
        val hasSplitRefs = units.any { it.isSkeleton } || units.any { it.root?.str(AT_dwo_name) != null || it.root?.str(AT_GNU_dwo_name) != null }

        val sectionSha = elf.sections.filter { it.isDebug }.associate { it.name to ElfParser.sha256(it.data) }
        val fileSha = ElfParser.sha256(elf.rawBytes)

        return ParsedDebugFile(
            elf = elf, units = units, linePrograms = linePrograms,
            issues = dedupe(issues), sectionSha = sectionSha, fileSha = fileSha,
            dwoUnits = dwoUnits, hasSplitRefs = hasSplitRefs,
        )
    }

    private fun dedupe(list: List<ParseIssue>): List<ParseIssue> =
        list.distinctBy { "${it.severity}|${it.code}|${it.section}|${it.offset}|${it.message}" }

    private fun validateLinePrograms(units: List<CompilationUnit>, programs: List<LineProgram>) {
        val byOffset = programs.associateBy { it.cuHeaderOffset }
        for (cu in units) {
            val stmtOffset = cu.root?.num(AT_stmt_list) ?: continue
            val prog = byOffset[stmtOffset]
            if (prog == null) {
                issues += ParseIssue("WARNING", "NO_LINEPROG",
                    "CU '${cu.name ?: "?"}' DW_AT_stmt_list=$stmtOffset has no matching .debug_line program",
                    ".debug_line", stmtOffset)
            } else if (prog.version != cu.version) {
                issues += ParseIssue("INFO", "VERSION_MIX",
                    "CU is DWARF${cu.version} but its line program is DWARF${prog.version}; line table version reported independently",
                    ".debug_line", stmtOffset)
            }
        }
    }

    /** Finds info refs that jump outside any CU: those cannot be resolved. */
    private fun validateReferences(units: List<CompilationUnit>) {
        for (cu in units) {
            for (die in cu.dies.values) {
                for (a in die.attributes) {
                    val ref = (a.value as? AttrValue.InfoRef)?.offset ?: continue
                    val targetsCu = units.any { other ->
                        ref >= other.firstDieOffset && ref < other.nextUnitOffset
                    }
                    if (!targetsCu) {
                        issues += ParseIssue("WARNING", "BAD_REF",
                            "${DwarfNames.attr(a.name)} at DIE ${die.offset} references $ref which is outside every known CU",
                            ".debug_info", ref)
                    }
                }
            }
        }
    }

    companion object {
        /** Build all address-bearing DIEs (subprograms, inlined subroutines). */
        fun symbols(parsed: ParsedDebugFile, rangeResolver: RangeResolver = RangeResolver(DebugSections(parsed.elf))): List<CodeSymbol> {
            val out = ArrayList<CodeSymbol>()
            for (cu in parsed.units) {
                if (cu.isSkeleton) continue // concrete code lives in the dwo
                val selector = cu.root?.num(AT_segment) ?: 0L
                for (die in cu.dies.values) {
                    if (die.tag != TAG_subprogram && die.tag != TAG_inlined_subroutine) continue
                    val ranges = rangesOf(cu, die, rangeResolver, selector)
                    if (ranges.isEmpty() && die.tag == TAG_subprogram) continue
                    val name = die.str(AT_name)
                    val linkage = die.str(AT_linkage_name) ?: die.str(AT_MIPS_linkage_name)
                    val prio = die.num(AT_explicit_priority)
                    out += CodeSymbol(
                        cuHeaderOffset = cu.headerOffset,
                        dieOffset = die.offset, tag = die.tag,
                        name = name, linkageName = linkage,
                        ranges = ranges, depth = die.depth,
                        isInline = die.tag == TAG_inlined_subroutine,
                        callFile = die.num(AT_call_file)?.toInt(),
                        callLine = die.num(AT_call_line)?.toInt(),
                        callColumn = die.num(AT_call_column)?.toInt(),
                        explicitPriority = prio,
                        abstractRoot = null,
                    )
                }
            }
            return out
        }

        /** high_pc constant vs address handling plus ranges/rnglists. */
        fun rangesOf(cu: CompilationUnit, die: Die, rr: RangeResolver, selector: Long): List<AddrRange> {
            val low = die.addr(AT_low_pc)
            val highAttr = die.attr(AT_high_pc)
            val rangesAttr = die.attr(AT_ranges)
            val out = ArrayList<AddrRange>()
            if (rangesAttr != null) {
                val indexed = rangesAttr.formCode == compass.model.AttrForm.RNGLISTX.code
                val offset = when (val v = rangesAttr.value) {
                    is AttrValue.RangeRef -> v.offset
                    is AttrValue.InfoRef -> v.offset
                    is AttrValue.Num -> v.value
                    else -> null
                }
                if (offset != null) {
                    out += if (cu.version >= 5) {
                        rr.dwarf5List(offset, indexed, cu.rnglistsBase, cu.addressSize, selector)
                    } else {
                        rr.legacyList(offset, cu.addressSize, low ?: 0L, selector)
                    }
                }
            }
            if (low != null && highAttr != null) {
                val high = when (val hv = highAttr.value) {
                    is AttrValue.Addr -> hv.value
                    is AttrValue.Num -> low + hv.value
                    else -> null
                }
                if (high != null) {
                    if (unsignedCompare(high, low) < 0) {
                        // zero-length is allowed (high == low); reversed never is
                        throw BoundsException("DW_AT_high_pc < DW_AT_low_pc at DIE ${die.offset}")
                    }
                    out += AddrRange(selector, low, high)
                }
            } else if (low != null && rangesAttr == null && die.tag == TAG_inlined_subroutine) {
                out += AddrRange(selector, low, low) // zero-length inline site
            }
            return out
        }

    }
}
