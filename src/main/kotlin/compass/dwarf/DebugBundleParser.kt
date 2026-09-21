@file:Suppress("ArrayInDataClass")
package compass.dwarf

import compass.elf.ElfSummary
import compass.elf.ParsedElf
import compass.util.Hex
import compass.util.Limits
import compass.util.ParseException
import compass.util.U64
import java.security.MessageDigest

/**
 * Inputs for a parse: the main ELF plus any number of linked .dwo/.dwp companion files.
 * Sections are merged (dwo sections added) so skeleton and split CUs can be parsed together.
 */
class DebugInputs(
    val main: ParsedElf,
    val companions: List<ParsedElf>
)

object DebugBundleParser {

    fun parse(inputs: DebugInputs): DebugBundle {
        val merged = LinkedHashMap<String, ByteArray>()
        for ((i, elf) in (listOf(inputs.main) + inputs.companions).withIndex()) {
            for ((name, bytes) in elf.sectionBytes) {
                merged.putIfAbsent(name, bytes)
            }
        }
        val sections = Sections.of(merged)
        val issues = ArrayList<ParseIssue>()
        val debugData = DebugData(sections)
        val abbrevs = AbbreviationTables(sections)

        val mainCuParser = CuParser(sections, abbrevs, debugData, dwo = false)
        val dwoCuParser = CuParser(sections, abbrevs, debugData, dwo = true)
        val mainCus = mainCuParser.parse()
        val dwoCus = dwoCuParser.parse()
        val allCus = mainCus + dwoCus.map { cu ->
            // ensure globally unique indexes
            cu.copy(index = cu.index + mainCus.size)
        }

        val mainLines = LineProgramParser(sections, debugData, dwo = false).parseAll(mainCus)
        val dwoLines = LineProgramParser(sections, debugData, dwo = true)
            .parseAll(dwoCus).map { it.copy(cuIndex = it.cuIndex + mainCus.size) }
        val allLines = mainLines + dwoLines

        val rangeResolver = RangeResolver(sections, debugData)

        // --- range post-processing, per CU independently ---
        val cuList = ArrayList<CompilationUnit>(allCus.size)
        for (cu in allCus) {
            val dies = ArrayList<Die>(cu.dies.size)
            for (die in cu.dies) {
                var ranges = die.ranges
                val dieIssues = ArrayList<ParseIssue>()
                if (ranges.isEmpty() && dieHasRangeAttrs(die)) {
                    ranges = try {
                        rangeResolver.rangesFor(cu, die)
                    } catch (e: ParseException) {
                        dieIssues += ParseIssue("warning", "BAD_RANGES",
                            "${e.message ?: "range parse failed"} — DIE '${die.name ?: die.tagName()}' ranges left empty",
                            if (cu.dwarfVersion >= 5) ".debug_rnglists" else ".debug_ranges", null, cu.offset)
                        emptyList()
                    }
                }
                dies += die.copy(ranges = ranges)
            }
            cuList += cu.copy(dies = dies, issues = cu.issues + rangeIssuesFor(cu, rangeResolver))
        }

        // --- name resolution through abstract_origin / specification chains ---
        val byOffset = HashMap<U64, Die>()
        for (cu in cuList) for (die in cu.dies) byOffset[die.offset] = die
        val refIssuesByCu = HashMap<U64, MutableList<ParseIssue>>()
        for (cu in cuList) {
            for (die in cu.dies) {
                val (resolved, issues) = resolveReferences(die, byOffset)
                // rebind in place after full mapping below
                refIssuesByCu.getOrPut(cu.offset) { mutableListOf() } += issues.map {
                    it.copy(cuOffset = cu.offset)
                }
            }
        }
        for (i in cuList.indices) {
            val cu = cuList[i]
            val resolved = cu.dies.map { die -> resolveReferences(die, byOffset).first }
            val extra = refIssuesByCu[cu.offset].orEmpty()
            cuList[i] = cu.copy(dies = resolved, issues = cu.issues + extra)
        }

        // --- split DWARF linking via dwo_id ---
        val splitLinks = linkSkeletonSplit(cuList)
        val linkedMissing = cuList.filter { it.kind == "skeleton" && it.dwoId != null && splitLinks[it.offset] == null }
        for (missing in linkedMissing) {
            issues += ParseIssue("warning", "MISSING_DWO",
                "skeleton CU '${missing.name ?: "?"}' dwo_id=${missing.dwoId} has no linked .dwo; " +
                    "ranges from skeleton remain trustworthy, but split line/inlining info is unavailable",
                ".debug_info.dwo", null, missing.offset)
        }

        for (cu in cuList) issues += cu.issues
        for (lp in allLines) issues += lp.issues

        val digest = hashContent(inputs)
        val sectionDigests = buildSectionDigests(sections)

        return DebugBundle(
            elf = inputs.main.summary,
            buildId = inputs.main.summary.buildId,
            contentSha256 = digest,
            sections = sectionDigests,
            cus = cuList,
            linePrograms = allLines,
            issues = issues,
            splitLinks = splitLinks,
            isDwo = false,
            dwoIds = cuList.mapNotNull { it.dwoId }
        )
    }

    private fun rangeIssuesFor(cu: CompilationUnit, rr: RangeResolver): List<ParseIssue> = emptyList()

    private fun dieHasRangeAttrs(die: Die): Boolean =
        die.attrs.containsKey(DwAt.LOW_PC) || die.attrs.containsKey(DwAt.RANGES)

    private fun resolveReferences(die: Die, byOffset: Map<U64, Die>): Pair<Die, List<ParseIssue>> {
        var name = die.name
        var linkage = die.linkageName
        var declFile = die.declarationFile
        var declLine = die.declarationLine
        var inlineCode = die.inlineCode
        var hops = 0
        var ref = die.abstractOrigin ?: die.specification
        var refAttr = if (die.abstractOrigin != null) "DW_AT_abstract_origin" else if (die.specification != null) "DW_AT_specification" else null
        val badRefs = ArrayList<ParseIssue>()
        while (ref != null) {
            if (++hops > Limits.MAX_REFERENCE_HOPS) {
                badRefs += ParseIssue("warning", "REF_CYCLE",
                    "$refAttr chain longer than ${Limits.MAX_REFERENCE_HOPS} hops at DIE ${die.offset}; chain stopped",
                    null, ref, null)
                break
            }
            val target = byOffset[ref]
            if (target == null) {
                badRefs += ParseIssue("warning", "REF_OUT_OF_BOUNDS",
                    "$refAttr -> $ref does not point at a parsed DIE; name lookup for '${die.name ?: die.tagName()}' " +
                        "cannot continue, but address ranges remain usable",
                    ".debug_info", ref, null)
                break
            }
            if (name == null) name = target.name
            if (linkage == null) linkage = target.linkageName
            if (declLine == null) declLine = target.declarationLine
            if (inlineCode == null) inlineCode = target.inlineCode
            val next = target.abstractOrigin ?: target.specification
            refAttr = if (target.abstractOrigin != null) "DW_AT_abstract_origin" else "DW_AT_specification"
            ref = next
        }
        // Inline call sites inherit call file/line from their own attrs (already read).
        return die.copy(
            name = name, linkageName = linkage,
            declarationFile = declFile, declarationLine = declLine,
            inlineCode = inlineCode
        ) to badRefs
    }

    private fun linkSkeletonSplit(cus: List<CompilationUnit>): Map<U64, U64> {
        val byDwoId = HashMap<U64, U64>()
        for (cu in cus) {
            if (cu.kind == "split" && cu.dwoId != null) byDwoId.putIfAbsent(cu.dwoId, cu.offset)
        }
        val links = LinkedHashMap<U64, U64>()
        for (cu in cus) {
            if (cu.kind == "skeleton" && cu.dwoId != null) {
                byDwoId[cu.dwoId]?.let { links[cu.offset] = it }
            }
        }
        return links
    }

    private fun hashContent(inputs: DebugInputs): String {
        val md = MessageDigest.getInstance("SHA-256")
        for (elf in listOf(inputs.main) + inputs.companions) {
            for (name in elf.sectionBytes.keys.sorted()) {
                md.update(name.toByteArray())
                md.update(elf.sectionBytes[name]!!)
            }
        }
        return Hex.encode(md.digest())
    }

    private fun buildSectionDigests(sections: Sections): List<SectionDigest> {
        val md = MessageDigest.getInstance("SHA-256")
        return sections.names().sorted().mapNotNull { name ->
            val b = sections[name] ?: return@mapNotNull null
            md.reset()
            SectionDigest(
                name = name,
                size = U64(b.size.toLong()),
                sha256 = Hex.encode(md.digest(b)),
                headHex = Hex.encode(b, minOf(32, b.size))
            )
        }
    }
}

fun Die.tagName(): String = when (tag) {
    DwTag.COMPILE_UNIT -> "DW_TAG_compile_unit"
    DwTag.SUBPROGRAM -> "DW_TAG_subprogram"
    DwTag.INLINED_SUBROUTINE -> "DW_TAG_inlined_subroutine"
    DwTag.LEXICAL_BLOCK -> "DW_TAG_lexical_block"
    else -> "DW_TAG_0x${tag.toString(16)}"
}
