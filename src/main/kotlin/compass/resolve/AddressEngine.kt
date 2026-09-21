package compass.resolve

import compass.dwarf.*
import compass.store.LoadedModule

/**
 * The "行址罗盘" engine. Resolves one section-relative address against one
 * parsed module, keeping every legal candidate and ordering them by:
 *
 *   1. explicit priority (exact scope hit preferred over line-only)
 *   2. narrowest containing range
 *   3. greatest inline depth
 *   4. stable tiebreak (cu index, DIE offset)
 *
 * Zero-length ranges never match by containment but remain visible in the UI.
 */
class AddressEngine(val module: LoadedModule) {
    private val dwarf = module.dwarf
    private val scopesByCu: Map<Int, List<ScopeEntry>>
    private val scopeWarnings: List<String>

    init {
        val map = LinkedHashMap<Int, List<ScopeEntry>>()
        val warns = ArrayList<String>()
        for (cu in dwarf.cus) {
            val extractor = ScopeExtractor(dwarf, cu)
            map[cu.index] = extractor.extract()
            warns += extractor.collectedWarnings
        }
        scopesByCu = map
        scopeWarnings = warns.distinct()
    }

    fun scopesFor(cuIndex: Int): List<ScopeEntry> = scopesByCu[cuIndex].orEmpty()

    /** Resolve a section-relative (unrelocated) address. */
    fun resolveRelative(relative: Long, loadBias: Long, generation: Int): QueryExplanation {
        val warnings = ArrayList<String>()
        warnings += dwarf.warnings
        warnings += scopeWarnings
        val candidates = ArrayList<AddressCandidate>()

        for (unit in dwarf.cus) {
            val cuName = (unit.root.attr(DW.AT_name) as? AttrValue.Str)?.value
            val cuCompDir = (unit.root.attr(DW.AT_comp_dir) as? AttrValue.Str)?.value

            val matchingScopes = ArrayList<Pair<ScopeEntry, AddrRange>>()
            collectChain(unit.root, relative, ArrayList(), matchingScopes)

            for ((scope, range) in matchingScopes) {
                val chain = buildInlineChain(unit, scope)
                val lp = unit.lineProgram
                val fileIdx = (scope.die.attr(DW.AT_decl_file) as? AttrValue.Num)?.value?.toInt()
                val lpFile = fileIdx?.let { lp?.files?.getOrNull(it - 1) ?: lp?.files?.getOrNull(it) }
                val (lineRow, seqIdx) = lineLookup(unit, relative)
                val filePath = lineRow?.let { filePathOf(unit, it.row) } ?: lpFile?.fullPath
                candidates += AddressCandidate(
                    moduleKey = module.key,
                    moduleVersion = module.version,
                    moduleFileName = module.fileName,
                    loadBias = loadBias,
                    generation = generation,
                    inputAddress = relative + loadBias,
                    relativeAddress = relative,
                    cuName = cuName,
                    cuCompDir = cuCompDir,
                    cuOffset = unit.offset,
                    cuVersion = unit.version,
                    tableVersion = unit.tableVersion,
                    scopeName = scope.name ?: scope.linkageName,
                    filePath = filePath,
                    line = lineRow?.row?.line,
                    column = lineRow?.row?.column,
                    sequenceIndex = seqIdx,
                    matchedRangeStart = range.start,
                    matchedRangeEnd = range.end,
                    matchedRangeLength = range.length,
                    inlineDepth = chain.size - 1,
                    inlineChain = chain,
                    priority = 100,
                    rangeLength = range.length,
                    cuIndex = unit.index,
                    dieOffset = scope.die.offset,
                    dwoMissing = unit.dwoName != null,
                    warnings = unit.warnings,
                    source = "dwarf",
                )
            }

            // line-only matches when no scope covers the address (e.g. line table
            // describes code whose DIE lives in a missing dwo)
            val (lineRow, seqIdx) = lineLookup(unit, relative)
            if (lineRow != null && matchingScopes.isEmpty()) {
                candidates += AddressCandidate(
                    moduleKey = module.key,
                    moduleVersion = module.version,
                    moduleFileName = module.fileName,
                    loadBias = loadBias,
                    generation = generation,
                    inputAddress = relative + loadBias,
                    relativeAddress = relative,
                    cuName = cuName,
                    cuCompDir = cuCompDir,
                    cuOffset = unit.offset,
                    cuVersion = unit.version,
                    tableVersion = unit.tableVersion,
                    scopeName = null,
                    filePath = filePathOf(unit, lineRow.row),
                    line = lineRow.row.line,
                    column = lineRow.row.column,
                    sequenceIndex = seqIdx,
                    matchedRangeStart = lineRow.sequence.startAddress,
                    matchedRangeEnd = lineRow.sequence.endAddress,
                    matchedRangeLength = lineRow.sequence.endAddress - lineRow.sequence.startAddress,
                    inlineDepth = 0,
                    inlineChain = emptyList(),
                    priority = 40,
                    rangeLength = lineRow.sequence.endAddress - lineRow.sequence.startAddress,
                    cuIndex = unit.index,
                    dieOffset = -1L,
                    dwoMissing = unit.dwoName != null,
                    warnings = unit.warnings + (if (unit.dwoName != null) listOf("仅有行表命中：可能缺少 dwo 内联信息") else emptyList()),
                    source = "line-only",
                )
            }
        }

        val sorted = candidates.sortedWith(
            compareByDescending<AddressCandidate> { it.priority }
                .thenBy { it.rangeLength }
                .thenByDescending { it.inlineDepth }
                .thenBy { it.cuIndex }
                .thenBy { it.dieOffset }
        )

        val notes = ArrayList<String>()
        if (sorted.isEmpty()) notes.add("地址未落入任何已知范围或 line sequence")
        if (sorted.size > 1) notes.add("保留 ${sorted.size} 个合法候选（重叠范围），按最窄范围/内联深度排序")

        return QueryExplanation(
            inputAddress = relative + loadBias,
            resolved = sorted.isNotEmpty(),
            loadBias = loadBias,
            generation = generation,
            moduleKey = module.key,
            moduleVersion = module.version,
            candidates = sorted,
            warnings = warnings.distinct(),
            notes = notes,
        )
    }

    private fun filePathOf(unit: CompUnit, row: LineRow): String? {
        val lp = unit.lineProgram ?: return null
        val f = lp.files.getOrNull(row.file - 1) ?: lp.files.getOrNull(row.file)
        return f?.fullPath ?: f?.name
    }

    private data class RowHit(val row: LineRow, val sequence: LineSequence)

    private fun lineLookup(unit: CompUnit, addr: Long): Pair<RowHit?, Int?> {
        val lp = unit.lineProgram ?: return null to null
        for (seq in lp.sequences) {
            val row = seq.rowFor(addr)
            if (row != null) return RowHit(row, seq) to seq.index
        }
        return null to null
    }

    private fun collectChain(
        die: Die,
        addr: Long,
        ancestorChain: MutableList<ScopeEntry>,
        matches: MutableList<Pair<ScopeEntry, AddrRange>>,
    ) {
        val cu = dwarf.cus[die.cuIndex]
        val extractor = scopeExtractor(cu)
        val entry = extractor.entryForDie(die)
        var pushed = false
        if (entry != null) {
            ancestorChain.add(entry)
            pushed = true
            val hit = entry.ranges.firstOrNull { it.length > 0 && it.contains(addr) }
            if (hit != null) matches += entry to hit
        }
        die.children.forEach { collectChain(it, addr, ancestorChain, matches) }
        if (pushed) ancestorChain.removeAt(ancestorChain.size - 1)
    }

    private val extractorCache = HashMap<Int, ScopeExtractor>()
    private fun scopeExtractor(cu: CompUnit): ScopeExtractor =
        extractorCache.getOrPut(cu.index) { ScopeExtractor(dwarf, cu) }

    private fun buildInlineChain(cu: CompUnit, leaf: ScopeEntry): List<InlineFrame> {
        // walk from CU root down to the leaf using the DIE tree, recording enclosing
        // subprogram / inlined_subroutine scopes.
        val path = ArrayList<Die>()
        fun find(die: Die): Boolean {
            path.add(die)
            if (die.offset == leaf.die.offset) return true
            if (die.children.any { find(it) }) return true
            path.removeAt(path.size - 1)
            return false
        }
        find(cu.root)
        val frames = ArrayList<InlineFrame>()
        for (die in path) {
            if (die.tag != DW.TAG_subprogram && die.tag != DW.TAG_inlined_subroutine) continue
            val extractor = scopeExtractor(cu)
            val entry = extractor.entryForDie(die)
            frames += InlineFrame(
                name = entry?.name ?: "(anonymous)",
                linkageName = entry?.linkageName,
                depth = frames.size,
                callFile = entry?.callFile,
                callLine = entry?.callLine,
                dieOffset = die.offset,
            )
        }
        return frames
    }
}
