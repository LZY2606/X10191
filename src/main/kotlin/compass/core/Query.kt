package compass.core

import compass.dwarf.LineRow

data class InlineFrame(
    val name: String?,
    val callFile: String?,
    val callLine: Long?,
    val callColumn: Long?,
)

data class QueryCandidate(
    val cuIndex: Int,
    val cuName: String,
    val cuOffset: Long,
    val infoVersion: Int,
    val lineVersion: Int?,
    val file: String,
    val line: Long,
    val column: Long,
    val sequence: Int,
    val functionName: String?,
    val functionRangeWidth: Long,
    val inlineDepth: Int,
    val inlineChain: List<InlineFrame>,   // outermost first
    val priority: Int,
)

data class QueryResult(
    val inputAddress: Long,
    val loadBias: Long,
    val relativeAddress: Long,
    val candidates: List<QueryCandidate>,
    val notes: List<String>,
) {
    val best: QueryCandidate? get() = candidates.firstOrNull()
}

/**
 * Address query engine. Runtime addresses are de-relocated with the snapshot's
 * load bias; every legal candidate is kept and ranked by (narrowest range,
 * deepest inline chain, explicit priority) with deterministic tie-breaks so
 * results do not depend on import order.
 */
class QueryEngine(
    private val model: DebugFileModel,
    private val loadBias: Long,
    private val priority: Int = 0,
) {
    fun query(inputAddress: Long, inputIsRuntime: Boolean = true): QueryResult {
        val rel = if (inputIsRuntime) inputAddress - loadBias else inputAddress
        val notes = mutableListOf<String>()
        notes += model.trustNotes
        val candidates = mutableListOf<QueryCandidate>()

        for (cu in model.cus) {
            if (cu.isolated) continue
            val row = findLineRow(cu, rel)
            val containingScopes = cu.scopes.filter { s -> s.ranges.any { it.contains(rel) } }
            val narrowest = containingScopes
                .flatMap { s -> s.ranges.filter { it.contains(rel) } }
                .minOfOrNull { it.length }
            val fnScope = containingScopes
                .filter { it.tag == compass.dwarf.Dw.TAG_subprogram }
                .minByOrNull { s -> s.ranges.filter { it.contains(rel) }.minOf { it.length } }
            val inlineSites = cu.inlines
                .filter { site -> site.ranges.any { it.contains(rel) } }
                .sortedBy { it.depth }
            val chain = inlineSites.map {
                InlineFrame(it.name, it.callFile, it.callLine, it.callColumn)
            }
            val inlineDepth = inlineSites.maxOfOrNull { it.depth } ?: 0

            if (row == null && containingScopes.isEmpty()) continue

            val width = narrowest
                ?: cu.ranges.filter { it.contains(rel) }.minOfOrNull { it.length }
                ?: Long.MAX_VALUE

            candidates += QueryCandidate(
                cuIndex = cu.index,
                cuName = cu.name,
                cuOffset = cu.offset,
                infoVersion = cu.version,
                lineVersion = cu.lineVersion,
                file = row?.file ?: "<no-line-info>",
                line = row?.line ?: 0,
                column = row?.column ?: 0,
                sequence = row?.sequence ?: -1,
                functionName = fnScope?.name,
                functionRangeWidth = width,
                inlineDepth = inlineDepth,
                inlineChain = chain,
                priority = priority,
            )
        }

        candidates.sortWith(
            compareBy(
                { it.functionRangeWidth },
                { -it.inlineDepth },
                { -it.priority },
                { it.cuName },
                { it.cuOffset },
                { it.file },
                { it.line },
                { it.sequence },
            )
        )
        if (candidates.isEmpty()) notes += "相对地址 0x${rel.toString(16)} 未命中任何 CU 范围。"
        return QueryResult(inputAddress, loadBias, rel, candidates, notes.distinct())
    }

    /**
     * Finds the line row covering [addr]. Rows are grouped per sequence; a row
     * covers [row.addr, nextRow.addr). Zero-length ranges match nothing.
     */
    private fun findLineRow(cu: CuModel, addr: Long): LineRow? {
        val bySeq = cu.lineRows.groupBy { it.sequence }
        var best: LineRow? = null
        for ((_, rows) in bySeq) {
            for (i in rows.indices) {
                val row = rows[i]
                if (row.endSequence) continue
                val next = rows.getOrNull(i + 1)
                val end = next?.address ?: continue
                if (end <= row.address) continue // zero-length / degenerate: no coverage
                if (addr >= row.address && addr < end) {
                    if (best == null || row.address > best!!.address) best = row
                }
            }
        }
        return best
    }
}
