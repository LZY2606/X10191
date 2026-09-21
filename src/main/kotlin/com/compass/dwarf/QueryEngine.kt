package com.compass.dwarf

/**
 * Resolves a relative (unrelocated) address against parsed debug data.
 *
 * Every legal candidate is retained and ordered deterministically:
 *  1. explicit rank (DIE+line > line only)
 *  2. narrowest enclosing range
 *  3. greatest inline depth
 *  4. a stable content key (file hash, CU offset, sequence/row) — the result
 *     order therefore does not depend on import order.
 */
class QueryEngine(private val debugFiles: List<ParsedDebug>) {

    data class InlineFrame(
        val tag: String,
        val name: String?,
        val ranges: List<AddrRange>,
        val callFile: String?,
        val callLine: Int?,
        val callColumn: Int?,
        val depth: Int,
        val source: String
    )

    data class Candidate(
        val rank: Int,
        val cuName: String?,
        val cuOffset: Long,
        val cuCompDir: String?,
        val dwarfVersion: Int,
        val fileName: String,
        val line: Int,
        val column: Int,
        val sequenceIndex: Int,
        val sequenceStart: Long,
        val sequenceEnd: Long,
        val rowAddress: Long,
        val functionName: String?,
        val enclosingRange: AddrRange?,
        val inlineDepth: Int,
        val inlineChain: List<InlineFrame>,
        val lineTableVersion: Int,
        val issues: List<ParseIssue>,
        val dwoResolved: Boolean,
        val isSplit: Boolean,
        val stableKey: String,
        val confidence: String
    ) {
        val trustNotes: List<String>
            get() = buildList {
                if (issues.any { it.severity == "error" })
                    add("该 CU 存在解析错误；行列与序列来自成功解析的部分，错误域之外的结论仍可信。")
                if (isSplit && !dwoResolved)
                    add("缺少 .dwo：文件/行号、CU 范围与 load bias 仍可信；内联调用树可能不完整。")
                if (issues.any { it.scope == "form" })
                    add("遇到未知 DW_FORM：对应 DIE 属性被隔离，line program 独立解析仍可信。")
                if (issues.none { it.severity == "error" } && !(isSplit && !dwoResolved))
                    add("解析完整：CU、范围、line program 与内联树全部来自本地解析。")
            }
    }

    fun query(relativeAddr: Long): List<Candidate> {
        val candidates = mutableListOf<Candidate>()
        for (parsed in debugFiles.sortedBy { it.elf.sha256 }) {
            for (cu in parsed.cus.sortedBy { it.offset }) queryCu(parsed, cu, relativeAddr, candidates)
        }
        return candidates.sortedWith(
            compareByDescending<Candidate> { it.rank }
                .thenBy { it.enclosingRange?.length ?: Long.MAX_VALUE }
                .thenByDescending { it.inlineDepth }
                .thenBy { it.stableKey }
        )
    }

    private fun queryCu(parsed: ParsedDebug, cu: CuInfo, addr: Long, out: MutableList<Candidate>) {
        val lt = cu.lineTable ?: return
        for (seq in lt.sequences.sortedBy { it.startAddress }) {
            if (addr < seq.startAddress || addr > seq.endAddress) continue
            val row = seq.rows.filter { it.address <= addr }.maxByOrNull { it.address } ?: continue
            val chain = cu.inlineChainAt(addr)
            val leaf = chain.firstOrNull()
            val enclosing = leaf?.ranges?.filter { it.contains(addr) }?.minByOrNull { it.length }
                ?: cu.ranges.filter { it.contains(addr) }.minByOrNull { it.length }
            val rank = when {
                leaf != null && enclosing != null -> 4
                enclosing != null -> 3
                else -> 2
            }
            val frames = chain.map { die ->
                InlineFrame(
                    die.tagName,
                    die.resolvedName,
                    die.ranges,
                    die.callFileResolved,
                    (die.attr(DW_AT_call_line) as? AttrValue.Num)?.v?.toInt(),
                    (die.attr(DW_AT_call_column) as? AttrValue.Num)?.v?.toInt(),
                    die.depth,
                    if (cu.isSplit && cu.dwoResolved) "dwo" else "main"
                )
            }
            val confidence = when {
                cu.issues.any { it.severity == "error" } -> "degraded"
                cu.isSplit && !cu.dwoResolved -> "partial"
                rank >= 4 -> "exact"
                else -> "line-only"
            }
            out += Candidate(
                rank = rank,
                cuName = cu.name,
                cuOffset = cu.offset,
                cuCompDir = cu.compDir,
                dwarfVersion = cu.version,
                fileName = lt.resolveFile(row.fileIndex),
                line = row.line,
                column = row.column,
                sequenceIndex = seq.index,
                sequenceStart = seq.startAddress,
                sequenceEnd = seq.endAddress,
                rowAddress = row.address,
                functionName = leaf?.resolvedName,
                enclosingRange = enclosing,
                inlineDepth = chain.size,
                inlineChain = frames,
                lineTableVersion = lt.version,
                issues = (cu.issues + parsed.issues).distinct(),
                dwoResolved = !cu.isSplit || cu.dwoResolved,
                isSplit = cu.isSplit,
                stableKey = "${parsed.elf.sha256.take(16)}:${cu.offset.toString(16)}:${seq.index}:${row.address.toString(16)}",
                confidence = confidence
            )
        }
    }
}
