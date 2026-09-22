package compass.dwarf

/** 一次模块加载快照：代次、加载基址。relAddr = runtimeAddr - loadBias。 */
data class ModuleSnapshot(
    val id: Long,
    val moduleVersionId: Long,
    val generation: Int,
    val loadBias: Long,
    val note: String?
)

data class InlineFrame(
    val dieOffset: Long,
    val depth: Int,
    val tag: Int,
    val name: String,
    val callFile: String?,
    val callLine: Int?,
    val rangeLow: Long?,
    val rangeHigh: Long?
) {
    val width: Long get() = if (rangeLow != null && rangeHigh != null) rangeHigh - rangeLow else Long.MAX_VALUE
}

data class LineCandidate(
    val cuOffset: Long,
    val cuName: String?,
    val cuVersion: Int,
    val tableVersion: Int,
    val sequenceIndex: Int,
    val sequenceStart: Long,
    val sequenceEnd: Long,
    val address: Long,
    val file: String?,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val segment: Long,
    val prologueEnd: Boolean,
    val frames: List<InlineFrame>,
    val rank: Int,
    val source: String,
    val warnings: List<String>
)

data class QueryResult(
    val runtimeAddress: Long,
    val loadBias: Long,
    val relativeAddress: Long,
    val snapshotGeneration: Int,
    val candidates: List<LineCandidate>,
    val resolved: Boolean,
    val warnings: List<String>,
    val degraded: Boolean
)

/**
 * 查询器。同一相对地址的所有合法解释都会保留为候选：
 *  - 每个 line sequence 中 address<=rel 的最后一行（同地址多行全保留）；
 *  - 每个覆盖 rel 的函数 DIE（重叠函数）各产生一个候选，携带其完整内联父链。
 * 排序（确定性）：最窄范围 → 内联深度 → 显式优先级（stmt/prologue）→ CU/地址/行列。
 */
class Resolver(private val parsed: ParsedDebugInfo) {

    fun query(runtimeAddress: Long, snapshot: ModuleSnapshot): QueryResult {
        val rel = runtimeAddress - snapshot.loadBias
        val warnings = ArrayList<String>()
        val degraded = parsed.cus.any { it.degraded }
        if (degraded) warnings.add("存在被隔离的 CU（未知 form/损坏 section）：其 DIE 级结论不可用；行号结论仅来自完好部分")

        val candidates = ArrayList<LineCandidate>()
        for (prog in parsed.programs) {
            val cu = parsed.cus.firstOrNull { it.offset == prog.cuOffset }
            data class Seq(val index: Int, val start: Long, val end: Long, val rows: List<Int>)
            val seqs = ArrayList<Seq>()
            var cur = ArrayList<Int>()
            for ((i, row) in prog.rows.withIndex()) {
                cur.add(i)
                if (row.endSequence) {
                    val first = if (cur.size > 1) prog.rows[cur.first()].address else row.address
                    seqs.add(Seq(seqs.size, first, row.address, cur))
                    cur = ArrayList()
                }
            }
            for (seq in seqs) {
                if (unsignedLt(rel, seq.start) || unsignedGt(rel, seq.end)) continue
                val eligible = seq.rows.filter { idx ->
                    val row = prog.rows[idx]
                    !row.endSequence && unsignedLe(row.address, rel)
                }
                if (eligible.isEmpty()) continue
                val lastAddr = prog.rows[eligible.last()].address
                val sameRowIdxs = eligible.filter { prog.rows[it].address == lastAddr }

                // 覆盖 rel 的函数根（subprogram 或最深 inline），重叠时多个
                val roots = coveringRoots(cu, rel, warnings)
                val frameOptions: List<List<InlineFrame>> =
                    if (roots.isEmpty()) listOf(emptyList()) else roots.map { buildChain(cu!!, it, rel, prog, warnings) }

                for (idx in sameRowIdxs) {
                    val row = prog.rows[idx]
                    for (frames in frameOptions) {
                        val missingDwo = cu?.dwoName != null && !dwoPresent(cu)
                        candidates.add(
                            LineCandidate(
                                cuOffset = prog.cuOffset,
                                cuName = cu?.name,
                                cuVersion = cu?.dwarfVersion ?: prog.table.dwarfVersion,
                                tableVersion = prog.table.dwarfVersion,
                                sequenceIndex = seq.index,
                                sequenceStart = seq.start,
                                sequenceEnd = seq.end,
                                address = row.address,
                                file = prog.fileName(row.fileIndex),
                                line = row.line,
                                column = row.column,
                                isStmt = row.isStmt,
                                segment = row.segment,
                                prologueEnd = row.prologueEnd,
                                frames = frames,
                                rank = rankFor(row),
                                source = when {
                                    cu == null -> "line-only"
                                    missingDwo -> "skeleton（缺 dwo）"
                                    cu.split -> "split(dwo)"
                                    else -> "full"
                                },
                                warnings = if (missingDwo) listOf(
                                    "DW_AT_dwo_name=${cu.dwoName} 未导入：skeleton 的行号、CU 与具体函数地址范围仍可信；内联链可能不完整"
                                ) else emptyList()
                            )
                        )
                    }
                }
            }
        }

        candidates.sortWith(
            compareByDescending<LineCandidate> { it.frames.firstOrNull()?.narrowScore() ?: 0L }
                .thenByDescending { it.frames.size }
                .thenByDescending { it.rank }
                .thenBy { it.cuOffset }
                .thenBy { it.address }
                .thenBy { it.line }
                .thenBy { it.column }
                .thenBy { it.frames.firstOrNull()?.dieOffset ?: 0L }
        )

        return QueryResult(
            runtimeAddress = runtimeAddress,
            loadBias = snapshot.loadBias,
            relativeAddress = rel,
            snapshotGeneration = snapshot.generation,
            candidates = candidates,
            resolved = candidates.isNotEmpty(),
            warnings = warnings.distinct(),
            degraded = degraded
        )
    }

    private fun InlineFrame.narrowScore(): Long {
        val w = width
        return if (w <= 0) 0L else Long.MAX_VALUE - w.coerceAtLeast(1L)
    }

    /**
     * 返回覆盖 [rel] 的“根函数节点”集合：
     *  - 内联子例程的顶层祖先 subprogram 去重；
     *  - 互相重叠的不同 subprogram 全部保留（重叠函数场景）；
     *  - 零长度范围不覆盖任何地址。
     */
    private fun coveringRoots(cu: CompilationUnit?, rel: Long, warnings: MutableList<String>): List<DieNode> {
        if (cu == null || cu.degraded) return emptyList()
        val funcs = cu.dies.values.filter { die ->
            (die.tag == DW.TAG_subprogram || die.tag == DW.TAG_inlined_subroutine) && die.covers(rel)
        }
        if (funcs.isEmpty()) return emptyList()
        val roots = LinkedHashMap<Long, DieNode>()
        for (f in funcs) {
            var node = f
            var guard = 0
            while (true) {
                if (++guard > 4096) { warnings.add("DIE 父链循环/过长，已截断"); break }
                val parent = node.parentOffset?.let { cu.dies[it] }
                if (parent != null && (parent.tag == DW.TAG_subprogram || parent.tag == DW.TAG_inlined_subroutine) && parent.covers(rel)) {
                    node = parent
                } else break
            }
            roots[node.offset] = node
        }
        return roots.values.sortedWith(compareBy<DieNode> { it.ranges.minOfOrNull { r -> r.high - r.low } ?: Long.MAX_VALUE }
            .thenBy { it.offset })
    }

    /** 从根函数向下走到覆盖点的最深内联节点，再由深到浅输出帧（帧0=最内层）。 */
    private fun buildChain(cu: CompilationUnit, root: DieNode, rel: Long, prog: LineProgram, warnings: MutableList<String>): List<InlineFrame> {
        val deepest = deepestCovering(cu, root, rel, 0, warnings)
        val ordered = ArrayList<DieNode>()
        var cur: DieNode? = deepest
        var hops = 0
        val added = HashSet<Long>()
        while (cur != null) {
            if (added.add(cur.offset)) ordered.add(cur)
            cur = cur.parentOffset?.let { cu.dies[it] }
            if (++hops > 256) { warnings.add("内联链超过 256 层，已截断"); break }
        }
        return ordered.mapIndexed { i, die ->
            val narrow = die.ranges.filter { !it.isEmpty }.minByOrNull { it.high - it.low }
            val originName = die.abstractOrigin?.let { resolveRef(cu, it, warnings)?.name }
            InlineFrame(
                dieOffset = die.offset,
                depth = i,
                tag = die.tag,
                name = die.name ?: originName ?: ("<anonymous 0x${die.offset.toString(16)}>"),
                callFile = die.callFile?.let { prog.fileName(it) },
                callLine = die.callLine,
                rangeLow = narrow?.low,
                rangeHigh = narrow?.high
            )
        }
    }

    private fun deepestCovering(cu: CompilationUnit, node: DieNode, rel: Long, depth: Int, warnings: MutableList<String>): DieNode {
        if (depth > 4096) return node
        var best: DieNode = node
        for (childOff in node.childrenOffsets) {
            val child = cu.dies[childOff] ?: continue
            if (child.tag == DW.TAG_inlined_subroutine && child.covers(rel)) {
                val deeper = deepestCovering(cu, child, rel, depth + 1, warnings)
                // 多个内联子节点重叠时取范围更窄者
                val wBest = best.ranges.filter { !it.isEmpty }.minOfOrNull { it.high - it.low } ?: Long.MAX_VALUE
                val wDeeper = deeper.ranges.filter { !it.isEmpty }.minOfOrNull { it.high - it.low } ?: Long.MAX_VALUE
                if (deeper != best && wDeeper < wBest) best = deeper
            }
        }
        return best
    }

    private fun rankFor(row: LineRow): Int {
        var score = 0
        if (row.isStmt) score += 4
        if (row.prologueEnd) score += 2
        score += 1
        return score
    }

    private fun dwoPresent(cu: CompilationUnit): Boolean =
        cu.dwoId != null && parsed.cus.any { it.split && it.dwoId == cu.dwoId }

    private fun resolveRef(cu: CompilationUnit, target: Long, warnings: MutableList<String>): DieNode? {
        cu.dies[target]?.let { return it }
        if (target < 0) warnings.add("引用偏移为负 0x${target.toString(16)}，判定越界并忽略")
        else warnings.add("引用 0x${target.toString(16)} 不落在当前 CU 内（跨 CU 或越界），本次忽略")
        return null
    }

    private fun unsignedLe(a: Long, b: Long) = java.lang.Long.compareUnsigned(a, b) <= 0
    private fun unsignedLt(a: Long, b: Long) = java.lang.Long.compareUnsigned(a, b) < 0
    private fun unsignedGt(a: Long, b: Long) = java.lang.Long.compareUnsigned(a, b) > 0
}
