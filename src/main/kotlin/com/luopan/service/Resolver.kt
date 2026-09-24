package com.luopan.service

import com.luopan.dwarf.*
import com.luopan.dwarf.DwarfAttr as A
import com.luopan.dwarf.DwarfTag as T

/** 一次查询固定的模块加载快照。 */
class LoadSnapshot(
    val moduleKey: String,
    val actualBase: Long,
    val preferredBase: Long,
) {
    val loadBias: Long get() = actualBase - preferredBase
}

class LineCandidate(
    val file: String,
    val line: Int,
    val column: Int,
    val segment: Long,
    val sequenceStart: Long,
    val sequenceEnd: Long,
    val cuName: String,
    val cuOffset: Int,
    val version: Int,
    val isStmt: Boolean,
    val endSequenceRow: Boolean,
    val score: Long,
)

class FunctionCandidate(
    val info: FunctionInfo,
    val matchedRange: AddrRange?,
    val rangeWidth: Long,
    val inlineFrames: List<InlineFrame>,
    val priority: Int,
    val score: Long,
    val fromSplit: Boolean,
)

class AddressResult(
    val queryAddress: Long,
    val relativeAddress: Long,
    val segment: Long,
    val loadBias: Long,
    val actualBase: Long,
    val preferredBase: Long,
    val lineCandidates: List<LineCandidate>,
    val functionCandidates: List<FunctionCandidate>,
    val trusted: Boolean,
    val trustNotes: List<String>,
    val tableVersionUsed: String?,
    val moduleKey: String,
)

class Resolver(private val store: ImportStore) {

    /**
     * 解析一个运行时地址。
     * 所有合法候选都保留：同一地址可命中重叠函数、多个 line sequence 与内联点。
     */
    fun resolve(
        moduleKey: String,
        runtimeAddr: Long,
        segment: Long = 0,
        snapshot: LoadSnapshot,
        versionId: Long? = null,
    ): AddressResult {
        val files = store.filesForModule(moduleKey, versionId)
        val rel = runtimeAddr - snapshot.loadBias
        val notes = mutableListOf<String>()
        var trusted = true
        var tableVersion: String? = null

        val lineCands = ArrayList<LineCandidate>()
        val funcCands = ArrayList<FunctionCandidate>()

        // skeleton 与 dwo 配对（同一次导入或跨版本导入，按版本确定性排序）
        val skeletons = files.flatMap { it.dwarf.units.filter { u -> u.isSkeleton } }
        val splitAll = files.flatMap { it.dwarf.splitUnits }

        for (imp in files) {
            val df = imp.dwarf
            if (df.diagnostics.any { it.severity == "ERROR" }) {
                trusted = false
                notes.add("模块 ${imp.fileName} 含 ERROR 级解析问题，地址结论可能不完整")
            }
            if (df.dwoExpected.isNotEmpty() && df.sections.infoDwo == null) {
                val available = store.allFiles().any { other ->
                    other.dwarf.splitUnits.any { su ->
                        su.dwoId != null && su.dwoId in df.dwoExpected.map { it.first }
                    }
                }
                if (!available) {
                    notes.add("缺少 .dwo（${df.dwoExpected.mapNotNull { it.second }.joinToString()}）：" +
                        "骨架中的地址范围仍可信，但内联调用链与部分行号不可得")
                }
            }

            // ---- line 候选（主 .debug_line + split .debug_line.dwo）----
            for (lp in listOf(df.line, df.splitLine)) {
                for (seq in lp.sequences) {
                    val rows = seq.rows
                    for (i in rows.indices) {
                        val row = rows[i]
                        if (row.segment != segment) continue
                        val next = rows.getOrNull(i + 1)?.address ?: seq.endAddress
                        val covers = if (row.endSequence) row.address == rel
                        else rel in row.address until next
                        if (!covers) continue
                        // end_sequence 行的地址是"末端哨兵"，不作为普通命中
                        if (row.endSequence && rel != row.address) continue
                        val file = row.file?.path ?: "<unknown>"
                        val closeness = rel - row.address
                        val score = closeness
                        lineCands.add(
                            LineCandidate(
                                file, row.line, row.column, row.segment,
                                seq.startAddress, seq.endAddress, seq.cuName, seq.cuOffset,
                                seq.version, row.isStmt, row.endSequence, score,
                            )
                        )
                        if (tableVersion == null) tableVersion = "DWARF v${seq.version}"
                    }
                }
            }

            // ---- 函数 / 内联候选 ----
            funcCands.addAll(collectFunctionCandidates(imp, df.units, rel, segment, false, notes))
            funcCands.addAll(collectFunctionCandidates(imp, df.splitUnits, rel, segment, true, notes))
        }

        // 全局确定性排序：不依赖导入先后（见 score 键中的内容型 tie-break）
        val sortedLines = lineCands
            .sortedWith(compareBy<LineCandidate> { it.score }
                .thenBy { it.version * -1 }
                .thenBy { it.cuName }
                .thenBy { it.file }
                .thenBy { it.line }
                .thenBy { it.sequenceStart })
            .distinctBy { listOf(it.file, it.line, it.column, it.sequenceStart, it.cuOffset) }

        val sortedFuncs = rankFunctions(funcCands)

        if (sortedLines.isEmpty() && sortedFuncs.isEmpty()) {
            notes.add("地址 0x${"%x".format(rel)} 未落入任何已知范围：行号与函数均不可判定（这本身是可信的否定结论）")
        }

        return AddressResult(
            queryAddress = runtimeAddr, relativeAddress = rel, segment = segment,
            loadBias = snapshot.loadBias, actualBase = snapshot.actualBase,
            preferredBase = snapshot.preferredBase,
            lineCandidates = sortedLines, functionCandidates = sortedFuncs,
            trusted = trusted, trustNotes = notes.distinct(),
            tableVersionUsed = tableVersion, moduleKey = moduleKey,
        )
    }

    private fun collectFunctionCandidates(
        imp: ImportedFile, units: List<CompileUnit>, rel: Long, segment: Long,
        fromSplit: Boolean, notes: MutableList<String>,
    ): List<FunctionCandidate> {
        val out = ArrayList<FunctionCandidate>()
        for (cu in units) {
            val dieByOffset = cu.dies.associateBy { it.offset }
            val funcs = imp.dwarf.functions.filter { it.cuOffset == cu.sectionOffset }
            val rangeByDie = cu.ranges.groupBy { it.dieIndex }
            for (fn in funcs) {
                val die = dieByOffset[fn.dieOffset] ?: continue
                val ranges = (rangeByDie[die.index] ?: emptyList()).map { it.range }
                var matched: AddrRange? = null
                for (r in ranges) {
                    if (r.segment != 0L && r.segment != segment) continue
                    if (r.length == 0L) {
                        if (r.start == rel) { matched = r; break }
                    } else if (rel in r.start until r.end) { matched = r; break }
                }
                if (ranges.isEmpty()) continue
                if (matched == null) continue

                val chain = buildInlineChain(cu, die, dieByOffset, imp.dwarf.functions, rel)
                val priority = explicitPriority(die, fn, chain)
                val width = matched.length
                val depthScore = chain.size
                val score = tieScore(width, depthScore, priority, fn, cu, matched)
                out.add(FunctionCandidate(fn, matched, width, chain, priority, score, fromSplit))
            }
        }
        return out
    }

    /** 从命中的 DIE 向根走，收集 inlined_subroutine 帧；名字经 abstract_origin/specification 解析。 */
    private fun buildInlineChain(
        cu: CompileUnit, hitDie: Die, dieByOffset: Map<Int, Die>,
        allFuncs: List<FunctionInfo>, rel: Long,
    ): List<InlineFrame> {
        val funcByDie = allFuncs.filter { it.cuOffset == cu.sectionOffset }.associateBy { it.dieOffset }
        val frames = ArrayList<InlineFrame>()
        var cur: Die? = hitDie
        var depth = 0
        val guard = HashSet<Int>()
        while (cur != null) {
            val d = cur
            if (!guard.add(d.offset)) break // 引用环保护
            if (d.tag == T.INLINED_SUBROUTINE || d.tag == T.SUBPROGRAM || d.tag == T.ENTRY_POINT) {
                val (name, originOff, inlineVal, declLine) = resolveIdentity(d, dieByOffset, funcByDie)
                val callLine = (d.attr(A.CALL_LINE) as? AttrVal.Const)?.v?.toInt()
                frames.add(
                    InlineFrame(
                        depth = depth,
                        functionName = name,
                        file = null,
                        line = callLine ?: declLine?.toInt(),
                        dieOffset = d.offset,
                        abstractOriginOffset = originOff,
                        inlineCode = inlineVal,
                    )
                )
                depth++
            }
            cur = if (d.parent >= 0) cu.dies.getOrNull(d.parent) else null
        }
        // 命中点在最内：由内向外已经成立
        return frames
    }

    private data class Identity(
        val name: String,
        val origin: Int?,
        val inline: Long?,
        val declLine: Long?,
    )

    private fun resolveIdentity(
        die: Die,
        dieByOffset: Map<Int, Die>,
        funcByDie: Map<Int, FunctionInfo>,
    ): Identity {
        var name = (die.attr(A.NAME) as? AttrVal.Str)?.v
        var inline = (die.attr(A.INLINE) as? AttrVal.Const)?.v
        var declLine = (die.attr(A.DECL_LINE) as? AttrVal.Const)?.v
        var origin: Int? = null
        var cur = die
        var hops = 0
        val seen = HashSet<Int>()
        while (hops < 16) {
            val viaAbstract = (cur.attr(A.ABSTRACT_ORIGIN) as? AttrVal.Ref)?.offset
            val viaSpec = (cur.attr(A.SPECIFICATION) as? AttrVal.Ref)?.offset
            val next = viaAbstract ?: viaSpec ?: break
            origin = next
            if (!seen.add(next)) break
            val target = dieByOffset[next] ?: break
            cur = target
            name = name ?: (target.attr(A.NAME) as? AttrVal.Str)?.v
            inline = inline ?: (target.attr(A.INLINE) as? AttrVal.Const)?.v
            declLine = declLine ?: (target.attr(A.DECL_LINE) as? AttrVal.Const)?.v
            hops++
        }
        return Identity(name ?: "<anonymous@0x${"%x".format(die.offset)}>", origin, inline, declLine)
    }

    /**
     * 显式优先级：有名字、有具体范围（非声明）、非 artificial、subprogram 优先等。
     * 值越大越优先；仅在范围宽度与内联深度之后决定最终次序。
     */
    private fun explicitPriority(die: Die, fn: FunctionInfo, chain: List<InlineFrame>): Int {
        var p = 0
        if (fn.name != null && !fn.name.startsWith("<anonymous")) p += 4
        if (!fn.declaration) p += 2
        if (die.tag == T.SUBPROGRAM) p += 2
        if (die.tag == T.INLINED_SUBROUTINE) p += 1
        if ((die.attr(A.ARTIFICIAL) as? AttrVal.Flag)?.v == true) p -= 3
        return p
    }

    /** 内容型稳定次序：宽度→深度→优先级→名字→CU→DIE 偏移，导入次序不参与。 */
    private fun tieScore(
        width: Long, depth: Int, priority: Int, fn: FunctionInfo, cu: CompileUnit, matched: AddrRange,
    ): Long {
        // 仅用于排序比较（不要求数学含义）
        var h = 1125899906842597L
        val text = (fn.name ?: "") + "|" + cu.name + "|" + fn.dieOffset
        for (c in text) h = 31 * h + c.code
        return h
    }

    private fun rankFunctions(cands: List<FunctionCandidate>): List<FunctionCandidate> {
        return cands.sortedWith(
            compareBy<FunctionCandidate> { it.matchedRange!!.length } // 最窄范围
                .thenByDescending { it.inlineFrames.size }             // 内联更深
                .thenByDescending { it.priority }                       // 显式优先级
                .thenBy { it.matchedRange!!.start }
                .thenBy { it.info.cuName }
                .thenBy { it.info.name ?: "" }
                .thenBy { it.info.dieOffset }
        ).distinctBy { listOf(it.info.dieOffset, it.info.cuOffset, it.matchedRange?.start, it.matchedRange?.end) }
    }
}
