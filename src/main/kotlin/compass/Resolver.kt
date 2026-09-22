package compass.dwarf

/** 内联调用链中的一帧。 */
data class InlineFrame(
    val depth: Int,
    val name: String,
    val linkageName: String?,
    val tag: String,
    val callFile: String?,
    val callLine: Int?,
    val callColumn: Int?,
    val inlineCode: Long?, // 0 not inlined,1 inlined,2 declared not,3 declared yes
    val dieOffset: Long,
    val source: String
)

data class RangeHit(
    val dieOffset: Long,
    val tag: Int,
    val name: String,
    val rangeSource: String,
    val lo: Long,
    val hi: Long,
    val width: ULong,
    val pointMatch: Boolean,
    val inlineDepth: Int,
    val priority: Int,
    val frames: List<InlineFrame>
)

data class AddressHit(
    val segment: Long,
    val addressRel: Long,
    val loadBias: Long?,
    val generation: Long?,
    val file: String?,
    val line: Int?,
    val column: Int?,
    val cuName: String?,
    val cuOffset: Long,
    val dwarfVersion: Int,
    val sequenceIndex: Int?,
    val sequenceStart: Long?,
    val sequenceEnd: Long?,
    val frames: List<InlineFrame>,
    val candidates: List<RangeHit>,
    val splitDwoName: String?,
    val notes: List<String>
)

class ResolutionInput(
    val units: List<CompileUnit>,
    val dieById: (Long, Int) -> Die?, // cuIndex, offset
    val segment: Long,
    val address: Long,
    val loadBias: Long? = null,
    val generation: Long? = null
)

/**
 * 地址解析核心。
 *
 * 排序（稳定，且不依赖导入顺序）：
 *  1) 普通区间 [lo,hi) 命中优先于零长度点命中；
 *  2) 区间越窄越优先（width 升序）；
 *  3) 内联深度越深越优先；
 *  4) 显式优先级（subprogram=2, inlined_subroutine=3, lexical_block=1）；
 *  5) 内容兜底键：CU 偏移、DIE 偏移、range 来源。
 * 全部合法候选都保留在 candidates 中。
 */
class Resolver {
    fun resolve(input: ResolutionInput): AddressHit? {
        val addr = input.address
        val notes = mutableListOf<String>()
        var best: RangeHit? = null
        val all = mutableListOf<RangeHit>()

        for ((cuIdx, cu) in input.units.withIndex()) {
            // 分段地址：segment 不匹配的 CU 跳过（segment 0 是默认）
            val ranges = cu.dieRanges
            for ((dieOff, rr) in ranges) {
                val die = cu.diesFlat.firstOrNull { it.offset == dieOff } ?: continue
                for (r in rr) {
                    if (r.segment != input.segment) continue
                    val point = r.zeroLength
                    val hit = if (!point) Util.unsignedLeq(r.lo, addr) && Util.unsignedLess(addr, r.hi)
                    else r.lo == addr
                    if (!hit) continue
                    val frames = buildChain(cu, die, input)
                    val name = frames.lastOrNull()?.name ?: dieName(cu, die, input)
                    val cand = RangeHit(
                        dieOffset = dieOff, tag = die.tag, name = name,
                        rangeSource = r.source, lo = r.lo, hi = r.hi,
                        width = Util.width(r.lo, r.hi), pointMatch = point,
                        inlineDepth = frames.indexOfLast { it.tag == "DW_TAG_inlined_subroutine" } + 1,
                        priority = priorityFor(die.tag),
                        frames = frames
                    )
                    all += cand
                }
            }
        }

        val sorted = all.sortedWith(compareBy(
            { it.pointMatch },                 // false 在前
            { it.width },                      // 越窄越前
            { -it.inlineDepth },               // 越深越前
            { -it.priority },
            { cuOffsetOf(it) },
            { it.dieOffset },
            { it.rangeSource }
        ))
        best = sorted.firstOrNull()

        // 行号：在最佳候选所在 CU 的 line program 中找
        var file: String? = null
        var line: Int? = null
        var column: Int? = null
        var cuName: String? = null
        var cuOffset = -1L
        var dwarfVersion = 0
        var seqIndex: Int? = null
        var seqStart: Long? = null
        var seqEnd: Long? = null
        var dwo: String? = null
        val chosenCu = best?.let { hit -> input.units.firstOrNull { cu -> cu.diesFlat.any { it.offset == hit.dieOffset } } }
            ?: input.units.firstOrNull { cu -> cu.ranges.any { it.segment == input.segment && Util.unsignedLeq(it.lo, addr) && Util.unsignedLess(addr, it.hi) } }

        if (chosenCu != null) {
            cuName = chosenCu.name
            cuOffset = chosenCu.globalOffset
            dwarfVersion = chosenCu.version
            dwo = chosenCu.dwoName
            val prog = chosenCu.lineProgram
            if (prog != null) {
                val seq = prog.sequences.firstOrNull {
                    it.segment == input.segment && Util.unsignedLeq(it.start, addr) && Util.unsignedLeq(addr, it.end)
                }
                if (seq != null) {
                    seqIndex = seq.index; seqStart = seq.start; seqEnd = seq.end
                    val rows = prog.rows.filter { !it.endSequence }.sortedByDescending { it.order }
                    val row = rows.firstOrNull { it.segment == input.segment && Util.unsignedLeq(it.address, addr) }
                    if (row != null) {
                        line = row.line; column = if (row.column == 0) null else row.column
                        val fi = fileIndexForVersion(prog, row.fileIndex)
                        file = prog.files.getOrNull(fi)?.path
                    }
                } else {
                    notes += "地址不在任何 line sequence 内（可能是 gap / 函数外代码）"
                }
            } else if (dwo != null) {
                notes += "行号位于 dwo '$dwo' 中但未导入，骨架级 CU/函数范围结论仍可信"
            }
        }

        if (best == null && chosenCu == null) return null
        return AddressHit(
            segment = input.segment, addressRel = addr, loadBias = input.loadBias, generation = input.generation,
            file = file, line = line, column = column, cuName = cuName, cuOffset = cuOffset,
            dwarfVersion = dwarfVersion, sequenceIndex = seqIndex, sequenceStart = seqStart, sequenceEnd = seqEnd,
            frames = best?.frames ?: emptyList(), candidates = sorted, splitDwoName = dwo, notes = notes
        )
    }

    /** v5 行号文件索引 0-based，v4 从 1 开始；统一映射到 files 列表下标。 */
    private fun fileIndexForVersion(prog: LineProgram, index: Int): Int =
        if (prog.version >= 5) index else (index - 1).coerceAtLeast(0)

    private fun cuOffsetOf(hit: RangeHit): Long = hit.dieOffset // 真正 CU 在 buildChain 时无法得到，用 DIE 偏移足够兜底唯一

    private fun priorityFor(tag: Int) = when (tag) {
        DW.TAG_INLINED_SUBROUTINE -> 3
        DW.TAG_SUBPROGRAM -> 2
        DW.TAG_LEXICAL_BLOCK -> 1
        else -> 0
    }

    /**
     * 构造内联链：从命中的 DIE 向上走父链（通过 diesFlat 的深度序），
     * 并沿 abstract_origin / specification 解析名称与调用位置。引用跳转次数受限。
     */
    private fun buildChain(cu: CompileUnit, leaf: Die, input: ResolutionInput): List<InlineFrame> {
        val byOffset = cu.diesFlat
        val parents = HashMap<Long, Die?>()
        val stack = ArrayDeque<Die>()
        for (d in byOffset) {
            while (stack.isNotEmpty() && stack.last().depth >= d.depth) stack.removeLast()
            parents[d.offset] = stack.lastOrNull()
            stack.addLast(d)
        }

        val frames = mutableListOf<InlineFrame>()
        var cur: Die? = leaf
        var hops = 0
        val seen = HashSet<Long>()
        var depthCounter = 0
        while (cur != null && depthCounter < 64) {
            val d = cur
            val origin = followOrigin(d, cu, seen)
            val name = stringAttr(origin ?: d, DW.AT_NAME, input)
                ?: stringAttr(origin ?: d, DW.AT_LINKAGE_NAME, input) ?: "?"
            val linkage = stringAttr(d, DW.AT_LINKAGE_NAME, input)
            val callFileNum = d.num(DW.AT_CALL_FILE)
            val callFile = callFileNum?.let { _ ->
                // 调用文件存在 DW_AT_call_file；line 程序文件表归属 CU，此处仅展示索引
                "file#$callFileNum"
            }
            frames += InlineFrame(
                depth = depthCounter,
                name = name,
                linkageName = linkage,
                tag = tagName(d.tag),
                callFile = callFile,
                callLine = d.num(DW.AT_CALL_LINE)?.toInt(),
                callColumn = d.num(DW.AT_CALL_COLUMN)?.toInt(),
                inlineCode = d.num(DW.AT_INLINE) ?: origin?.num(DW.AT_INLINE),
                dieOffset = d.offset,
                source = if (origin != null) "abstract_origin" else "direct"
            )
            depthCounter++
            cur = parents[d.offset]
            // 父链上只保留函数/内联节点
            while (cur != null && cur.tag != DW.TAG_SUBPROGRAM && cur.tag != DW.TAG_INLINED_SUBROUTINE) {
                cur = parents[cur.offset]
            }
            hops++
            if (hops > 64) break
        }
        return frames
    }

    private fun followOrigin(die: Die, cu: CompileUnit, seen: HashSet<Long>): Die? {
        val ref = die.attr(DW.AT_ABSTRACT_ORIGIN)?.value
            ?: die.attr(DW.AT_SPECIFICATION)?.value
            ?: return null
        val target = (ref as? Raw.DieRef)?.globalOffset ?: (ref as? Long) ?: return null
        if (!seen.add(target)) return null
        return cu.diesFlat.firstOrNull { it.offset == target }
    }

    private fun dieName(cu: CompileUnit, die: Die, input: ResolutionInput): String {
        val origin = die.attr(DW.AT_ABSTRACT_ORIGIN)?.value ?: die.attr(DW.AT_SPECIFICATION)?.value
        val target = (origin as? Raw.DieRef)?.globalOffset ?: return die.attr(DW.AT_NAME)?.value as? String ?: "?"
        val refDie = cu.diesFlat.firstOrNull { it.offset == target }
        return refDie?.attr(DW.AT_NAME)?.value as? String ?: "?"
    }

    private fun stringAttr(die: Die, attr: Int, input: ResolutionInput): String? = die.attr(attr)?.value as? String

    private fun tagName(tag: Int) = when (tag) {
        DW.TAG_SUBPROGRAM -> "DW_TAG_subprogram"
        DW.TAG_INLINED_SUBROUTINE -> "DW_TAG_inlined_subroutine"
        DW.TAG_LEXICAL_BLOCK -> "DW_TAG_lexical_block"
        DW.TAG_COMPILE_UNIT -> "DW_TAG_compile_unit"
        else -> "DW_TAG_0x${tag.toString(16)}"
    }
}
