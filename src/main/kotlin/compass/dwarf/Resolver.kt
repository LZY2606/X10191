package compass.dwarf

/** 一个可被地址命中的词法作用域（函数 / 内联实例 / 词法块）。 */
data class Scope(
    val dieOffset: Long,
    val tag: Int,
    val name: String,
    val declFile: String?,
    val declLine: Int?,
    val inlineDepth: Int,
    val ranges: List<AddrRange>,
    val callFile: String?,
    val callLine: Int?,
    val callColumn: Int?,
    val abstractName: String?,
    val parent: Scope?,
    val unit: CompUnit
) {
    val inlined: Boolean get() = tag == Tag.INLINED_SUBROUTINE
    /** 命中某地址时该 scope 的最窄包含范围宽度（0 长度范围按精确点处理）。 */
    fun containingWidth(a: SegAddr): Long? {
        var best: Long? = null
        for (r in ranges) {
            if (r.contains(a)) {
                val w = if (r.zeroLength) 0L else r.length
                if (best == null || w < best!!) best = w
            }
        }
        return best
    }
}

data class LineMatch(
    val unit: CompUnit,
    val sequence: LineSequence,
    val row: LineRow,
    val filePath: String,
    val distance: Long,
    val equalPoint: Boolean
)

data class InlineFrame(
    val depth: Int,
    val name: String,
    val tag: String,
    val declFile: String?,
    val declLine: Int?,
    val callFile: String?,
    val callLine: Int?,
    val callColumn: Int?,
    val rangeWidth: Long,
    val dieOffset: Long
)

data class TrustInfo(val level: String, val reasons: List<String>) {
    companion object {
        val HIGH = "高"
        val MEDIUM = "中"
        val LOW = "低"
    }
}

data class AddressResult(
    val runtimeAddress: SegAddr,
    val relativeAddress: SegAddr,
    val loadBias: Long,
    val snapshotId: Long?,
    val snapshotLabel: String,
    val filePath: String?,
    val fileId: Int?,
    val line: Int?,
    val column: Int?,
    val tableVersion: Int?,
    val unitName: String?,
    val unitOffset: Long?,
    val sequenceIndex: Int?,
    val sequenceStart: SegAddr?,
    val sequenceEnd: SegAddr?,
    val inlineChain: List<InlineFrame>,
    val candidates: List<CandidateView>,
    val trust: TrustInfo,
    val notes: List<String>
)

data class CandidateView(
    val rank: Int,
    val filePath: String,
    val line: Int,
    val column: Int,
    val unit: String,
    val unitOffset: Long,
    val sequence: Int,
    val rangeWidth: Long,
    val inlineDepth: Int,
    val equalPoint: Boolean,
    val tableVersion: Int,
    val selectionReason: String
)

class Resolver {

    fun buildScopes(unit: CompUnit): List<Scope> {
        val root = unit.root ?: return emptyList()
        val out = ArrayList<Scope>()
        val abstractNames = collectAbstractNames(unit)
        fun walk(die: Die, parent: Scope?, depth: Int) {
            val tag = die.tag
            if (tag == Tag.SUBPROGRAM || tag == Tag.INLINED_SUBROUTINE || tag == Tag.LEXICAL_BLOCK) {
                val ranges = dieRanges(die, unit)
                val name = nameOf(die, unit, abstractNames)
                val scope = Scope(
                    die.offset, tag, name,
                    fileOf(unit, die.attr(Attr.DECL_FILE)?.asLong()?.toInt()),
                    die.attr(Attr.DECL_LINE)?.asLong()?.toInt(),
                    depth, ranges,
                    fileOf(unit, die.attr(Attr.CALL_FILE)?.asLong()?.toInt()),
                    die.attr(Attr.CALL_LINE)?.asLong()?.toInt(),
                    die.attr(Attr.DW_AT_GNU_call_col)?.asLong()?.toInt(),
                    abstractOriginName(die, abstractNames),
                    parent, unit
                )
                out += scope
                die.children.forEach { walk(it, scope, depth + 1) }
            } else {
                die.children.forEach { walk(it, parent, depth) }
            }
        }
        walk(root, null, 0)
        return out
    }

    private fun collectAbstractNames(unit: CompUnit): Map<Long, String> {
        val m = HashMap<Long, String>()
        unit.root?.walk { die, _ ->
            val inline = die.attr(Attr.INLINE)?.asLong()
            if (die.tag == Tag.SUBPROGRAM && inline != null && inline != 0L) {
                die.attr(Attr.NAME)?.asString()?.let { m[die.offset] = it }
            }
        }
        return m
    }

    private fun abstractOriginName(die: Die, abstract: Map<Long, String>): String? {
        val origin = (die.attr(Attr.ABSTRACT_ORIGIN) as? AttrValue.Ref)?.unitOffset
            ?: (die.attr(Attr.SPECIFICATION) as? AttrValue.Ref)?.unitOffset
        return origin?.let { abstract[it] }
    }

    private fun nameOf(die: Die, unit: CompUnit, abstract: Map<Long, String>): String {
        die.attr(Attr.NAME)?.asString()?.let { return it }
        abstractOriginName(die, abstract)?.let { return it }
        return when (die.tag) {
            Tag.SUBPROGRAM -> "?(subprogram@0x${die.offset.toString(16)})"
            Tag.INLINED_SUBROUTINE -> "?(inlined@0x${die.offset.toString(16)})"
            else -> "(lexical_block)"
        }
    }

    private fun fileOf(unit: CompUnit, id: Int?): String? {
        val lp = unit.lineProgram ?: return null
        val idx = when {
            id == null || id <= 0 -> return null
            lp.version >= 5 -> id
            else -> id - 1
        }
        return lp.files.getOrNull(idx)?.path
    }

    /**
     * 计算 DIE 的全部范围：
     * - low_pc + high_pc(constant)  → [low, low+high)
     * - low_pc + high_pc(address)   → [low, high)
     * - 只有 low_pc                 → 零长度精确点
     * - ranges / rnglistx           → range list
     */
    fun dieRanges(die: Die, unit: CompUnit): List<AddrRange> {
        val low = die.attr(Attr.LOW_PC)
        val high = die.attr(Attr.HIGH_PC)
        val result = ArrayList<AddrRange>()
        if (low != null) {
            val lo = low.asLong()!!
            when {
                high == null -> result += AddrRange(SegAddr(0, lo), SegAddr(0, lo))
                high is AttrValue.Sconstant -> result += AddrRange(SegAddr(0, lo), SegAddr(0, lo + high.value))
                high is AttrValue.Uconstant && (die.attrForm(Attr.HIGH_PC) in CONSTANT_FORMS) ->
                    result += AddrRange(SegAddr(0, lo), SegAddr(0, lo + high.value))
                else -> result += AddrRange(SegAddr(0, lo), SegAddr(0, high.asLong()!!))
            }
        }
        val rangesAttr = die.attr(Attr.RANGES)
        if (rangesAttr != null) result += resolveRangesAttr(rangesAttr, unit, die)
        return result
    }

    private fun Die.attrForm(a: Int): Int =
        ((this.attr(a) as? AttrValue.Uconstant)?.form) ?: ((this.attr(a) as? AttrValue.SecOff)?.form ?: -1)

    private fun resolveRangesAttr(attr: AttrValue, unit: CompUnit, die: Die): List<AddrRange> {
        return when (attr) {
            is AttrValue.Uconstant -> {
                // rnglistx (DWARF5): index 进 rnglists（rangesBase 为头后偏移）
                resolveRngListX(attr.value, unit)
            }
            is AttrValue.SecOff -> {
                if (unit.version >= 5) {
                    // DW_FORM_sec_offset 指向 .debug_rnglists 绝对偏移
                    resolveRngListAt(attr.offset, unit)
                } else {
                    resolveV4List(attr.offset, unit, lowPcBase(unit, die))
                }
            }
            else -> emptyList()
        }
    }

    private fun lowPcBase(unit: CompUnit, die: Die): Long {
        // DWARF4: 无 DW_AT_ranges 的前驱 DIE 的 low_pc 作为 base；CU 根 low_pc 最常见
        var d: Die? = die
        while (d != null) {
            d.attr(Attr.LOW_PC)?.asLong()?.let { return it }
            d = d.parent
        }
        return unit.root?.attr(Attr.LOW_PC)?.asLong() ?: 0L
    }

    private fun resolveV4List(sectionOffset: Long, unit: CompUnit, base: Long): List<AddrRange> {
        // 需要 RangeListParser；这里通过 unit 的管线缓存拿到，简单起见由外部注入 provider
        val entries = v4Provider?.invoke(sectionOffset, unit.addressSize) ?: return emptyList()
        val out = ArrayList<AddrRange>()
        var curBase = base
        for (e in entries) when (e) {
            is RngV4Entry.End -> break
            is RngV4Entry.Base -> curBase = e.addr
            is RngV4Entry.Pair -> out += AddrRange(SegAddr(0, curBase + e.begin), SegAddr(0, curBase + e.end))
            is RngV4Entry.Indexed -> {
                val b = addrIndex(e.index, unit) ?: curBase
                out += AddrRange(SegAddr(0, b + e.begin), SegAddr(0, b + e.end))
            }
        }
        return out
    }

    var v4Provider: ((Long, Int) -> List<RngV4Entry>?)? = null
    var addrIndexProvider: ((Long, CompUnit) -> Long?)? = null

    private fun addrIndex(index: Long, unit: CompUnit): Long? = addrIndexProvider?.invoke(index, unit)

    private fun resolveRngListX(index: Long, unit: CompUnit): List<AddrRange> {
        val base = unit.rangesBase ?: return emptyList()
        val entrySize = if (unit.dwarf64) 8 else 4
        return rngListAtProvider?.invoke(base + index * entrySize, unit) ?: emptyList()
    }

    private fun resolveRngListAt(sectionOffset: Long, unit: CompUnit): List<AddrRange> =
        rngListAtProvider?.invoke(sectionOffset, unit) ?: emptyList()

    var rngListAtProvider: ((Long, CompUnit) -> List<AddrRange>?)? = null

    // ---- line matching ----

    fun matchLine(units: List<CompUnit>, rel: SegAddr): List<LineMatch> {
        val matches = ArrayList<LineMatch>()
        for (u in units) {
            val lp = u.lineProgram ?: continue
            for (seq in lp.sequences) {
                if (rel.segment != seq.start.segment) continue
                if (rel.offset < seq.start.offset || rel.offset >= seq.end.offset) continue
                // 序列内取“地址不超过 rel 的最后一行”（equal point 规则）
                var best: LineRow? = null
                var bestDist = Long.MAX_VALUE
                for (row in lp.rows) {
                    if (row.sequence != seq.index) continue
                    if (row.address.segment != rel.segment) continue
                    if (row.address.offset in seq.start.offset..rel.offset) {
                        val d = rel.offset - row.address.offset
                        if (d <= bestDist) { bestDist = d; best = row }
                    }
                }
                if (best != null) {
                    val idx = if (lp.version >= 5) best.fileId else best.fileId - 1
                    val path = lp.files.getOrNull(idx)?.path ?: "?"
                    matches += LineMatch(u, seq, best, path, bestDist, bestDist == 0L)
                }
            }
        }
        return matches
    }

    fun scopesAt(units: List<CompUnit>, rel: SegAddr): List<Pair<Scope, Long>> {
        val hits = ArrayList<Pair<Scope, Long>>()
        for (u in units) {
            for (s in buildScopes(u)) {
                val w = s.containingWidth(rel) ?: continue
                hits += s to w
            }
        }
        return hits
    }
}

private val CONSTANT_FORMS = setOf(
    Form.DATA1, Form.DATA2, Form.DATA4, Form.DATA8, Form.SDATA, Form.UDATA
)
