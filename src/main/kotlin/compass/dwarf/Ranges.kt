package compass.dwarf

/**
 * 解析 DWARF 范围列表。
 * - DWARF 4：.debug_ranges，使用 CU 地址宽度；基地址取 CU 根 DW_AT_low_pc，或 range 条目内 base address。
 * - DWARF 5 / GNU split 扩展：.debug_rnglists，头部后为操作码 + 操作数。
 */
class RangeResolver(private val view: UnitView, private val le: Boolean = true) {
    @Suppress("unused")
    private val sectionsUnused get() = view.sections
    constructor(sections: SectionSet, le: Boolean = true) : this(
        UnitView(
            skeleton = CompUnit(0, 0, 0, 0, false, 0, 0, 4, 0, null, null, null, null, null, null, null, null, emptyList(), null, null),
            splitCu = null, sections = sections, splitSections = null, missingDwo = false,
        ), le
    )

    private fun secsOf(cu: CompUnit): SectionSet = view.sectionsFor(cu)
    private fun sectionBytes(name: String, cu: CompUnit): ByteArray? =
        secsOf(cu)[name] ?: view.sections[name]


    fun dieRanges(die: Die, cu: CompUnit, view: UnitView): List<AddrRange> {
        val low = die.attr(DW_AT.LOW_PC)
        val high = die.attr(DW_AT.HIGH_PC)
        val rng = die.atVal(DW_AT.RANGES)?.let { (it.value as? AttrValue.Data)?.v?.let { off -> off to (it.form == DW_FORM.RNGLISTX) } }
        return when {
            rng != null -> readRangeList(rng.first, rng.second, cu)
            low != null -> {
                val base = resolveAddr(low, cu, view)
                when (high) {
                    null -> listOf(AddrRange(base, base, explicit = true)) // 零长度范围（low_pc 单独出现）
                    is AttrValue.Addr -> listOf(AddrRange(base, resolveAddr(high, cu, view), explicit = true))
                    is AttrValue.Data -> listOf(AddrRange(base, base + high.v, explicit = true))
                    else -> listOf(AddrRange(base, base, explicit = true))
                }
            }
            else -> emptyList()
        }
    }

    /** 将一个表示地址的属性值解析为运行期相对地址（addrX 走 .debug_addr） */
    fun resolveAddr(v: AttrValue, cu: CompUnit, view: UnitView): Long = when (v) {
        is AttrValue.Addr -> v.v
        is AttrValue.Data -> v.v
        is AttrValue.AddrIndex -> readDebugAddr(v.index, cu, view)
        else -> throw ParseException("属性不是地址: ${v::class.simpleName}")
    }

    fun readDebugAddr(index: Long, cu: CompUnit, view: UnitView): Long {
        val addrBytes = view.sections[".debug_addr"] ?: throw ParseException("缺少 .debug_addr（split CU 的 addrx 无法解析）")
        val base = cu.addrBase ?: defaultAddrBase(view, cu)
        val r = BinReader(addrBytes, (base + index * cu.addressSize).toInt(), le)
        return r.uword(cu.addressSize)
    }

    /** v5 中 CU 根无 DW_AT_addr_base 时，.debug_addr 基址可从 .debug_info 引用位置推导；这里保守取 0 */
    private fun defaultAddrBase(view: UnitView, cu: CompUnit): Long = 0L

    private fun cuLowPc(cu: CompUnit, view: UnitView): Long? {
        val low = cu.root?.attr(DW_AT.LOW_PC) ?: return null
        return runCatching { resolveAddr(low, cu, view) }.getOrNull()
    }

    private fun readRangeList(offset: Long, indexed: Boolean, cu: CompUnit, view: UnitView): List<AddrRange> {
        // v5：rnglistx => DW_AT_rnglists_base + 索引；sec_offset => 直接字节偏移
        val rnglists = view.sections[".debug_rnglists"]
        if (rnglists != null) {
            val base = cu.rnglistsBase ?: 0L
            val target = if (indexed) resolveRngIndex(rnglists, base, offset) else offset
            return readRnglists(rnglists, target, cu, view)
        }
        val v4 = view.sections[".debug_ranges"]
            ?: throw ParseException("DIE 引用 range list 但 .debug_ranges/.debug_rnglists 缺失")
        return readV4Ranges(v4, offset, cu)
    }

    /** 将 rnglistx 索引经 section 头内偏移表换算成字节偏移 */
    fun resolveRngIndex(data: ByteArray, base: Long, index: Long): Long {
        val r = BinReader(data, 0, le)
        val (dwarf64, _) = readRngHeader(r)
        // DW_AT_rnglists_base 指向偏移表之后；这里按标准从头读 offset array
        r.seek(0)
        r.u32(); if (dwarf64) r.u64()
        r.u16(); r.u8(); r.u8()
        val count = r.u32()
        val offSize = if (dwarf64) 8 else 4
        r.seek(r.pos + (index * offSize).toInt())
        return r.uword(offSize)
    }

    fun readV4Ranges(data: ByteArray, offset: Long, cu: CompUnit): List<AddrRange> {
        val r = BinReader(data, offset.toInt(), le)
        val width = cu.addressSize
        var base = cuLowPc(cu, view) ?: 0L
        val out = mutableListOf<AddrRange>()
        var guard = 0
        while (true) {
            if (++guard > 1_000_000) throw ParseException(".debug_ranges 条目过多")
            val a = r.uword(width); val b = r.uword(width)
            val maxV = if (width == 4) 0xffffffffL else -1L
            if (a == 0L && b == 0L) break
            if (a == maxV) { base = b; continue }
            out.add(AddrRange(a + base, b + base, explicit = true))
        }
        return out
    }

    fun readRnglists(data: ByteArray, listOffset: Long, cu: CompUnit): List<AddrRange> {
        // listOffset 为相对整个 section 的偏移：定位到所在 list 头部
        val hr = BinReader(data, 0, le)
        val (dwarf64, hdrLen) = readRngHeader(hr)
        val offSize = if (dwarf64) 8 else 4
        val headerEnd = hr.pos
        if (listOffset < headerEnd) throw ParseException("rnglist 偏移 0x${listOffset.toString(16)} 落在头部内")
        val r = BinReader(data, listOffset.toInt(), le)
        val width = cu.addressSize
        var base = 0L
        val out = mutableListOf<AddrRange>()
        var guard = 0
        while (true) {
            if (++guard > 1_000_000) throw ParseException(".debug_rnglists 操作码过多")
            val op = r.u8()
            when (op) {
                DW_RLE.END_OF_LIST -> break
                DW_RLE.BASE_ADDRESSX -> base = readDebugAddr(r.uleb(), cu, view)
                DW_RLE.STARTX_ENDX -> {
                    val s = readDebugAddr(r.uleb(), cu, view); val e = readDebugAddr(r.uleb(), cu, view)
                    out.add(AddrRange(s, e, explicit = true))
                }
                DW_RLE.STARTX_LENGTH -> {
                    val s = readDebugAddr(r.uleb(), cu, view); val len = r.uleb()
                    out.add(AddrRange(s, s + len, explicit = true))
                }
                DW_RLE.OFFSET_PAIR -> {
                    val a = r.uword(offSize); val b = r.uword(offSize)
                    out.add(AddrRange(base + a, base + b, explicit = true))
                }
                DW_RLE.BASE_ADDRESS -> { base = r.uword(width) }
                DW_RLE.START_END -> {
                    val s = r.uword(width); val e = r.uword(width)
                    out.add(AddrRange(s, e, explicit = true))
                }
                DW_RLE.START_LENGTH -> {
                    val s = r.uword(width); val len = r.uword(width)
                    out.add(AddrRange(s, s + len, explicit = true))
                }
                else -> throw ParseException("未知 .debug_rnglists 操作码 0x${op.toString(16)}", r.pos.toLong() - 1)
            }
        }
        return out
    }

    data class RngHeader(val dwarf64: Boolean, val headerLength: Int)
    fun readRngHeader(r: BinReader): RngHeader {
        val lenField = r.u32()
        val dwarf64 = lenField == 0xffffffffL
        val unitLen = if (dwarf64) r.u64() else lenField
        val version = r.u16()
        val addressSize = r.u8()
        val segmentSize = r.u8()
        val offsetEntryCount = r.u32()
        val offSize = if (dwarf64) 8 else 4
        r.seek(r.pos + (offsetEntryCount * offSize).toInt())
        return RngHeader(dwarf64, (unitLen + (if (dwarf64) 12 else 4)).toInt())
    }
}
