package compass.dwarf

/**
 * 地址范围解析：
 *  - DWARF4：DW_AT_low_pc + DW_AT_high_pc（high_pc 两种含义：地址 / 常量长度），
 *    以及 .debug_ranges（base address selection entry）。
 *  - DWARF5：.debug_rnglists（base_addressx / startx_endx / offset_pair / start_length）
 *    与 DW_FORM_rnglistx。
 * 零长度范围保留并标记 zeroLength；任何越界只产生诊断。
 */
class RangeResolver(
    private val sections: Map<String, ByteArray>,
    private val diags: MutableList<Diagnostic>,
    private val ctx: InfoParser.UnitCtx,
    private val resolver: PostResolver
) {
    fun rangesFor(die: Die?): List<AddrRange> {
        if (die == null) return emptyList()
        val out = mutableListOf<AddrRange>()

        val lowPc = die.num(DW.AT_LOW_PC)
        val highAttr = die.attr(DW.AT_HIGH_PC)
        if (lowPc != null && highAttr != null) {
            val hi = if (isAddressForm(highAttr.form)) highAttr.value as Long
            else Util.unsignedAdd(lowPc, highAttr.value as Long)
            out += AddrRange(0, lowPc, hi, "low_high_pc", Util.unsignedSub(hi, lowPc) == 0L)
        } else if (lowPc != null) {
            // 只有 low_pc：视为 [low, low) 锚点（与零长度范围同一类）
            out += AddrRange(0, lowPc, lowPc, "low_pc_only", true)
        }

        die.attr(DW.AT_RANGES)?.let { a ->
            out += when {
                a.form == DW.FORM_RNGLISTX || a.form == DW.FORM_GNU_RANGELISTX ->
                    parseRnglistByIndex((a.value as Long), die)
                ctx.version >= 5 -> parseRnglistAtOffset(a.value as Long)
                else -> parseV4Ranges(a.value as Long, lowPc ?: 0L)
            }
        }
        die.attr(DW.AT_RNGLISTS)?.let { _ ->
            // DW_AT_rnglists 是表基址，仅配合 rnglistx 使用，不直接产生范围
        }
        return out
    }

    private fun isAddressForm(form: Int) = form == DW.FORM_ADDR

    /** v4 .debug_ranges：起始 base 是 CU 的 low_pc；0/-1 哨兵处理两种大小。 */
    private fun parseV4Ranges(offset: Long, cuLowPc: Long): List<AddrRange> {
        val bytes = sections[".debug_ranges"] ?: run {
            diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "DW_AT_ranges 但缺 .debug_ranges")
            return emptyList()
        }
        val out = mutableListOf<AddrRange>()
        var base = cuLowPc
        try {
            val c = Cursor(ByteView(bytes, offset.toInt()))
            val max = ctx.addressSize
            val maxVal: Long = if (max == 4) 0xffffffffL else -1L
            while (true) {
                val a = readFixedAddr(c, max)
                val b = readFixedAddr(c, max)
                if (a == 0L && b == 0L) break
                if (a == maxVal) {
                    base = b
                    continue
                }
                val lo = Util.unsignedAdd(base, a)
                val hi = Util.unsignedAdd(base, b)
                out += AddrRange(0, lo, hi, "ranges_v4", Util.unsignedSub(hi, lo) == 0L)
            }
        } catch (e: CursorException) {
            diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", ".debug_ranges 越界 off=$offset: ${e.message}")
        }
        return out
    }

    private fun readFixedAddr(c: Cursor, size: Int): Long = when (size) {
        1 -> c.u8().toLong(); 2 -> c.u16().toLong(); 4 -> c.u32(); 8 -> c.u64()
        else -> throw CursorException("bad addr size")
    }

    private fun rnglistsHeaderOffset(cuRoot: Die): Long =
        cuRoot.num(DW.AT_RNGLISTS) ?: 0L

    /** rnglistx：在该 CU 的 rnglists 表里数第 N 个 list。 */
    private fun parseRnglistByIndex(index: Long, cuRoot: Die): List<AddrRange> {
        val bytes = sections[".debug_rnglists"] ?: run {
            diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "rnglistx 但缺 .debug_rnglists")
            return emptyList()
        }
        val header = rnglistsHeaderOffset(cuRoot).toInt()
        val listStart = try {
            val c = Cursor(ByteView(bytes, header))
            c.u16() // version
            c.u8()  // address_size
            c.u8()  // segment_selector_size
            val offCount = c.u32().toInt()
            if (index < 0 || index >= offCount) {
                diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "rnglistx 索引 $index 越界（$offCount 个）")
                return emptyList()
            }
            c.seek(12 + (index * 4).toInt())
            header + c.u32().toInt()
        } catch (e: CursorException) {
            diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "rnglists 头越界: ${e.message}")
            return emptyList()
        }
        return decodeRnglist(bytes, listStart)
    }

    private fun parseRnglistAtOffset(offset: Long): List<AddrRange> =
        decodeRnglist(sections[".debug_rnglists"] ?: run {
            diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "DW_AT_ranges 但缺 .debug_rnglists")
            return emptyList()
        }, offset.toInt())

    private fun decodeRnglist(bytes: ByteArray, start: Int): List<AddrRange> {
        val out = mutableListOf<AddrRange>()
        var base = 0L
        try {
            val c = Cursor(ByteView(bytes, start))
            loop@ while (c.remaining > 0) {
                when (val op = c.u8()) {
                    DW.RLE_END_OF_LIST -> break@loop
                    DW.RLE_BASE_ADDRESSX -> base = resolver.addrAt(c.uleb()) ?: 0L
                    0x06 -> base = readFixedAddr(c, ctx.addressSize) // RLE_base_address
                    DW.RLE_STARTX_ENDX -> {
                        val lo = resolver.addrAt(c.uleb()) ?: continue
                        val hi = resolver.addrAt(c.uleb()) ?: continue
                        out += AddrRange(0, lo, hi, "rnglists_startx", Util.width(lo, hi) == 0UL)
                    }
                    0x03 -> { // RLE_startx_length
                        val lo = resolver.addrAt(c.uleb()) ?: continue
                        val len = c.uleb()
                        val hi = Util.unsignedAdd(lo, len)
                        out += AddrRange(0, lo, hi, "rnglists_startx_len", len == 0L)
                    }
                    0x04 -> { // RLE_offset_pair
                        val lo = Util.unsignedAdd(base, c.uleb())
                        val hi = Util.unsignedAdd(base, c.uleb())
                        out += AddrRange(0, lo, hi, "rnglists_pair", Util.width(lo, hi) == 0UL)
                    }
                    0x05 -> { // RLE_start_length
                        val lo = readFixedAddr(c, ctx.addressSize)
                        val len = c.uleb()
                        val hi = Util.unsignedAdd(lo, len)
                        out += AddrRange(0, lo, hi, "rnglists_start_len", len == 0L)
                    }
                    else -> {
                        diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "rnglists 未知条目 op=$op，list 隔离")
                        break@loop
                    }
                }
            }
        } catch (e: CursorException) {
            diags += Diagnostic("ERROR", "cu:${ctx.cuIndex}", "rnglists 越界: ${e.message}")
        }
        return out
    }
}
