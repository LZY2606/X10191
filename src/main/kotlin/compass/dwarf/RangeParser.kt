package compass.dwarf

import compass.ByteReader

/**
 * Range lists come in two encodings:
 *  - DWARF <= 4: .debug_ranges, offset from DW_AT_ranges, terminated by (0,0);
 *    a segmented triplet variant (base-selector, start, end) is recognised when the
 *    CU root advertises a vendor DW_AT_segment marker.
 *  - DWARF 5: .debug_rnglists with DW_RLE_* entry kinds and .debug_addr indexes.
 */
object RangeParser {

    fun parseDebugRanges(
        data: ByteArray,
        offset: Long,
        addressSize: Int,
        segmented: Boolean,
        cuLowPc: Long?,
        addrReader: (Long) -> Long,
    ): List<AddressRange> {
        val r = ByteReader(data)
        r.seek(offset.toIntExact())
        var base = cuLowPc ?: 0L
        val out = ArrayList<AddressRange>()
        var entries = 0
        while (r.remaining >= if (segmented) 3 * addressSize else 2 * addressSize) {
            if (++entries > 1_000_000) throw IllegalStateException("range entry limit")
            if (segmented) {
                val sel = r.addr(addressSize)
                val start = r.addr(addressSize)
                val end = r.addr(addressSize)
                when {
                    sel == 0L && start == 0L && end == 0L -> break
                    start == maxAddr(addressSize) -> base = end // base address selector entry
                    else -> out.add(range(SegAddr(sel, rel(base, start)), SegAddr(sel, rel(base, end)),
                        RangeSource.DEBUG_RANGES))
                }
            } else {
                val start = r.addr(addressSize)
                val end = r.addr(addressSize)
                when {
                    start == 0L && end == 0L -> break
                    start == maxAddr(addressSize) -> base = end
                    else -> out.add(range(SegAddr(0, rel(base, start)), SegAddr(0, rel(base, end)),
                        RangeSource.DEBUG_RANGES))
                }
            }
        }
        return out
    }

    fun parseRnglists(
        data: ByteArray,
        listOffset: Long,
        addressSize: Int,
        addrBase: Long,
        addrReader: (Long) -> Long,
    ): List<AddressRange> {
        // listOffset is section relative (or rnglists_base + indexed offset).
        val r = ByteReader(data)
        r.seek(listOffset.toIntExact())
        var baseAddress = SegAddr(0, 0L)
        var baseIndex = 0L
        val out = ArrayList<AddressRange>()
        var entries = 0
        while (r.remaining > 0) {
            if (++entries > 1_000_000) throw IllegalStateException("rnglist entry limit")
            when (val kind = r.u8()) {
                DW.RLE_end_of_list -> break
                DW.RLE_base_addressx -> {
                    baseIndex = r.uleb(); baseAddress = SegAddr(0, addrReader(addrBase + baseIndex * addressSize))
                }
                DW.RLE_startx_endx -> {
                    val sx = r.uleb(); val ex = r.uleb()
                    out.add(range(SegAddr(0, addrReader(addrBase + sx * addressSize)),
                        SegAddr(0, addrReader(addrBase + ex * addressSize)), RangeSource.DEBUG_RNGLISTS))
                }
                DW.RLE_startx_length -> {
                    val sx = r.uleb(); val len = r.uleb()
                    val s = addrReader(addrBase + sx * addressSize)
                    out.add(range(SegAddr(0, s), SegAddr(0, s + len), RangeSource.DEBUG_RNGLISTS))
                }
                DW.RLE_offset_pair -> {
                    val so = r.uleb(); val eo = r.uleb()
                    out.add(range(SegAddr(0, baseAddress.offset + so),
                        SegAddr(0, baseAddress.offset + eo), RangeSource.DEBUG_RNGLISTS))
                }
                DW.RLE_base_address -> {
                    baseAddress = SegAddr(0, r.addr(addressSize))
                }
                DW.RLE_start_end -> {
                    val s = r.addr(addressSize); val e = r.addr(addressSize)
                    out.add(range(SegAddr(0, s), SegAddr(0, e), RangeSource.DEBUG_RNGLISTS))
                }
                DW.RLE_start_length -> {
                    val s = r.addr(addressSize); val len = r.uleb()
                    out.add(range(SegAddr(0, s), SegAddr(0, s + len), RangeSource.DEBUG_RNGLISTS))
                }
                else -> throw IllegalStateException("unknown DW_RLE 0x${kind.toString(16)} in rnglist")
            }
        }
        return out
    }

    /** Indexed access (DW_FORM_rnglistx): read the CU's rnglists offsets table. */
    fun rnglistOffset(data: ByteArray, rnglistsBase: Long, index: Long): Long {
        val r = ByteReader(data)
        r.seek((rnglistsBase + index * 4).toIntExact())
        return rnglistsBase + r.u32()
    }

    private fun rel(base: Long, v: Long): Long = if (v < base || (v ushr 63) != 0L) base + v else v

    private fun maxAddr(addressSize: Int): Long = when (addressSize) {
        8 -> -1L
        4 -> 0xffffffffL
        2 -> 0xffffL
        else -> 0xffL
    }

    private fun range(start: SegAddr, end: SegAddr, source: RangeSource) =
        AddressRange(start, end, source, end.offset == start.offset && end.segment == start.segment)

    private fun Long.toIntExact(): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw IllegalStateException("offset too large: $this")
        return toInt()
    }
}
