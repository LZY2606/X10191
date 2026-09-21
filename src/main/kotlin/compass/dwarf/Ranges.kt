package compass.dwarf

import compass.elf.ByteReader
import compass.elf.ByteSlice
import compass.elf.ParseException

/**
 * Range resolution for both encodings:
 *  - DWARF <=4: .debug_ranges with base address / end-of-list sentinels
 *  - DWARF 5 : .debug_rnglists with base_addressx / startx / offset_pair
 * Zero-length ranges are kept (exact-match semantics).
 */
object RangeLists {

    fun readV4(
        section: ByteSlice, offset: Long, addressSize: Int,
        cuLowPc: Long, addrAt: (Long) -> Long
    ): List<PcRange> {
        if (offset < 0 || offset >= section.length) throw ParseException("ranges offset 越界")
        val r = section.reader()
        r.seek(offset.toInt())
        val out = ArrayList<PcRange>()
        var base = cuLowPc
        val baseSentinel = if (addressSize < 8) (1L shl (addressSize * 8)) - 1 else -1L
        while (true) {
            val a = r.readAddr(addressSize, "range a")
            val b = r.readAddr(addressSize, "range b")
            if (a == 0L && b == 0L) break
            if (a == baseSentinel) { base = b; continue }
            addRange(out, a, b)
            if (out.size > Limits.MAX_RANGES) throw ParseException("range 数量超上限")
        }
        return out
    }

    fun readV5(
        section: ByteSlice, rnglistsOffset: Long, index: Long?,
        addressSize: Int, dwarf64: Boolean, addrAt: (Long) -> Long
    ): List<PcRange> {
        // rnglistsOffset: value of DW_AT_rnglists_base (or CU header offset); index from rnglistx
        var listStart = rnglistsOffset
        if (index != null) {
            // DW_AT_rnglists_base (CU attr) marks first byte after header; indexes index offsets there.
            val arrayStart = rnglistsOffset
            val r = section.reader(); r.seek((arrayStart + index * 4).toInt())
            val rel = r.u32(true, "rnglist array entry")
            listStart = arrayStart + rel
        }
        return readV5List(section, listStart, addressSize, addrAt)
    }

    private fun readV5List(
        section: ByteSlice, listStart: Long, addressSize: Int, addrAt: (Long) -> Long
    ): List<PcRange> {
        if (listStart < 0 || listStart >= section.length) throw ParseException("rnglist 起始越界")
        val r = section.reader(); r.seek(listStart.toInt())
        val out = ArrayList<PcRange>()
        var base = 0L
        while (true) {
            val kind = r.u8("rle kind")
            when (kind) {
                DW_RLE_end_of_list -> break
                DW_RLE_base_addressx -> base = addrAt(Leb.uleb(r, "base addrx"))
                DW_RLE_startx_endx -> {
                    val lo = addrAt(Leb.uleb(r)); val hi = addrAt(Leb.uleb(r))
                    addRange(out, lo, hi)
                }
                DW_RLE_startx_length -> {
                    val lo = addrAt(Leb.uleb(r)); val len = Leb.uleb(r)
                    addRange(out, lo, lo + len)
                }
                DW_RLE_offset_pair -> {
                    val lo = base + Leb.uleb(r); val hi = base + Leb.uleb(r)
                    addRange(out, lo, hi)
                }
                DW_RLE_base_address -> base = r.readAddr(addressSize, "base")
                DW_RLE_start_end -> {
                    val lo = r.readAddr(addressSize); val hi = r.readAddr(addressSize)
                    addRange(out, lo, hi)
                }
                DW_RLE_start_length -> {
                    val lo = r.readAddr(addressSize); val len = Leb.uleb(r)
                    addRange(out, lo, lo + len)
                }
                else -> throw ParseException("未知 rnglist 条目 kind=0x${kind.toString(16)}, 已隔离")
            }
            if (out.size > Limits.MAX_RANGES) throw ParseException("range 数量超上限")
        }
        return out
    }

    private fun addRange(out: MutableList<PcRange>, lo: Long, hi: Long) {
        out.add(PcRange(lo, hi, zeroLength = lo == hi))
    }
}
