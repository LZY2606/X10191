package compass.dwarf

data class AddrRange(val start: Long, val end: Long) {
    val width: Long get() = end - start
    fun contains(addr: Long) = addr >= start && addr < end
}

data class RangeListResult(val ranges: List<AddrRange>, val warnings: List<String>)

object RangeListParser {
    private const val MAX_ENTRIES = 1_000_000

    /** DWARF2-4 .debug_ranges list at [offset]. [cuBase] is the CU's base address (usually low_pc or 0). */
    fun parseDebugRanges(
        data: ByteArray,
        offset: Long,
        addrSize: Int,
        cuBase: Long,
        bigEndian: Boolean = false,
    ): RangeListResult {
        val warnings = mutableListOf<String>()
        if (offset < 0 || offset >= data.size) {
            return RangeListResult(emptyList(), listOf(".debug_ranges offset 0x${offset.toString(16)} out of bounds"))
        }
        val r = Reader(data, ".debug_ranges", offset.toInt(), bigEndian)
        val maxAddr = if (addrSize == 8) -1L else 0xFFFFFFFFL
        var base = cuBase
        val out = mutableListOf<AddrRange>()
        var count = 0
        while (r.remaining() >= addrSize * 2) {
            if (++count > MAX_ENTRIES) throw DwarfException(".debug_ranges: entry limit exceeded")
            val a = if (addrSize == 8) r.u64() else r.u32()
            val b = if (addrSize == 8) r.u64() else r.u32()
            if (a == 0L && b == 0L) break // end of list
            if (a == maxAddr) { base = b; continue } // base address selection
            out.add(AddrRange(base + a, base + b))
        }
        if (count > 0 && (out.isEmpty() && base == cuBase) && r.remaining() < addrSize * 2 && r.remaining() != 0)
            warnings.add(".debug_ranges truncated")
        return RangeListResult(out, warnings)
    }

    /** DWARF5 .debug_rnglists list at absolute [offset]. [addrTable] resolves addrx indices (null if .debug_addr missing). */
    fun parseRngLists(
        data: ByteArray,
        offset: Long,
        addrSize: Int,
        cuBase: Long,
        addrTable: ((Long) -> Long?)?,
        bigEndian: Boolean = false,
    ): RangeListResult {
        val warnings = mutableListOf<String>()
        if (offset < 0 || offset >= data.size) {
            return RangeListResult(emptyList(), listOf(".debug_rnglists offset 0x${offset.toString(16)} out of bounds"))
        }
        val r = Reader(data, ".debug_rnglists", offset.toInt(), bigEndian)
        var base = cuBase
        val out = mutableListOf<AddrRange>()
        var count = 0
        fun addrAt(idx: Long): Long? {
            if (addrTable == null) { warnings.add("addrx index $idx but .debug_addr missing"); return null }
            val v = addrTable(idx)
            if (v == null) warnings.add("addrx index $idx out of .debug_addr bounds")
            return v
        }
        while (!r.eof()) {
            if (++count > MAX_ENTRIES) throw DwarfException(".debug_rnglists: entry limit exceeded")
            val kind = r.u8()
            when (kind) {
                Dw.RLE_end_of_list -> break
                Dw.RLE_base_addressx -> { base = addrAt(r.uleb128()) ?: base }
                Dw.RLE_startx_endx -> {
                    val s = addrAt(r.uleb128()); val e = addrAt(r.uleb128())
                    if (s != null && e != null) out.add(AddrRange(s, e))
                }
                Dw.RLE_startx_length -> {
                    val s = addrAt(r.uleb128()); val len = r.uleb128()
                    if (s != null) out.add(AddrRange(s, s + len))
                }
                Dw.RLE_offset_pair -> {
                    val a = r.uleb128(); val b = r.uleb128()
                    out.add(AddrRange(base + a, base + b))
                }
                Dw.RLE_base_address -> base = if (addrSize == 8) r.u64() else r.u32()
                Dw.RLE_start_end -> {
                    val s = if (addrSize == 8) r.u64() else r.u32()
                    val e = if (addrSize == 8) r.u64() else r.u32()
                    out.add(AddrRange(s, e))
                }
                Dw.RLE_start_length -> {
                    val s = if (addrSize == 8) r.u64() else r.u32()
                    val len = r.uleb128()
                    out.add(AddrRange(s, s + len))
                }
                else -> {
                    warnings.add("unknown RLE kind 0x${kind.toString(16)} at 0x${(r.pos - 1).toString(16)}; list aborted")
                    break
                }
            }
        }
        return RangeListResult(out, warnings)
    }

    /** Locate a DWARF5 rnglists offset for a DW_FORM_rnglistx index, given the CU's rnglists_base. */
    fun rnglistxOffset(data: ByteArray, rnglistsBase: Long, index: Long): Long? {
        val off = rnglistsBase + index * 4
        if (off < 0 || off + 4 > data.size) return null
        val r = Reader(data, ".debug_rnglists", off.toInt())
        return rnglistsBase + r.u32()
    }
}
