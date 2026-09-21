package compass.dwarf

import compass.binary.ByteReader
import compass.binary.DwarfParseException

/**
 * Range-list decoding for DWARF 4 (.debug_ranges) and DWARF 5 (.debug_rnglists).
 *
 * Ranges are returned verbatim, including zero-length entries. The resolver keeps
 * zero-length ranges in the section-map view but excludes them from containment
 * matches, matching linker reality.
 */
class RangeListResolver(
    val sections: DwarfSections,
    private val addressSize: Int,
    private val is64: Boolean,
    private val warnings: MutableList<String>,
    /** DWARF 5 addrx resolution callback. */
    private val resolveAddrIndex: (Long) -> Long?,
) {
    fun dwarf4Ranges(offset: Long, cuLowPc: Long): List<AddrRange> {
        val data = sections.ranges ?: return emptyList()
        if (offset < 0 || offset >= data.size) {
            warnings.add(".debug_ranges 偏移越界 offset=$offset")
            return emptyList()
        }
        val endMark = if (addressSize == 8) -1L else 0xffffffffL
        val r = ByteReader(data, offset.toInt(), data.size)
        val out = ArrayList<AddrRange>()
        var base = cuLowPc
        var guard = 0
        while (true) {
            if (++guard > MAX_ENTRIES) throw DwarfParseException(".debug_ranges 条目过多")
            val begin = r.addr(addressSize)
            val end = r.addr(addressSize)
            if (begin == 0L && end == 0L) break
            if (begin == endMark && end == endMark) { base = cuLowPc; continue }
            if (begin == endMark) { base = end; continue }
            out += AddrRange(begin + base, end + base)
        }
        return out
    }

    private val rnglistHeader = HashMap<Long, RngListHeader>()

    private data class RngListHeader(val offsetSize: Int, val offsetArrayStart: Long)

    private fun preScanV5() {
        val data = sections.rnglists ?: return
        if (data.size < 12) return
        val r = ByteReader(data)
        // There may be multiple contributions; scan conservatively from offset 0 and
        // remember the primary header, plus record offsets lazily in resolveV5.
        try {
            val length = r.u32()
            val version = r.u16()
            if (version == 5 && length in 4 until data.size.toLong()) {
                // DWARF 5 rnglists header (DWARF32):
                // unit_length(4) version(2) address_size(1) segment_selector_size(1)
                // offset_size(1) offset_entry_count(1) [pad to 4 bytes] => data at +12
                val addrSize = r.u8()
                r.u8() // segment selector
                val offSize = r.u8().let { if (it == 8) 8 else 4 }
                val offLen = r.u8().toLong()
                r.u16() // padding to align offset table
                val offsetArrayStart = r.pos.toLong()
                rnglistHeader[0] = RngListHeader(offSize, offsetArrayStart + offLen * offSize)
            }
        } catch (_: DwarfParseException) {
            // corrupt header; individual lookups will fail closed
        }
    }

    init { preScanV5() }

    /**
     * Resolve a v5 range-list entry. [offsetOrIndex] is the raw DW_AT_ranges value;
     * [rnglistsBase] (if any) plus a [DW.FORM.rnglistx] index translates it.
     */
    fun dwarf5Ranges(rawOffset: Long, useIndex: Boolean, rnglistsBase: Long?): List<AddrRange> {
        val data = sections.rnglists ?: return emptyList()
        val header = rnglistHeader[0]
        var offset = rawOffset
        if (useIndex) {
            // index into the offset array: header start + 12 + index*offsetSize
            val offSize = header?.offsetSize ?: offsetSizeOf(is64)
            val arrayStart = if (header != null) 12L + 4L + 4L else 12L
            val pos = (arrayStart + rawOffset * offSize).toInt()
            if (pos < 0 || pos + offSize > data.size) {
                warnings.add("rnglistx 索引越界 index=$rawOffset")
                return emptyList()
            }
            val ar = ByteReader(data, pos, pos + offSize)
            offset = if (offSize == 8) ar.u64() else ar.u32()
        }
        if (offset < 0 || offset >= data.size) {
            warnings.add(".debug_rnglists 偏移越界 offset=$offset")
            return emptyList()
        }
        val r = ByteReader(data, offset.toInt(), data.size)
        val out = ArrayList<AddrRange>()
        var guard = 0
        while (true) {
            if (++guard > MAX_ENTRIES) throw DwarfParseException(".debug_rnglists 条目过多")
            val op = r.u8()
            when (op) {
                0x00 -> break
                0x01 -> out += AddrRange(r.addr(addressSize), r.addr(addressSize))
                0x02 -> {
                    val startIdx = r.uleb(); val endIdx = r.uleb()
                    val s = resolveAddrIndex(startIdx)
                    val e = resolveAddrIndex(endIdx)
                    if (s == null || e == null) {
                        warnings.add("DW_RLE_startx_endx 无法解析 .debug_addr 索引 ($startIdx,$endIdx)")
                    } else out += AddrRange(s, e)
                }
                0x03 -> {
                    val startIdx = r.uleb(); val length = r.uleb()
                    val s = resolveAddrIndex(startIdx)
                    if (s == null) warnings.add("DW_RLE_startx_length 无法解析 .debug_addr 索引 $startIdx")
                    else out += AddrRange(s, s + length)
                }
                0x04 -> {
                    val off = r.u64(); out += AddrRange(off, off + r.uleb())
                }
                0x05 -> { val off = r.u64(); out += AddrRange(off, r.u64()) }
                0x06, 0x08 -> { val start = r.addr(addressSize); val len = r.uleb(); out += AddrRange(start, start + len) }
                0x07 -> out += AddrRange(r.addr(addressSize), r.addr(addressSize))
                else -> { warnings.add("未知 rnglist 操作码 0x${op.toString(16)} offset=$offset"); break }
            }
        }
        return out
    }

    companion object {
        const val MAX_ENTRIES = 1 shl 20
        fun offsetSizeOf(is64: Boolean) = if (is64) 8 else 4
    }
}
