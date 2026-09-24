package compass.dwarf

data class AddrRange(val begin: Long, val end: Long) {
    val width: Long get() = end - begin
    val zeroLength: Boolean get() = begin == end
    fun contains(addr: Long): Boolean =
        if (zeroLength) addr == begin else addr >= begin && addr < end
}

object RangeLists {
    const val MAX_ENTRIES = 1_000_000

    private fun maskFor(addrSize: Int): Long =
        if (addrSize >= 8) -1L else (1L shl (addrSize * 8)) - 1L

    /** DWARF4-style .debug_ranges at [offset]. */
    fun parseRanges(
        section: ByteArray,
        offset: Long,
        addrSize: Int,
        littleEndian: Boolean = true,
        diagnostics: MutableList<String> = mutableListOf()
    ): List<AddrRange> {
        if (offset < 0 || offset >= section.size) {
            diagnostics.add("ranges offset $offset out of bounds (.debug_ranges size ${section.size})")
            return emptyList()
        }
        val r = Reader(section, offset.toInt(), section.size, littleEndian)
        val out = ArrayList<AddrRange>()
        var base = 0L
        val mask = maskFor(addrSize)
        while (r.remaining() >= addrSize * 2) {
            if (out.size >= MAX_ENTRIES) throw LimitExceededException("too many range entries")
            val a = if (addrSize == 8) r.u64() else r.u32()
            val b = if (addrSize == 8) r.u64() else r.u32()
            if (a == 0L && b == 0L) break
            if (a == mask) {
                base = b
                continue
            }
            out.add(AddrRange((base + a) and mask, (base + b) and mask))
        }
        return out
    }

    /** DWARF5 .debug_rnglists. [offset] is a section offset (already resolved from rnglistx). */
    fun parseRnglists(
        section: ByteArray,
        offset: Long,
        defaultAddrSize: Int,
        littleEndian: Boolean = true,
        addrResolver: (Long) -> Long?,
        diagnostics: MutableList<String> = mutableListOf(),
        initialBase: Long = 0
    ): List<AddrRange> {
        if (offset < 0 || offset >= section.size) {
            diagnostics.add("rnglists offset $offset out of bounds (.debug_rnglists size ${section.size})")
            return emptyList()
        }
        val r = Reader(section, offset.toInt(), section.size, littleEndian)
        val out = ArrayList<AddrRange>()
        var base = initialBase
        var addrSize = defaultAddrSize
        while (r.remaining() > 0) {
            if (out.size >= MAX_ENTRIES) throw LimitExceededException("too many rnglist entries")
            val kind = r.u8()
            when (kind) {
                Dw.RLE_end_of_list -> break
                Dw.RLE_base_addressx -> {
                    val idx = r.uleb()
                    val v = addrResolver(idx)
                    if (v == null) diagnostics.add("addrx $idx unresolvable for base_addressx") else base = v
                }
                Dw.RLE_startx_endx -> {
                    val s = addrResolver(r.uleb())
                    val e = addrResolver(r.uleb())
                    if (s == null || e == null) diagnostics.add("addrx unresolvable for startx_endx")
                    else out.add(AddrRange(s, e))
                }
                Dw.RLE_startx_length -> {
                    val s = addrResolver(r.uleb())
                    val len = r.uleb()
                    if (s == null) diagnostics.add("addrx unresolvable for startx_length")
                    else out.add(AddrRange(s, s + len))
                }
                Dw.RLE_offset_pair -> {
                    val b = r.uleb()
                    val e = r.uleb()
                    out.add(AddrRange(base + b, base + e))
                }
                Dw.RLE_base_address -> {
                    base = if (addrSize == 8) r.u64() else r.u32()
                }
                Dw.RLE_start_end -> {
                    val s = if (addrSize == 8) r.u64() else r.u32()
                    val e = if (addrSize == 8) r.u64() else r.u32()
                    out.add(AddrRange(s, e))
                }
                Dw.RLE_start_length -> {
                    val s = if (addrSize == 8) r.u64() else r.u32()
                    val len = r.uleb()
                    out.add(AddrRange(s, s + len))
                }
                else -> {
                    diagnostics.add("unknown RLE kind $kind at rnglists offset ${r.pos - 1}; stopping list")
                    break
                }
            }
        }
        return out
    }

    /** Resolve the offset of a rnglists contribution for a DW_AT_ranges value. */
    fun rnglistOffset(
        section: ByteArray,
        value: AttrValue,
        rnglistsBase: Long,
        littleEndian: Boolean = true,
        diagnostics: MutableList<String> = mutableListOf()
    ): Long? {
        return when (value) {
            is AttrValue.SecOffset -> value.v
            is AttrValue.UInt -> value.v
            is AttrValue.Rnglistx -> {
                // offsets table lives right after the 12-byte header at rnglistsBase
                val tablePos = rnglistsBase + 12
                if (tablePos < 0 || tablePos + 4 > section.size) {
                    diagnostics.add("rnglists offsets table out of bounds at $tablePos")
                    return null
                }
                val r = Reader(section, tablePos.toInt(), section.size, littleEndian)
                r.skip(value.index * 4)
                rnglistsBase + r.u32()
            }
            else -> null
        }
    }
}
