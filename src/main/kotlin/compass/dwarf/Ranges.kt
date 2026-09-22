package compass.dwarf

object RangeParser {
    /** DWARF4 .debug_ranges at [offset]. [cuLowPc] is the default base address. */
    fun parseDebugRanges(
        r0: Reader, offset: Long, addrSize: Int, cuLowPc: Long?, limits: DwarfLimits,
    ): Pair<List<RangeEntry>, List<String>> {
        val issues = mutableListOf<String>()
        if (offset < 0 || offset >= r0.size) return emptyList<RangeEntry>() to listOf("ranges offset 0x${offset.toString(16)} out of bounds")
        val r = r0.cloneAt(offset.toInt())
        val mask = if (addrSize == 8) -1L else (1L shl (addrSize * 8)) - 1
        var base = cuLowPc ?: 0L
        val out = mutableListOf<RangeEntry>()
        while (true) {
            if (out.size >= limits.maxRanges) throw DwarfException("range list too long")
            if (r.remaining() < addrSize * 2) {
                issues += "range list at 0x${offset.toString(16)} missing terminator"
                break
            }
            val begin = r.addr(addrSize)
            val end = r.addr(addrSize)
            if (begin == 0L && end == 0L) break
            if (begin == mask) { base = end; continue }
            out += RangeEntry((base + begin) and mask, (base + end) and mask)
        }
        return out to issues
    }

    /** DWARF5 .debug_rnglists. [index] selects via the header offset array when [viaIndex]. */
    fun parseRnglists(
        r0: Reader, offsetOrIndex: Long, viaIndex: Boolean, addrSize: Int,
        rnglistsBase: Long, cuLowPc: Long?, limits: DwarfLimits,
        resolveAddrx: (Long) -> Long?,
    ): Pair<List<RangeEntry>, List<String>> {
        val issues = mutableListOf<String>()
        val offset: Long
        if (viaIndex) {
            val offArrayPos = rnglistsBase + 12 + offsetOrIndex * (if (r0.dwarf64) 8 else 4)
            // header: unit_length(4/12) version(2) addrsize(1) seg(1) offset_entry_count(4) then offsets
            if (offArrayPos < 0 || offArrayPos + 4 > r0.size) {
                return emptyList<RangeEntry>() to listOf("rnglistx index $offsetOrIndex out of bounds")
            }
            val hr = r0.cloneAt(rnglistsBase.toInt())
            val len0 = hr.u32(); val d64 = len0 == 0xffffffffL
            if (d64) hr.u64()
            hr.u16(); hr.u8(); hr.u8()
            val entryCount = hr.u32()
            if (offsetOrIndex >= entryCount) return emptyList<RangeEntry>() to listOf("rnglistx index $offsetOrIndex >= offset_entry_count $entryCount")
            val arr = r0.cloneAt(hr.pos)
            arr.dwarf64 = d64
            var rel = 0L
            repeat(offsetOrIndex.toInt() + 1) { rel = arr.offset() }
            offset = rnglistsBase + rel
        } else {
            offset = rnglistsBase + offsetOrIndex
        }
        if (offset < 0 || offset >= r0.size) return emptyList<RangeEntry>() to listOf("rnglists offset 0x${offset.toString(16)} out of bounds")
        val r = r0.cloneAt(offset.toInt())
        var base = cuLowPc ?: 0L
        val out = mutableListOf<RangeEntry>()
        while (true) {
            if (out.size >= limits.maxRanges) throw DwarfException("rnglist too long")
            if (r.remaining() < 1) { issues += "rnglist missing end_of_list"; break }
            when (val kind = r.u8()) {
                Rle.END_OF_LIST -> break
                Rle.BASE_ADDRESSX -> {
                    val idx = r.uleb()
                    base = resolveAddrx(idx) ?: run { issues += "unresolved addrx $idx for rnglist base"; 0L }
                }
                Rle.STARTX_ENDX -> {
                    val s = resolveAddrx(r.uleb()); val e = resolveAddrx(r.uleb())
                    if (s != null && e != null) out += RangeEntry(s, e) else issues += "unresolved addrx in startx_endx"
                }
                Rle.STARTX_LENGTH -> {
                    val s = resolveAddrx(r.uleb()); val len = r.uleb()
                    if (s != null) out += RangeEntry(s, s + len) else issues += "unresolved addrx in startx_length"
                }
                Rle.OFFSET_PAIR -> {
                    val b = r.uleb(); val e = r.uleb()
                    out += RangeEntry(base + b, base + e)
                }
                Rle.BASE_ADDRESS -> base = r.addr(addrSize)
                Rle.START_END -> {
                    val s = r.addr(addrSize); val e = r.addr(addrSize)
                    out += RangeEntry(s, e)
                }
                Rle.START_LENGTH -> {
                    val s = r.addr(addrSize); val len = r.uleb()
                    out += RangeEntry(s, s + len)
                }
                else -> {
                    issues += "unknown rnglist entry kind $kind, list abandoned"
                    break
                }
            }
        }
        return out to issues
    }
}
