package compass.dwarf

import compass.Limits

/** Inclusive-exclusive address range. start == end is a legal zero-length range. */
data class AddrRange(val start: Long, val end: Long) {
    val width: Long get() = end - start
    fun contains(addr: Long): Boolean =
        if (start == end) addr == start else addr >= start && addr < end
}

/** DWARF4 .debug_ranges list at [offset]. [base] is the CU base address (usually low_pc). */
fun parseDebugRanges(
    section: ByteArray,
    offset: Int,
    addrSize: Int,
    base: Long,
    warnings: MutableList<String>,
): List<AddrRange> {
    val out = ArrayList<AddrRange>()
    if (offset < 0 || offset >= section.size) {
        warnings.add("ranges offset 0x${offset.toString(16)} outside .debug_ranges (size 0x${section.size.toString(16)})")
        return out
    }
    val r = Reader(section, offset)
    var curBase = base
    val baseMarker: Long = if (addrSize == 8) -1L else (1L shl (addrSize * 8)) - 1
    while (r.remaining() >= addrSize * 2) {
        if (out.size >= Limits.MAX_RANGES) { warnings.add("range list too long; truncated"); break }
        val a = r.addr(addrSize)
        val b = r.addr(addrSize)
        if (a == 0L && b == 0L) break
        if (a == baseMarker) { curBase = b; continue }
        out.add(AddrRange(curBase + a, curBase + b))
    }
    if (out.isEmpty() && r.remaining() < addrSize * 2)
        warnings.add("unterminated range list at 0x${offset.toString(16)}")
    return out
}

/** DWARF5 .debug_rnglists list. [offset] is the value of DW_AT_ranges (already
 *  resolved through the offset table for rnglistx). */
fun parseRnglists(
    section: ByteArray,
    offset: Int,
    addrSize: Int,
    cuBase: Long,
    resolveAddrx: (Long) -> Long?,
    warnings: MutableList<String>,
): List<AddrRange> {
    val out = ArrayList<AddrRange>()
    if (offset < 0 || offset >= section.size) {
        warnings.add("rnglists offset 0x${offset.toString(16)} outside .debug_rnglists (size 0x${section.size.toString(16)})")
        return out
    }
    val r = Reader(section, offset)
    var base = cuBase
    while (!r.eof) {
        if (out.size >= Limits.MAX_RANGES) { warnings.add("rnglist too long; truncated"); break }
        val kind = r.u8()
        when (kind) {
            0x00 -> return out // end_of_list
            0x01 -> { // base_addressx
                val idx = r.uleb()
                base = resolveAddrx(idx) ?: run {
                    warnings.add("rnglists base_addressx index $idx unresolvable"); 0L
                }
            }
            0x02 -> { // startx_endx
                val s = resolveAddrx(r.uleb()); val e = resolveAddrx(r.uleb())
                if (s != null && e != null) out.add(AddrRange(s, e))
                else warnings.add("rnglists startx_endx unresolvable")
            }
            0x03 -> { // startx_length
                val s = resolveAddrx(r.uleb()); val len = r.uleb()
                if (s != null) out.add(AddrRange(s, s + len)) else warnings.add("rnglists startx_length unresolvable")
            }
            0x04 -> { // offset_pair
                val a = r.uleb(); val b = r.uleb()
                out.add(AddrRange(base + a, base + b))
            }
            0x05 -> base = r.addr(addrSize) // base_address
            0x06 -> { val s = r.addr(addrSize); val e = r.addr(addrSize); out.add(AddrRange(s, e)) } // start_end
            0x07 -> { val s = r.addr(addrSize); val len = r.uleb(); out.add(AddrRange(s, s + len)) } // start_length
            else -> {
                warnings.add("unknown rnglists entry kind 0x${kind.toString(16)} at 0x${(r.pos - 1).toString(16)}; list truncated")
                return out
            }
        }
    }
    warnings.add("rnglists missing end_of_list terminator")
    return out
}

/** Reads the rnglists header offset table: returns the absolute offset of list [index]. */
fun rnglistsOffsetFor(
    section: ByteArray,
    index: Long,
    rnglistsBase: Long,
    warnings: MutableList<String>,
): Long? {
    if (section.isEmpty()) { warnings.add("no .debug_rnglists section"); return null }
    val r = Reader(section, 0)
    return try {
        val len0 = r.u32()
        val dwarf64 = len0 == 0xFFFF_FFFFL
        if (dwarf64) r.u64()
        val version = r.u16()
        if (version != 5) { warnings.add(".debug_rnglists version $version != 5"); return null }
        r.u8(); r.u8() // addr_size, seg_size
        val offsetEntryCount = r.u32()
        val offsetsStart = r.pos
        if (index >= offsetEntryCount && offsetEntryCount > 0) {
            warnings.add("rnglistx index $index beyond offset table ($offsetEntryCount entries)")
            return null
        }
        val entryOff = offsetsStart + (index * (if (dwarf64) 8 else 4)).toInt()
        if (entryOff >= section.size) { warnings.add("rnglistx index $index out of section"); return null }
        val rr = Reader(section, entryOff)
        val rel = rr.offset(dwarf64)
        rnglistsBase + rel
    } catch (e: DwarfException) {
        warnings.add("bad .debug_rnglists header: ${e.message}")
        null
    }
}
