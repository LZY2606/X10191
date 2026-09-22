package compass.dwarf

const val MAX_RANGE_ENTRIES = 100_000

data class AddrRange(val begin: Long, val end: Long) {
    val width: Long get() = end - begin
    val zeroLength: Boolean get() = begin == end
    fun contains(addr: Long): Boolean = inRange(addr, begin, end)
}

/** DWARF4 .debug_ranges list at [offset]. [base] is the CU base address. */
fun parseDebugRanges(
    data: ByteArray,
    offset: Long,
    addrSize: Int,
    base: Long,
    littleEndian: Boolean,
    warnings: MutableList<String>,
): List<AddrRange> {
    val out = mutableListOf<AddrRange>()
    if (offset < 0 || offset >= data.size) {
        warnings += "ranges offset $offset out of bounds"
        return out
    }
    val c = Cursor(data, offset.toInt(), data.size, littleEndian)
    var curBase = base
    val allOnes = if (addrSize == 4) 0xFFFFFFFFL else -1L
    var entries = 0
    while (c.remaining >= addrSize * 2) {
        if (++entries > MAX_RANGE_ENTRIES) { warnings += "range entry limit exceeded"; break }
        val begin = c.addr(addrSize)
        val end = c.addr(addrSize)
        when {
            begin == allOnes -> curBase = end
            begin == 0L && end == 0L -> return out
            else -> out += AddrRange(curBase + begin, curBase + end)
        }
    }
    if (out.isEmpty() || entries == 0) warnings += "unterminated .debug_ranges list at $offset"
    return out
}

private data class RnglistsHeader(val addrSize: Int, val offsets: List<Long>, val listsStart: Long)

private fun readRnglistsHeader(data: ByteArray, littleEndian: Boolean): RnglistsHeader {
    val c = Cursor(data, 0, data.size, littleEndian)
    var dwarf64 = false
    var len = c.u32()
    if (len == 0xFFFFFFFFL) { dwarf64 = true; len = c.u64() }
    c.u16() // version
    val addrSize = c.u8()
    c.u8() // segment selector size
    val count = c.u32()
    val offsets = (0 until minOf(count, 1_000_000)).map { c.offset(dwarf64) }
    return RnglistsHeader(addrSize, offsets, c.pos.toLong())
}

/** DWARF5 .debug_rnglists list. [offset] is either a direct section offset
 *  (DW_FORM_sec_offset) or, when [rnglistxIndex] is set, resolved through the
 *  header offset table. */
fun parseDebugRnglists(
    data: ByteArray,
    offset: Long?,
    rnglistxIndex: Long?,
    base: Long,
    littleEndian: Boolean,
    addrTable: ByteArray?,
    addrBase: Long,
    warnings: MutableList<String>,
): List<AddrRange> {
    val out = mutableListOf<AddrRange>()
    if (data.isEmpty()) { warnings += "no .debug_rnglists section"; return out }
    val header = try {
        readRnglistsHeader(data, littleEndian)
    } catch (e: DwarfParseException) {
        warnings += "broken .debug_rnglists header: ${e.message}"; return out
    }
    val listOffset: Long = when {
        rnglistxIndex != null -> {
            val idx = rnglistxIndex.toInt()
            if (idx < 0 || idx >= header.offsets.size) {
                warnings += "rnglistx index $rnglistxIndex out of bounds"; return out
            }
            header.listsStart + header.offsets[idx]
        }
        offset != null -> offset
        else -> return out
    }
    if (listOffset < 0 || listOffset >= data.size) {
        warnings += "rnglists offset $listOffset out of bounds"
        return out
    }
    fun addrx(index: Long): Long? {
        val table = addrTable ?: run { warnings += "rnglists needs .debug_addr which is missing"; return null }
        val at = addrBase + index * header.addrSize
        if (at < 0 || at + header.addrSize > table.size) {
            warnings += ".debug_addr index $index out of bounds"; return null
        }
        return Cursor(table, at.toInt(), table.size, littleEndian).addr(header.addrSize)
    }
    val c = Cursor(data, listOffset.toInt(), data.size, littleEndian)
    var curBase = base
    var entries = 0
    while (c.remaining >= 1) {
        if (++entries > MAX_RANGE_ENTRIES) { warnings += "rnglists entry limit exceeded"; break }
        when (c.u8()) {
            0 -> return out // RLE_end_of_list
            1 -> { val i = c.uleb(); curBase = addrx(i) ?: return out } // base_addressx
            2 -> { // startx_endx
                val b = addrx(c.uleb()) ?: return out
                val e = addrx(c.uleb()) ?: return out
                out += AddrRange(b, e)
            }
            3 -> { // startx_length
                val b = addrx(c.uleb()) ?: return out
                out += AddrRange(b, b + c.uleb())
            }
            4 -> { val b = c.uleb(); val e = c.uleb(); out += AddrRange(curBase + b, curBase + e) } // offset_pair
            5 -> curBase = c.addr(header.addrSize) // base_address
            6 -> { val b = c.addr(header.addrSize); val e = c.addr(header.addrSize); out += AddrRange(b, e) } // start_end
            7 -> { val b = c.addr(header.addrSize); out += AddrRange(b, b + c.uleb()) } // start_length
            else -> { warnings += "unknown rnglists entry code"; return out }
        }
    }
    warnings += "unterminated .debug_rnglists list at $listOffset"
    return out
}
