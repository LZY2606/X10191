package compass.dwarf

import compass.elf.ByteReader
import compass.elf.ParseException

data class UnitLength(val afterLength: Int, val length: Long, val dwarf64: Boolean, val headerStart: Int)

/** Reads a DWARF initial-length field; reader ends up positioned right after it. */
fun readUnitLength(r: ByteReader): UnitLength {
    val start = r.pos
    val w = r.u32(true, "unit_length")
    return if (w == 0xffffffffL) {
        val len64 = r.u64(true, "unit_length64")
        if (len64 !in 0..Limits.MAX_FORWARD_SKIP.toLong())
            throw ParseException("64 位 unit_length 异常: $len64")
        val after = r.pos
        if (after.toLong() + len64 > r.size) throw ParseException("unit 越过 section 结尾")
        UnitLength(after, len64, true, start)
    } else {
        if (w > Limits.MAX_FORWARD_SKIP) throw ParseException("unit_length 异常: $w")
        val after = r.pos
        if (after.toLong() + w > r.size) throw ParseException("unit 越过 section 结尾")
        UnitLength(after, w, false, start)
    }
}

fun ByteReader.u64Compat(dwarf64: Boolean, what: String = "offset"): Long =
    if (dwarf64) u64(true, what) else u32(true, what)

fun ByteReader.readAddr(size: Int, what: String = "address"): Long = when (size) {
    1 -> u8(what).toLong()
    2 -> u16(true, what).toLong()
    4 -> u32(true, what)
    8 -> u64(true, what)
    else -> throw ParseException("非法 address_size=$size")
}
