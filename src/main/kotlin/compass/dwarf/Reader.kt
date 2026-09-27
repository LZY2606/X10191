package compass.dwarf

/** Bounded little/big-endian cursor over a byte slice. All reads are bounds-checked;
 *  violations throw [DwarfTruncated] so callers can degrade gracefully instead of
 *  producing misaligned garbage. */
class DwarfTruncated(message: String) : Exception(message)

class Reader(
    val bytes: ByteArray,
    val start: Int = 0,
    val limit: Int = bytes.size,
    val littleEndian: Boolean = true,
) {
    var pos: Int = start
        private set

    val remaining: Int get() = limit - pos
    fun exhausted() = pos >= limit

    private fun need(n: Int, what: String) {
        if (n < 0 || pos + n > limit) throw DwarfTruncated("need $n bytes for $what at 0x${pos.toString(16)}, limit 0x${limit.toString(16)}")
    }

    fun seek(newPos: Int) {
        if (newPos < start || newPos > limit) throw DwarfTruncated("seek 0x${newPos.toString(16)} outside [0x${start.toString(16)},0x${limit.toString(16)})")
        pos = newPos
    }

    fun skip(n: Int) { need(n, "skip"); pos += n }

    fun u8(what: String = "u8"): Int { need(1, what); return bytes[pos++].toInt() and 0xFF }

    fun u16(what: String = "u16"): Int {
        need(2, what)
        val b = bytes; val p = pos; pos += 2
        return if (littleEndian) (b[p].toInt() and 0xFF) or ((b[p + 1].toInt() and 0xFF) shl 8)
        else ((b[p].toInt() and 0xFF) shl 8) or (b[p + 1].toInt() and 0xFF)
    }

    fun u32(what: String = "u32"): Long {
        need(4, what)
        val b = bytes; val p = pos; pos += 4
        return if (littleEndian)
            (b[p].toLong() and 0xFF) or ((b[p + 1].toLong() and 0xFF) shl 8) or
                ((b[p + 2].toLong() and 0xFF) shl 16) or ((b[p + 3].toLong() and 0xFF) shl 24)
        else
            ((b[p].toLong() and 0xFF) shl 24) or ((b[p + 1].toLong() and 0xFF) shl 16) or
                ((b[p + 2].toLong() and 0xFF) shl 8) or (b[p + 3].toLong() and 0xFF)
    }

    fun u64(what: String = "u64"): Long {
        need(8, what)
        val hi: Long; val lo: Long
        if (littleEndian) { lo = u32(what); hi = u32(what) } else { hi = u32(what); lo = u32(what) }
        return (hi shl 32) or lo
    }

    fun uleb(what: String = "uleb"): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8(what)
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift > 70) throw DwarfTruncated("uleb128 too long for $what")
        }
    }

    fun sleb(what: String = "sleb"): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8(what)
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
            if (shift > 70) throw DwarfTruncated("sleb128 too long for $what")
        }
    }

    fun uint(size: Int, what: String = "uint"): Long = when (size) {
        1 -> u8(what).toLong()
        2 -> u16(what).toLong()
        4 -> u32(what)
        8 -> u64(what)
        else -> throw DwarfTruncated("bad uint size $size for $what")
    }

    fun cstring(what: String = "cstring"): String {
        val sb = StringBuilder()
        while (true) {
            val b = u8(what)
            if (b == 0) return sb.toString()
            sb.append(b.toChar())
        }
    }

    fun bytes(n: Int, what: String = "bytes"): ByteArray {
        need(n, what)
        val out = bytes.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    /** Reads a DWARF initial-length; returns (length, is64bit). */
    fun initialLength(what: String = "unit_length"): Pair<Long, Boolean> {
        val first = u32(what)
        if (first == 0xFFFFFFFFL) return u64(what) to true
        if (first >= 0xFFFFFFF0L) throw DwarfTruncated("reserved initial length 0x${first.toString(16)}")
        return first to false
    }
}
