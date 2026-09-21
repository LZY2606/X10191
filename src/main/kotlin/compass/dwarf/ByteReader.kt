package compass.dwarf

/** Bounds-checked little-endian cursor. All reads are guarded: any overrun
 *  throws [DwarfTruncated] so a corrupt section can never silently shift the
 *  cursor and produce pseudo results. */
class DwarfTruncated(msg: String) : Exception(msg)
class DwarfBadData(msg: String) : Exception(msg)

class ByteReader(
    val bytes: ByteArray,
    pos: Int = 0,
    /** hard limit (exclusive); defaults to bytes.size */
    val limit: Int = bytes.size
) {
    var pos: Int = pos
        private set

    val remaining: Int get() = limit - pos
    fun exhausted(): Boolean = pos >= limit

    private fun need(n: Int, what: String) {
        if (n < 0 || pos + n > limit || pos + n > bytes.size)
            throw DwarfTruncated("need $n bytes for $what at 0x${pos.toString(16)}, limit 0x${limit.toString(16)}")
    }

    fun u8(what: String = "u8"): Int {
        need(1, what); return bytes[pos++].toInt() and 0xFF
    }

    fun i8(what: String = "i8"): Int = u8(what).toByte().toInt()

    fun u16(what: String = "u16"): Int {
        need(2, what)
        val v = (bytes[pos].toInt() and 0xFF) or ((bytes[pos + 1].toInt() and 0xFF) shl 8)
        pos += 2; return v
    }

    fun u32(what: String = "u32"): Long {
        need(4, what)
        var v = 0L
        for (i in 0..3) v = v or ((bytes[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 4; return v
    }

    fun u64(what: String = "u64"): Long {
        need(8, what)
        var v = 0L
        for (i in 0..7) v = v or ((bytes[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 8; return v
    }

    fun bytes(n: Int, what: String = "bytes"): ByteArray {
        need(n, what)
        val out = bytes.copyOfRange(pos, pos + n)
        pos += n; return out
    }

    fun skip(n: Int, what: String = "skip") { need(n, what); pos += n }

    /** Unsigned LEB128, at most 8 bytes (64-bit value). */
    fun uleb(what: String = "uleb"): Long {
        var result = 0L
        var shift = 0
        for (i in 0 until 10) {
            val b = u8(what)
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
        throw DwarfBadData("uleb128 too long at 0x${pos.toString(16)}")
    }

    /** Signed LEB128. */
    fun sleb(what: String = "sleb"): Long {
        var result = 0L
        var shift = 0
        for (i in 0 until 10) {
            val b = u8(what)
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
        }
        throw DwarfBadData("sleb128 too long at 0x${pos.toString(16)}")
    }

    fun cstring(what: String = "cstring"): String {
        val start = pos
        var p = pos
        while (p < limit && bytes[p].toInt() != 0) p++
        if (p >= limit) throw DwarfTruncated("unterminated $what at 0x${start.toString(16)}")
        val s = String(bytes, start, p - start, Charsets.UTF_8)
        pos = p + 1
        return s
    }

    /** 32-bit DWARF length prefix; returns (length, isDwarf64). */
    fun unitLength(what: String = "unit_length"): Pair<Long, Boolean> {
        val first = u32(what)
        if (first == 0xFFFF_FFFFL) return u64("$what(dwarf64)") to true
        if (first >= 0xFFFF_FFF0L) throw DwarfBadData("reserved $what value 0x${first.toString(16)}")
        return first to false
    }

    fun fork(pos: Int, limit: Int = this.limit): ByteReader {
        if (pos < 0 || pos > limit || limit > bytes.size)
            throw DwarfBadData("fork out of bounds: pos=0x${pos.toString(16)} limit=0x${limit.toString(16)}")
        return ByteReader(bytes, pos, limit)
    }
}
