package compass.util

/**
 * Bounded cursor over one debug section. Every read is range-checked; callers never receive
 * a silently-truncated value, which keeps the cursor aligned even when trailing bytes are junk.
 */
class ByteReader(val data: ByteArray, var pos: Int = 0, val start: Int = 0, val end: Int = data.size) {

    init {
        require(start in 0..end && end <= data.size) { "bad reader window" }
        if (pos == 0 && start != 0) pos = start
    }

    fun remaining(): Int = end - pos
    fun eof(): Boolean = pos >= end
    fun seek(p: Int) {
        if (p < start || p > end) throw ParseException("seek out of bounds: $p not in [$start,$end)")
        pos = p
    }

    fun require(n: Int) {
        if (n < 0 || pos > end - n) throw ParseException("unexpected end of section at $pos, need $n, have ${end - pos}")
    }

    fun u8(): Int { require(1); return data[pos++].toInt() and 0xff }
    fun s8(): Int { require(1); return data[pos++].toInt() }

    fun u16(): Int {
        require(2)
        val v = (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8)
        pos += 2
        return v
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        for (i in 0..3) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        pos += 4
        return v
    }

    fun u32u(): U64 = U64(u32())

    fun u64(): U64 {
        require(8)
        var v = 0L
        for (i in 0..7) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        pos += 8
        return U64(v)
    }

    fun bytes(n: Int): ByteArray {
        if (n < 0) throw ParseException("negative length $n")
        if (n > Limits.MAX_BLOCK_BYTES) throw ParseException("block length $n exceeds cap")
        require(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun cstring(): String {
        var p = pos
        while (p < end && data[p].toInt() != 0) p++
        if (p >= end) throw ParseException("unterminated string at $pos")
        val s = String(data, pos, p - pos, Charsets.UTF_8)
        pos = p + 1
        return s
    }

    fun cstringOrNull(): String? = if (eof()) null else cstring()

    fun uleb128(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            val b = u8()
            count++
            if (count > Limits.MAX_LEB128_BYTES) throw ParseException("ULEB128 too long")
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw ParseException("ULEB128 overflow")
        }
    }

    fun sleb128(): Long {
        var result = 0L
        var shift = 0
        var b = 0
        var count = 0
        while (true) {
            b = u8()
            count++
            if (count > Limits.MAX_LEB128_BYTES) throw ParseException("SLEB128 too long")
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw ParseException("SLEB128 overflow")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    /** ULEB as unsigned 64-bit (result already sign-extends naturally in two's complement). */
    fun ulebU(): U64 = U64(uleb128())

    fun snapshot(): Int = pos
    fun rollback(p: Int) { pos = p }
}

class ParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
