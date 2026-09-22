package compass.binfmt

import java.nio.charset.StandardCharsets

class DwarfParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * Bounded binary cursor. Every read is range-checked against [end], so a malformed
 * length field can never make the parser walk outside the section and fabricate data.
 */
class Cursor(
    val data: ByteArray,
    val start: Int = 0,
    val end: Int = data.size,
    pos: Int = start,
    val littleEndian: Boolean = true,
) {
    var pos: Int = pos
        private set

    init {
        require(start in 0..data.size && end in start..data.size) { "bad cursor bounds" }
    }

    fun available(): Int = end - pos
    fun at(p: Int): Cursor { seek(p); return this }
    fun seek(p: Int) {
        if (p < start || p > end) throw DwarfParseException("seek out of bounds: $p not in [$start,$end)")
        pos = p
    }
    fun skip(n: Long) {
        val np = pos.toLong() + n
        if (np < 0 || np > Int.MAX_VALUE) throw DwarfParseException("skip overflow")
        seek(np.toInt())
    }
    fun slice(at: Int, len: Int): Cursor {
        if (at < start || at.toLong() + len > end) {
            throw DwarfParseException("sub-slice out of bounds: off=$at len=$len sectionEnd=$end")
        }
        return Cursor(data, at, at + len, at, littleEndian)
    }

    private fun take(n: Int) {
        if (pos + n > end || pos + n < pos) throw DwarfParseException("unexpected end of data at $pos, need $n bytes, limit $end")
    }

    fun u8(): Int { take(1); return data[pos++].toInt() and 0xff }
    fun s8(): Int { take(1); return data[pos++].toInt() }
    fun u16(): Int { take(2); var v = 0; if (littleEndian) { v = (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8) } else { v = ((data[pos].toInt() and 0xff) shl 8) or (data[pos + 1].toInt() and 0xff) }; pos += 2; return v }
    fun u24(): Long {
        take(3); var v = 0L
        if (littleEndian) for (i in 0 until 3) v = v or ((data[pos + i].toLong() and 0xff) shl (8 * i))
        else for (i in 0 until 3) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        pos += 3; return v
    }
    fun u32(): Long {
        take(4); var v = 0L
        if (littleEndian) for (i in 0 until 4) v = v or ((data[pos + i].toLong() and 0xff) shl (8 * i))
        else for (i in 0 until 4) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        pos += 4; return v
    }
    fun u64(): Long {
        take(8); var v = 0L
        if (littleEndian) for (i in 0 until 8) v = v or ((data[pos + i].toLong() and 0xff) shl (8 * i))
        else for (i in 0 until 8) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        pos += 8; return v
    }
    fun bytes(n: Int): ByteArray { take(n); val out = data.copyOfRange(pos, pos + n); pos += n; return out }
    fun zstring(max: Int = 1 shl 20): String {
        val begin = pos
        while (pos < end && data[pos].toInt() != 0) {
            if (pos - begin > max) throw DwarfParseException("string too long at $begin")
            pos++
        }
        if (pos >= end) throw DwarfParseException("unterminated string at $begin")
        val s = String(data, begin, pos - begin, StandardCharsets.UTF_8)
        pos++
        return s
    }

    fun uleb128(maxBytes: Int = 16): Long {
        var result = 0L; var shift = 0; var n = 0
        while (true) {
            val b = u8(); n++
            if (n > maxBytes) throw DwarfParseException("uleb128 too long")
            result = result or ((b.toLong() and 0x7f) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw DwarfParseException("uleb128 overflow")
        }
    }
    fun sleb128(maxBytes: Int = 16): Long {
        var result = 0L; var shift = 0; var n = 0; var b = 0
        while (true) {
            b = u8(); n++
            if (n > maxBytes) throw DwarfParseException("sleb128 too long")
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }
    fun addr(bytes: Int): Long = when (bytes) {
        1 -> u8().toLong(); 2 -> u16().toLong(); 4 -> u32(); 8 -> u64()
        else -> throw DwarfParseException("unsupported address size $bytes")
    }
}
