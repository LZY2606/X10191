package compass.dwarf

/** Bounds-checked cursor over a single DWARF section's bytes. */
class DwarfCursor(val data: ByteArray, var pos: Int = 0) {
    val size: Int get() = data.size

    fun atEnd(): Boolean = pos >= data.size

    fun seek(off: Long) {
        if (off < 0 || off > data.size) {
            throw DwarfParseException("seek out of bounds: $off (size=${data.size})")
        }
        pos = off.toInt()
    }

    fun require(n: Int) {
        if (n < 0 || pos < 0 || pos > data.size - n) {
            throw DwarfParseException("read out of bounds: pos=$pos need=$n size=${data.size}")
        }
    }

    fun u8(): Int { require(1); return data[pos++].toInt() and 0xff }
    fun u16(): Int { require(2); val v = (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8); pos += 2; return v }
    fun u32(): Long { require(4); var v = 0L; for (i in 0 until 3) v = v or ((data[pos + i].toLong() and 0xff) shl (8 * i)); v = v or ((data[pos + 3].toLong() and 0xff) shl 24); pos += 4; return v }
    fun u64(): Long { require(8); var v = 0L; for (i in 0 until 7) v = v or ((data[pos + i].toLong() and 0xff) shl (8 * i)); v = v or (data[pos + 7].toLong() shl 56); pos += 8; return v }

    fun uleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        while (true) {
            if (++n > maxBytes) throw DwarfParseException("ULEB128 exceeds $maxBytes bytes")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw DwarfParseException("ULEB128 too long")
        }
        return result
    }

    fun sleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        var b = 0
        while (true) {
            if (++n > maxBytes) throw DwarfParseException("SLEB128 exceeds $maxBytes bytes")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw DwarfParseException("SLEB128 too long")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun bytes(n: Int): ByteArray { require(n); val out = data.copyOfRange(pos, pos + n); pos += n; return out }
    fun fixed(kind: Int): Long = when (kind) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw DwarfParseException("bad fixed width $kind")
    }

    fun cstring(): String {
        val start = pos
        while (pos < data.size && data[pos].toInt() != 0) pos++
        if (pos >= data.size) throw DwarfParseException("unterminated cstring at $start")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++ // NUL
        return s
    }
}

class DwarfParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
