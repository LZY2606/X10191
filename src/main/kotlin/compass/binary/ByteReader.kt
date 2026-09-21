package compass.binary

/**
 * Bounds-safe cursor over a byte slice. All accessors throw [DwarfParseException]
 * on underflow instead of producing garbage. A corrupt section can therefore be
 * isolated to the unit that references it.
 */
class ByteReader(val data: ByteArray, val base: Int = 0, val sectionEnd: Int = data.size) {
    var pos: Int = base

    val remaining: Int get() = sectionEnd - pos

    fun seek(p: Int): ByteReader {
        if (p < base || p > sectionEnd) throw DwarfParseException("cursor out of bounds: $p not in [$base,$sectionEnd)")
        pos = p
        return this
    }

    fun require(n: Int) {
        if (n < 0 || pos + n > sectionEnd || pos + n < pos) {
            throw DwarfParseException("unexpected end of data at $pos need $n (end=$sectionEnd)")
        }
    }

    fun u8(): Int { require(1); return data[pos++].toInt() and 0xff }
    fun s8(): Int { require(1); return data[pos++].toInt() } // bytes are signed in Kotlin

    fun u16(): Int {
        require(2)
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (big) (a shl 8) or b else (b shl 8) or a
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        if (big) {
            for (i in 0 until 4) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        if (big) {
            for (i in 0 until 8) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    fun readBytes(n: Int): ByteArray {
        require(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    /** Unsigned LEB128 with a hard cap on accepted bytes. */
    fun uleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (++count > maxBytes) throw DwarfParseException("ULEB128 too long at $pos")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 63) throw DwarfParseException("ULEB128 overflow at $pos")
        }
        return result
    }

    fun sleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var count = 0
        var b = 0
        while (true) {
            if (++count > maxBytes) throw DwarfParseException("SLEB128 too long at $pos")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift > 63) throw DwarfParseException("SLEB128 overflow at $pos")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    /** NUL-terminated UTF-8 string, capped at [max] bytes. */
    fun cstring(max: Int = 1 shl 20): String {
        val start = pos
        var n = 0
        while (true) {
            if (n >= max) throw DwarfParseException("string too long at $start")
            if (pos >= sectionEnd) throw DwarfParseException("unterminated string at $start")
            if (data[pos].toInt() == 0) break
            pos++
            n++
        }
        val s = String(data, start, n, Charsets.UTF_8)
        pos++
        return s
    }

    /** Fixed-length address integer. */
    fun addr(width: Int): Long = when (width) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw DwarfParseException("bad address width $width")
    }

    fun sliceAt(offset: Int, length: Int): ByteReader {
        if (offset < 0 || length < 0 || offset + length > data.size || offset + length < offset) {
            throw DwarfParseException("slice out of bounds: offset=$offset length=${length}size=${data.size}")
        }
        return ByteReader(data, offset, offset + length).let { it.big = big; it }
    }

    var big: Boolean = false
}

class DwarfParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
