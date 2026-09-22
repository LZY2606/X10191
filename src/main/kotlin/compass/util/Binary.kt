package compass.util

/** Cursor-based bounded reader over a byte array (optionally a window of one section). */
class ByteReader(
    val data: ByteArray,
    val base: Int = 0,
    val length: Int = data.size - base,
    private var pos: Int = base
) {
    init {
        require(base >= 0 && length >= 0 && base + length <= data.size) { "reader window out of bounds" }
    }

    val sectionStart: Int get() = base
    val sectionEnd: Int get() = base + length
    var position: Int
        get() = pos
        set(value) {
            if (value < base || value > sectionEnd) throw ParseException("seek out of bounds: $value")
            pos = value
        }

    fun remaining(): Int = sectionEnd - pos
    fun require(n: Int) {
        if (n < 0 || pos + n > sectionEnd) {
            throw ParseException("unexpected end of data: need $n bytes at 0x${pos.toString(16)}, have ${remaining()}")
        }
    }

    fun u8(): Int {
        require(1)
        return data[pos++].toInt() and 0xff
    }

    fun i8(): Int = u8().let { if (it and 0x80 != 0) it - 256 else it }

    fun u16(littleEndian: Boolean): Int {
        require(2)
        val a = data[pos++].toInt() and 0xff
        val b = data[pos++].toInt() and 0xff
        return if (littleEndian) a or (b shl 8) else (a shl 8) or b
    }

    fun u32(littleEndian: Boolean): Long {
        require(4)
        var v = 0L
        if (littleEndian) {
            for (i in 0 until 4) v = v or ((data[pos++].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 3 downTo 0) v = v or ((data[pos++].toLong() and 0xff) shl (i * 8))
        }
        return v
    }

    fun u64(littleEndian: Boolean): Long {
        require(8)
        var v = 0L
        if (littleEndian) {
            for (i in 0 until 8) v = v or ((data[pos++].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 7 downTo 0) v = v or ((data[pos++].toLong() and 0xff) shl (i * 8))
        }
        return v
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun readNTString(limit: Int = Int.MAX_VALUE): String {
        val start = pos
        while (pos < sectionEnd && data[pos].toInt() != 0) pos++
        if (pos >= sectionEnd) throw ParseException("unterminated string at 0x${start.toString(16)}")
        val len = minOf(pos - start, limit)
        val s = String(data, start, len, Charsets.UTF_8)
        pos++ // skip NUL
        return s
    }

    fun uleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (++count > maxBytes) throw ParseException("uleb128 too long at 0x${pos.toString(16)}")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw ParseException("uleb128 overflow")
        }
    }

    fun sleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var count = 0
        var b = 0
        while (true) {
            if (++count > maxBytes) throw ParseException("sleb128 too long at 0x${pos.toString(16)}")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw ParseException("sleb128 overflow")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-(1L shl shift))
        return result
    }

    /** Reader window of [size] bytes starting at current position; cursor advances by size. */
    fun slice(size: Int): ByteReader {
        require(size)
        val child = ByteReader(data, pos, size)
        pos += size
        return child
    }

    fun viewAt(offsetInSection: Int, size: Int): ByteReader {
        val abs = base + offsetInSection
        if (offsetInSection < 0 || abs < base || size < 0 || abs + size > sectionEnd) {
            throw ParseException("sub-view out of bounds: off=$offsetInSection size=$size")
        }
        return ByteReader(data, abs, size)
    }
}

class ParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
