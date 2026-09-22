package compass.core

/** All parsing failures are reported with this exception so a broken section can be isolated. */
class DwarfException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/** Bounds-checked little/big endian reader over a byte array. */
class Reader(val data: ByteArray, var pos: Int = 0, val littleEndian: Boolean = true) {
    val length: Int get() = data.size

    fun remaining(): Int = data.size - pos

    fun seek(p: Int): Reader {
        if (p < 0 || p > data.size) throw DwarfException("seek out of bounds: $p (size=${data.size})")
        pos = p
        return this
    }

    fun slice(start: Int, len: Int): ByteArray {
        if (start < 0 || len < 0 || start.toLong() + len > data.size)
            throw DwarfException("slice out of bounds: start=$start len=$len size=${data.size}")
        return data.copyOfRange(start, start + len)
    }

    fun need(n: Int) {
        if (n < 0 || pos < 0 || pos.toLong() + n > data.size)
            throw DwarfException("read out of bounds: pos=$pos need=$n size=${data.size}")
    }

    fun u8(): Int {
        need(1)
        return data[pos++].toInt() and 0xff
    }

    fun u16(): Int {
        need(2)
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (littleEndian) (b shl 8) or a else (a shl 8) or b
    }

    fun u32(): Long {
        need(4)
        var v = 0L
        if (littleEndian) {
            for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        need(8)
        var v = 0L
        if (littleEndian) {
            for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray {
        val out = slice(pos, n)
        pos += n
        return out
    }

    fun cstr(): String {
        val start = pos
        var end = start
        while (end < data.size && data[end].toInt() != 0) end++
        if (end >= data.size) throw DwarfException("unterminated C string at $start")
        val s = String(data, start, end - start, Charsets.UTF_8)
        pos = end + 1
        return s
    }

    fun cstrAt(offset: Long): String {
        val o = offset.toIntExact()
        if (o < 0 || o > data.size) throw DwarfException("cstr offset out of bounds: $offset")
        var end = o
        while (end < data.size && data[end].toInt() != 0) end++
        if (end >= data.size) throw DwarfException("unterminated C string at $o")
        return String(data, o, end - o, Charsets.UTF_8)
    }

    fun uleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        while (true) {
            if (++n > maxBytes) throw DwarfException("ULEB128 too long at $pos")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw DwarfException("ULEB128 overflow at $pos")
        }
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b = 0
        var n = 0
        while (true) {
            if (++n > 16) throw DwarfException("SLEB128 too long at $pos")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun address(sizeBytes: Int): Long = when (sizeBytes) {
        1 -> u8().toLong()
        2 -> u16().toLong() and 0xffff
        4 -> u32()
        8 -> u64()
        else -> throw DwarfException("unsupported address size $sizeBytes")
    }
}

fun Long.toIntExact(): Int {
    if (this < Int.MIN_VALUE || this > 0xffffffffL) throw DwarfException("value does not fit int: $this")
    return toInt()
}

fun Long.toUintInt(): Int {
    if (this < 0 || this > 0xffffffffL) throw DwarfException("unsigned 32-bit expected: $this")
    return toInt()
}
