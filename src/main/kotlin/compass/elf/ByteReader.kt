package compass.elf

/**
 * 小端/大端均可的字节游标。切片共享底层数组但带独立边界，
 * 任何越界读取都会抛出 [EndOfDataException]，解析器据此隔离损坏区域。
 */
class ByteReader(
    val data: ByteArray,
    val littleEndian: Boolean = true,
    val base: Int = 0,
    private val length: Int = data.size - base,
) {
    init {
        require(base >= 0 && length >= 0 && base + length <= data.size) {
            "slice out of bounds: base=$base length=$length data=${data.size}"
        }
    }

    var pos: Int = 0
        set(value) {
            if (value < 0 || value > length) throw EndOfDataException(
                "seek $value outside slice of length $length"
            )
            field = value
        }

    val size: Int get() = length
    fun remaining(): Int = length - pos
    fun atEnd(): Boolean = pos >= length

    fun slice(offset: Int, len: Int): ByteReader {
        if (offset < 0 || len < 0 || offset + len > length) {
            throw EndOfDataException("slice($offset,$len) out of $length")
        }
        return ByteReader(data, littleEndian, base + offset, len)
    }

    private fun need(n: Int) {
        if (n < 0 || pos + n > length || pos + n < pos) {
            throw EndOfDataException("need $n bytes at offset $pos in slice of length $length")
        }
    }

    fun peekU8(): Int {
        need(1)
        return data[base + pos].toInt() and 0xff
    }

    fun u8(): Int {
        need(1)
        val v = data[base + pos].toInt() and 0xff
        pos += 1
        return v
    }

    fun u16(): Int {
        need(2)
        val b0 = data[base + pos].toInt() and 0xff
        val b1 = data[base + pos + 1].toInt() and 0xff
        pos += 2
        return if (littleEndian) (b1 shl 8) or b0 else (b0 shl 8) or b1
    }

    fun u32(): Int {
        need(4)
        var v = 0
        if (littleEndian) {
            for (i in 0..3) v = v or ((data[base + pos + i].toInt() and 0xff) shl (i * 8))
        } else {
            for (i in 0..3) v = (v shl 8) or (data[base + pos + i].toInt() and 0xff)
        }
        pos += 4
        return v
    }

    fun u32asLong(): Long = u32().toLong() and 0xffffffffL

    fun u64(): Long {
        need(8)
        var v = 0L
        if (littleEndian) {
            for (i in 0..7) v = v or ((data[base + pos + i].toLong() and 0xffL) shl (i * 8))
        } else {
            for (i in 0..7) v = (v shl 8) or (data[base + pos + i].toLong() and 0xffL)
        }
        pos += 8
        return v
    }

    fun take(n: Int): ByteArray {
        need(n)
        val out = data.copyOfRange(base + pos, base + pos + n)
        pos += n
        return out
    }

    /** ULEB128，限制最多 [maxBytes] 字节防止损坏数据造成无限读取。 */
    fun uleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (++count > maxBytes) throw EndOfDataException("ULEB128 longer than $maxBytes bytes")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 63) throw EndOfDataException("ULEB128 overflow")
        }
        return result
    }

    /** SLEB128。 */
    fun sleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var count = 0
        var b = 0
        while (true) {
            if (++count > maxBytes) throw EndOfDataException("SLEB128 longer than $maxBytes bytes")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift > 63) throw EndOfDataException("SLEB128 overflow")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun cString(): String {
        val start = pos
        while (pos < length && data[base + pos] != 0.toByte()) pos++
        if (pos >= length) throw EndOfDataException("unterminated C string at $start")
        val s = String(data, base + start, pos - start, Charsets.UTF_8)
        pos += 1
        return s
    }

    fun cStringAt(offset: Int): String {
        if (offset < 0 || offset >= length) throw EndOfDataException("cStringAt $offset out of $length")
        pos = offset
        return cString()
    }
}

class EndOfDataException(message: String) : RuntimeException(message)
