package compass.dwarf

/** Bounds-checked little/big endian cursor over a byte slice. */
class ByteReader(
    private val data: ByteArray,
    var pos: Int = 0,
    var end: Int = data.size,
    val littleEndian: Boolean = true,
) {
    class TruncatedException(message: String) : Exception(message)

    val remaining: Int get() = end - pos
    fun hasRemaining(): Boolean = pos < end

    fun require(n: Int) {
        if (n < 0 || pos + n > end) throw TruncatedException("need $n bytes at 0x${pos.toString(16)}, only $remaining left")
    }

    fun u8(): Int { require(1); return data[pos++].toInt() and 0xFF }

    fun u16(): Int {
        require(2)
        val v = if (littleEndian)
            (data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8)
        else
            ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2
        return v
    }

    fun u32(): Long {
        require(4)
        val b = data
        val v = if (littleEndian)
            (b[pos].toLong() and 0xFF) or ((b[pos + 1].toLong() and 0xFF) shl 8) or
                ((b[pos + 2].toLong() and 0xFF) shl 16) or ((b[pos + 3].toLong() and 0xFF) shl 24)
        else
            ((b[pos].toLong() and 0xFF) shl 24) or ((b[pos + 1].toLong() and 0xFF) shl 16) or
                ((b[pos + 2].toLong() and 0xFF) shl 8) or (b[pos + 3].toLong() and 0xFF)
        pos += 4
        return v
    }

    fun u64(): Long {
        require(8)
        val b = data
        var v = 0L
        if (littleEndian) {
            for (i in 7 downTo 0) v = (v shl 8) or (b[pos + i].toLong() and 0xFF)
        } else {
            for (i in 0 until 8) v = (v shl 8) or (b[pos + i].toLong() and 0xFF)
        }
        pos += 8
        return v
    }

    fun uN(n: Int): Long = when (n) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw TruncatedException("unsupported int size $n")
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 63) throw TruncatedException("uleb128 too long")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                break
            }
            if (shift > 63) throw TruncatedException("sleb128 too long")
        }
        return result
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun cstring(): String {
        var i = pos
        while (i < end && data[i].toInt() != 0) i++
        if (i >= end) throw TruncatedException("unterminated string at 0x${pos.toString(16)}")
        val s = String(data, pos, i - pos, Charsets.UTF_8)
        pos = i + 1
        return s
    }

    fun slice(length: Int): ByteReader {
        require(length)
        val r = ByteReader(data, pos, pos + length, littleEndian)
        pos += length
        return r
    }

    fun cloneAt(newPos: Int, newEnd: Int = end): ByteReader = ByteReader(data, newPos, newEnd, littleEndian)
}
