package compass.elf

/**
 * Bounded little/big-endian cursor over a byte slice. Every read is bounds-checked;
 * running past the slice throws [SliceOutOfBoundsException] instead of silently
 * producing garbage (which would corrupt later parse results).
 */
class Cursor(
    val bytes: ByteArray,
    val base: Int = 0,
    val size: Int = bytes.size - base,
    private val littleEndian: Boolean = true,
    offset0: Int = 0,
) {
    var offset: Int = offset0
        private set

    init {
        require(base >= 0 && size >= 0 && base + size <= bytes.size) { "cursor slice out of bytes" }
        require(offset0 in 0..size)
    }

    val remaining: Int get() = size - offset

    fun seek(pos: Int): Cursor {
        if (pos < 0 || pos > size) throw SliceOutOfBoundsException("seek $pos in slice of $size")
        offset = pos
        return this
    }

    fun skip(n: Int): Cursor = seek(offset + n)

    fun slice(length: Int): Cursor {
        if (length < 0 || offset + length > size) {
            throw SliceOutOfBoundsException("slice($length) at $offset, remaining $remaining")
        }
        val child = Cursor(bytes, base + offset, length, littleEndian)
        offset += length
        return child
    }

    fun forkAt(absOffset: Int, length: Int): Cursor {
        if (absOffset < 0 || length < 0 || absOffset + length > size) {
            throw SliceOutOfBoundsException("forkAt($absOffset,$length) out of $size")
        }
        return Cursor(bytes, base + absOffset, length, littleEndian)
    }

    fun u8(): Int {
        if (offset + 1 > size) throw SliceOutOfBoundsException("u8 at $offset/$size")
        return bytes[base + offset++].toInt() and 0xFF
    }

    fun bytes(n: Int): ByteArray {
        if (n < 0 || offset + n > size) throw SliceOutOfBoundsException("bytes($n) at $offset/$size")
        val out = bytes.copyOfRange(base + offset, base + offset + n)
        offset += n
        return out
    }

    fun u16(): Int {
        if (offset + 2 > size) throw SliceOutOfBoundsException("u16 at $offset/$size")
        val p = base + offset
        offset += 2
        return if (littleEndian) {
            (bytes[p].toInt() and 0xFF) or ((bytes[p + 1].toInt() and 0xFF) shl 8)
        } else {
            ((bytes[p].toInt() and 0xFF) shl 8) or (bytes[p + 1].toInt() and 0xFF)
        }
    }

    fun u32(): Long {
        if (offset + 4 > size) throw SliceOutOfBoundsException("u32 at $offset/$size")
        val p = base + offset
        offset += 4
        var v = 0L
        if (littleEndian) {
            for (i in 3 downTo 0) v = (v shl 8) or (bytes[p + i].toLong() and 0xFF)
        } else {
            for (i in 0..3) v = (v shl 8) or (bytes[p + i].toLong() and 0xFF)
        }
        return v
    }

    fun u64(): ULong {
        if (offset + 8 > size) throw SliceOutOfBoundsException("u64 at $offset/$size")
        val p = base + offset
        offset += 8
        var v = 0UL
        if (littleEndian) {
            for (i in 7 downTo 0) v = (v shl 8) or (bytes[p + i].toULong() and 0xFFUL)
        } else {
            for (i in 0..7) v = (v shl 8) or (bytes[p + i].toULong() and 0xFFUL)
        }
        return v
    }

    fun zeroString(): String {
        val start = base + offset
        var p = start
        val end = base + size
        while (p < end && bytes[p].toInt() != 0) p++
        if (p >= end) throw SliceOutOfBoundsException("unterminated string")
        val s = String(bytes, start, p - start, Charsets.UTF_8)
        offset += (p - start) + 1
        return s
    }

    fun lenUleb(): Int {
        var result = 0
        var shift = 0
        var n = 0
        while (true) {
            if (offset + n >= size) throw SliceOutOfBoundsException("uleb past end")
            val b = bytes[base + offset + n].toInt()
            n++
            result = result or ((b and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 63) throw SliceOutOfBoundsException("uleb too large")
        }
        offset += n
        return result
    }

    fun lenSleb(): Int {
        var result = 0
        var shift = 0
        var n = 0
        while (true) {
            if (offset + n >= size) throw SliceOutOfBoundsException("sleb past end")
            val b = bytes[base + offset + n].toInt()
            n++
            result = result or ((b and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (b and 0x40 != 0) result = result or (-1 shl shift)
                break
            }
            if (shift > 63) throw SliceOutOfBoundsException("sleb too large")
        }
        offset += n
        return result
    }
}

class SliceOutOfBoundsException(message: String) : RuntimeException(message)

fun Cursor.uleb128(): ULong {
    var result = 0UL
    var shift = 0
    while (true) {
        val b = u8().toULong()
        result = result or ((b and 0x7FUL) shl shift)
        if (b and 0x80UL == 0UL) return result
        shift += 7
        if (shift > 63) throw SliceOutOfBoundsException("uleb128 overflow")
    }
}

fun Cursor.sleb128(): Long {
    var result = 0L
    var shift = 0
    while (true) {
        val b = u8()
        result = result or ((b and 0x7F).toLong() shl shift)
        shift += 7
        if (b and 0x80 == 0) {
            if (b and 0x40 != 0) result = result or (-1L shl shift)
            return result
        }
        if (shift > 63) throw SliceOutOfBoundsException("sleb128 overflow")
    }
}
