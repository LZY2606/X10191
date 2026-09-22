package compass.dwarf

open class DwarfParseException(message: String) : Exception(message)
class UnknownFormException(val form: Long) : DwarfParseException("unknown DWARF form 0x${form.toString(16)}")
class TruncatedException(where: String) : DwarfParseException("unexpected end of data: $where")

/** Bounds-checked little/big-endian byte cursor over a section. */
class Cursor(val data: ByteArray, var pos: Int, val end: Int, val littleEndian: Boolean = true) {
    val remaining: Int get() = end - pos

    fun require(n: Int) {
        if (n < 0 || pos + n > end) throw TruncatedException("offset $pos need $n bytes, $remaining left")
    }

    fun u8(): Int { require(1); return data[pos++].toInt() and 0xFF }
    fun i8(): Int { require(1); return data[pos++].toInt() }

    fun u16(): Int {
        require(2)
        val v = if (littleEndian)
            (data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8)
        else
            ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2
        return v
    }

    fun u24(): Int {
        require(3)
        val v = if (littleEndian)
            (data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8) or ((data[pos + 2].toInt() and 0xFF) shl 16)
        else
            ((data[pos].toInt() and 0xFF) shl 16) or ((data[pos + 1].toInt() and 0xFF) shl 8) or (data[pos + 2].toInt() and 0xFF)
        pos += 3
        return v
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        if (littleEndian) for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        else for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        pos += 4
        return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        if (littleEndian) for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        else for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray { require(n); val b = data.copyOfRange(pos, pos + n); pos += n; return b }

    fun cstring(): String {
        var p = pos
        while (p < end && data[p].toInt() != 0) p++
        if (p >= end) throw TruncatedException("unterminated string at $pos")
        val s = String(data, pos, p - pos, Charsets.UTF_8)
        pos = p + 1
        return s
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        repeat(10) {
            val b = u8()
            result = result or ((b and 0x7F).toLong() shl shift)
            if ((b and 0x80) == 0) return result
            shift += 7
        }
        throw DwarfParseException("uleb128 too long at $pos")
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        repeat(10) {
            val b = u8()
            result = result or ((b and 0x7F).toLong() shl shift)
            shift += 7
            if ((b and 0x80) == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
        }
        throw DwarfParseException("sleb128 too long at $pos")
    }

    fun addr(size: Int): Long = when (size) {
        4 -> u32()
        8 -> u64()
        else -> throw DwarfParseException("unsupported address size $size")
    }

    fun offset(dwarf64: Boolean): Long = if (dwarf64) u64() else u32()

    fun slice(n: Int): Cursor { require(n); val c = Cursor(data, pos, pos + n, littleEndian); pos += n; return c }
}

/** Unsigned-safe address comparisons (addresses kept as Long bit patterns). */
fun ule(a: Long, b: Long): Boolean = (a + Long.MIN_VALUE) <= (b + Long.MIN_VALUE)
fun ult(a: Long, b: Long): Boolean = (a + Long.MIN_VALUE) < (b + Long.MIN_VALUE)

/** addr in [begin, end); zero-length range matches only its exact point. */
fun inRange(addr: Long, begin: Long, end: Long): Boolean =
    if (begin == end) addr == begin else ule(begin, addr) && ult(addr, end)
