package compass.dwarf

import java.nio.ByteOrder

class DwarfParseException(message: String) : Exception(message)
class UnknownFormException(val form: Int) : DwarfParseException("unknown DW_FORM 0x${form.toString(16)}")

/**
 * Bounds-checked reader over one DWARF section. Every read validates against
 * [limit]; LEB128 loops are iteration-capped so corrupt data cannot spin.
 */
class Cursor(
    val buf: ByteArray,
    var pos: Int = 0,
    val limit: Int = buf.size,
    val order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
) {
    init {
        require(pos in 0..limit && limit <= buf.size) { "cursor window out of bounds" }
    }

    val remaining: Int get() = limit - pos
    fun exhausted(): Boolean = pos >= limit

    fun require(n: Int, what: String) {
        if (n < 0 || remaining < n) throw DwarfParseException("truncated $what at 0x${pos.toString(16)}")
    }

    fun u8(): Int { require(1, "u8"); return buf[pos++].toInt() and 0xFF }
    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        require(2, "u16")
        val b0 = buf[pos].toInt() and 0xFF; val b1 = buf[pos + 1].toInt() and 0xFF
        pos += 2
        return if (order == ByteOrder.LITTLE_ENDIAN) b0 or (b1 shl 8) else (b0 shl 8) or b1
    }

    fun u32(): Long {
        require(4, "u32")
        val r = if (order == ByteOrder.LITTLE_ENDIAN) {
            (buf[pos].toLong() and 0xFF) or
                ((buf[pos + 1].toLong() and 0xFF) shl 8) or
                ((buf[pos + 2].toLong() and 0xFF) shl 16) or
                ((buf[pos + 3].toLong() and 0xFF) shl 24)
        } else {
            ((buf[pos].toLong() and 0xFF) shl 24) or
                ((buf[pos + 1].toLong() and 0xFF) shl 16) or
                ((buf[pos + 2].toLong() and 0xFF) shl 8) or
                (buf[pos + 3].toLong() and 0xFF)
        }
        pos += 4
        return r
    }

    fun u64(): Long {
        require(8, "u64")
        val lo = u32(); val hi = u32()
        return if (order == ByteOrder.LITTLE_ENDIAN) lo or (hi shl 32) else (lo shl 32) or hi
    }

    fun uintN(n: Int): Long = when (n) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw DwarfParseException("unsupported int size $n")
    }

    fun uleb(): Long {
        var result = 0L; var shift = 0
        for (i in 0 until 10) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
        throw DwarfParseException("uleb128 too long at 0x${pos.toString(16)}")
    }

    fun sleb(): Long {
        var result = 0L; var shift = 0
        for (i in 0 until 10) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
        }
        throw DwarfParseException("sleb128 too long at 0x${pos.toString(16)}")
    }

    fun bytes(n: Int): ByteArray {
        require(n, "block")
        val r = buf.copyOfRange(pos, pos + n)
        pos += n
        return r
    }

    fun cstring(): String {
        var end = pos
        while (end < limit && buf[end] != 0.toByte()) end++
        val s = String(buf, pos, end - pos, Charsets.UTF_8)
        pos = (end + 1).coerceAtMost(limit)
        return s
    }

    fun skip(n: Int) { require(n, "skip"); pos += n }

    fun cloneAt(newPos: Int): Cursor {
        if (newPos < 0 || newPos > limit) throw DwarfParseException("cursor jump out of bounds: 0x${newPos.toString(16)}")
        return Cursor(buf, newPos, limit, order)
    }
}
