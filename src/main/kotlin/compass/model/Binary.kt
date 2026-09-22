package compass.model

import java.nio.ByteOrder

enum class ElfClass(val elfCode: Byte, val bytes: Int) {
    ELF32(1, 4), ELF64(2, 8);

    companion object {
        fun from(code: Int): ElfClass = entries.firstOrNull { it.elfCode.toInt() == code }
            ?: throw ElfParseException("unknown ELF EI_CLASS=$code")
    }
}

class BoundsException(message: String) : RuntimeException(message)
class ElfParseException(message: String) : RuntimeException(message)

/**
 * Cursor over a byte slice with hard bounds. Every read checks remaining
 * bytes first so malformed length headers can never walk outside the section.
 */
class BoundedReader(
    val data: ByteArray,
    val base: Int = 0,
    limit0: Int = data.size,
    val order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
) {
    var pos: Int = base
        private set
    var limit: Int = limit0
        set(value) {
            if (value < base || value > data.size) throw BoundsException("limit $value outside [${base},${data.size})")
            field = value
            if (pos > value) pos = value
        }

    val remaining: Int get() = limit - pos

    fun seek(newPos: Int) {
        if (newPos < base || newPos > limit) throw BoundsException("seek $newPos outside [${base},${limit})")
        pos = newPos
    }

    fun skip(n: Int) = seek(pos + n)

    fun sliceAt(offset: Int, length: Int): BoundedReader {
        if (offset < base || offset < 0 || length < 0 || offset.toLong() + length > limit.toLong())
            throw BoundsException("slice @$offset len=$length outside [${base},${limit})")
        return BoundedReader(data, offset, offset + length, order)
    }

    /** Section-relative offset slice: positions are relative to [base]. */
    fun sliceRel(relOffset: Int, length: Int): BoundedReader = sliceAt(base + relOffset, length)

    fun u8(): Int {
        if (remaining < 1) throw BoundsException("u8 past end at $pos/$limit")
        return data[pos++].toInt() and 0xff
    }

    fun u16(): Int {
        if (remaining < 2) throw BoundsException("u16 past end at $pos/$limit")
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (order == ByteOrder.LITTLE_ENDIAN) (b shl 8) or a else (a shl 8) or b
    }

    fun u32(): Long {
        if (remaining < 4) throw BoundsException("u32 past end at $pos/$limit")
        var v = 0L
        if (order == ByteOrder.LITTLE_ENDIAN) {
            for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toInt() and 0xff).toLong()
        } else {
            for (i in 0..3) v = (v shl 8) or (data[pos + i].toInt() and 0xff).toLong()
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        if (remaining < 8) throw BoundsException("u64 past end at $pos/$limit")
        var v = 0L
        if (order == ByteOrder.LITTLE_ENDIAN) {
            for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toInt() and 0xff).toLong()
        } else {
            for (i in 0..7) v = (v shl 8) or (data[pos + i].toInt() and 0xff).toLong()
        }
        pos += 8
        return v
    }

    fun uint(size: Int): Long = when (size) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> error("bad int size $size")
    }

    /** ULEB128; [maxBytes] guards corrupted streams. */
    fun uleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        while (true) {
            if (++n > maxBytes) throw BoundsException("uleb128 too long")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw BoundsException("uleb128 overflow")
        }
    }

    fun sleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        var b = 0
        while (true) {
            if (++n > maxBytes) throw BoundsException("sleb128 too long")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw BoundsException("sleb128 overflow")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun bytes(n: Int): ByteArray {
        if (n < 0 || remaining < n) throw BoundsException("bytes($n) past end at $pos/$limit")
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun nulString(maxLen: Int = 1 shl 20): String {
        val start = pos
        while (pos < limit && data[pos] != 0.toByte()) pos++
        if (pos >= limit) throw BoundsException("unterminated string starting $start")
        if (pos - start > maxLen) throw BoundsException("string too long")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun nulStringAt(absOffset: Int, maxLen: Int = 1 shl 20): String {
        if (absOffset < 0 || absOffset >= limit) throw BoundsException("string offset $absOffset oob")
        var p = absOffset
        while (p < limit && data[p] != 0.toByte()) p++
        if (p >= limit) throw BoundsException("unterminated string @$absOffset")
        if (p - absOffset > maxLen) throw BoundsException("string too long")
        return String(data, absOffset, p - absOffset, Charsets.UTF_8)
    }
}
