package addresscompass.dwarf

import java.nio.charset.StandardCharsets

/** A read exceeded the bounds of a section: this path must be isolated, never silently continued. */
class SectionTruncatedException(message: String) : RuntimeException(message)

/** A value references outside the intended target section. */
class OutOfBoundsReferenceException(message: String) : RuntimeException(message)

/**
 * Bounded little/big endian reader over a section's raw bytes.
 * Every access is bounds checked; there is intentionally no way to read past [limit].
 */
class ByteReader(
    private val data: ByteArray,
    private val base: Int = 0,
    private val limit: Int = data.size,
    val endian: java.nio.ByteOrder = java.nio.ByteOrder.LITTLE_ENDIAN,
) {
    var pos: Int = base
        private set

    val remaining: Int get() = limit - pos

    fun seek(p: Int) {
        if (p < base || p > limit) throw SectionTruncatedException("seek 0x${p.toString(16)} outside section bounds [0x${base.toString(16)},0x${limit.toString(16)})")
        pos = p
    }

    fun require(n: Int) {
        if (n < 0 || pos + n > limit) {
            throw SectionTruncatedException("need $n bytes at 0x${pos.toString(16)}, section size 0x${limit.toString(16)}")
        }
    }

    fun u8(): Int {
        require(1)
        return data[pos++].toInt() and 0xff
    }

    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        require(2)
        val v = if (endian == java.nio.ByteOrder.LITTLE_ENDIAN)
            (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8)
        else
            ((data[pos].toInt() and 0xff) shl 8) or (data[pos + 1].toInt() and 0xff)
        pos += 2
        return v
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        if (endian == java.nio.ByteOrder.LITTLE_ENDIAN) {
            for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }

    fun i32(): Int = u32().toInt()

    fun u64(): Long {
        require(8)
        var v = 0L
        if (endian == java.nio.ByteOrder.LITTLE_ENDIAN) {
            for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun readNULString(maxLen: Int): String {
        val start = pos
        var end = pos
        while (end < limit && data[end].toInt() != 0) {
            end++
            if (end - start > maxLen) throw SectionTruncatedException("unterminated/overlong string at 0x${start.toString(16)}")
        }
        if (end >= limit) throw SectionTruncatedException("unterminated string at 0x${start.toString(16)}")
        val s = String(data, start, end - start, StandardCharsets.UTF_8)
        pos = end + 1
        return s
    }

    fun readBytesAt(offset: Int, n: Int): ByteArray {
        if (offset < base || offset < 0 || n < 0 || offset + n > limit) {
            throw OutOfBoundsReferenceException("read 0x${offset.toString(16)}+$n outside section [0,0x${limit.toString(16)})")
        }
        return data.copyOfRange(offset, offset + n)
    }

    fun stringAt(offset: Int, maxLen: Int = 1 shl 24): String {
        if (offset < 0 || offset >= limit) {
            throw OutOfBoundsReferenceException("string offset 0x${offset.toString(16)} outside section size 0x${limit.toString(16)}")
        }
        val end = findNul(offset, maxLen)
        return String(data, offset, end - offset, StandardCharsets.UTF_8)
    }

    private fun findNul(start: Int, maxLen: Int): Int {
        var p = start
        while (p < limit && data[p].toInt() != 0) {
            p++
            if (p - start > maxLen) throw SectionTruncatedException("overlong string at 0x${start.toString(16)}")
        }
        if (p >= limit) throw SectionTruncatedException("unterminated string at 0x${start.toString(16)}")
        return p
    }

    fun sliceReader(offset: Int, length: Int): ByteReader {
        if (offset < 0 || length < 0 || offset + length > limit) {
            throw OutOfBoundsReferenceException("slice 0x${offset.toString(16)}+0x${length.toString(16)} outside section 0x${limit.toString(16)}")
        }
        return ByteReader(data, offset, offset + length, endian)
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (++count > 16) throw SectionTruncatedException("uleb128 too long at 0x${pos.toString(16)}")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw SectionTruncatedException("uleb128 overflow at 0x${pos.toString(16)}")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        var count = 0
        do {
            if (++count > 16) throw SectionTruncatedException("sleb128 too long at 0x${pos.toString(16)}")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
        } while (b and 0x80 != 0 && shift < 64)
        if (shift < 64 && b and 0x40 != 0) {
            result = result or (-(1L shl shift))
        }
        return result
    }

    fun sizedInt(size: Int): Long = when (size) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw SectionTruncatedException("bad integer size $size")
    }

    fun absoluteOffsetInSection(): Long = (pos - base).toLong()
}
