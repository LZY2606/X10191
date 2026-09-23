package compass.elf

import java.nio.charset.StandardCharsets

/**
 * Bounds-checked cursor over a little/big endian byte buffer.
 *
 * Every read validates [pos]+size <= size; an out-of-bounds read throws
 * [ByteReaderException] instead of silently producing bogus data. The parser
 * treats that as a hard stop for the containing unit so a corrupt section can
 * never desynchronize the cursor into neighboring entries.
 */
class ByteReader(
    val data: ByteArray,
    var pos: Int = 0,
    val endian: Endian = Endian.LITTLE,
    val base: Int = 0,
) {
    enum class Endian { LITTLE, BIG }

    constructor(
        data: ByteArray,
        offset: Int,
        length: Int,
        endian: Endian,
        base: Int = offset,
    ) : this(data, offset, endian, base) {
        this.end = offset + length
        checkBounds(offset, length)
    }

    private var end: Int = data.size

    class ByteReaderException(message: String) : RuntimeException(message)

    val remaining: Int get() = end - pos

    fun seek(p: Int) {
        if (p < base || p > end) throw ByteReaderException("seek $p outside [${base},${end})")
        pos = p
    }

    fun relative(delta: Int) = seek(pos + delta)

    fun slice(offset: Int, length: Int): ByteReader {
        checkBounds(offset, length)
        return ByteReader(data, offset, endian, offset).also { it.end = offset + length }
    }

    private fun checkBounds(offset: Int, length: Int) {
        if (offset < base || offset < 0 || length < 0 || offset.toLong() + length > end.toLong() ||
            offset + length > data.size
        ) {
            throw ByteReaderException(
                "read of $length byte(s) at $offset outside region [${base},${end}) (file ${data.size})"
            )
        }
    }

    fun u1(): Int {
        checkBounds(pos, 1)
        return data[pos].toInt() and 0xff
    }

    fun i1(): Int = u1().let { if (it and 0x80 != 0) it - 256 else it }

    fun u2(): Int {
        checkBounds(pos, 2)
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (endian == Endian.LITTLE) (b shl 8) or a else (a shl 8) or b
    }

    fun u4(): Long {
        checkBounds(pos, 4)
        var v = 0L
        if (endian == Endian.LITTLE) {
            for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }

    fun i4(): Int {
        val v = u4()
        return (v and 0xffffffffL).toInt()
    }

    fun u8(): Long {
        checkBounds(pos, 8)
        var v = 0L
        if (endian == Endian.LITTLE) {
            for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray {
        checkBounds(pos, n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun skip(n: Int) {
        checkBounds(pos, n)
        pos += n
    }

    fun align8() {
        val a = pos and 7
        if (a != 0) skip(8 - a)
    }

    /** NUL terminated C string; DWARF strings never contain embedded NULs. */
    fun cstring(offset: Int = pos): String {
        var p = offset
        if (p < base || p >= end) throw ByteReaderException("cstring at $p outside region")
        while (p < end && data[p].toInt() != 0) p++
        if (p >= end) throw ByteReaderException("unterminated string at $offset")
        val s = String(data, offset, p - offset, StandardCharsets.UTF_8)
        pos = p + 1
        return s
    }

    /** Unsigned LEB128 with [maxBytes] guard against corrupt data. */
    fun uleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        while (true) {
            val b = u1()
            n++
            if (n > maxBytes) throw ByteReaderException("ULEB128 longer than $maxBytes bytes")
            result = result or ((b.toLong() and 0x7f) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw ByteReaderException("ULEB128 overflow")
        }
    }

    fun ulebInt(maxBytes: Int = 16): Int = uleb(maxBytes).let {
        if (it < 0 || it > Int.MAX_VALUE.toLong()) throw ByteReaderException("ULEB128 not an int: $it")
        it.toInt()
    }

    fun sleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        var b = 0
        while (true) {
            b = u1()
            n++
            if (n > maxBytes) throw ByteReaderException("SLEB128 longer than $maxBytes bytes")
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw ByteReaderException("SLEB128 overflow")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }
}
