package compass

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Bounded little/big-endian cursor over a section's raw bytes.
 *
 * Every read is checked against [limit]. A truncated or malformed structure
 * therefore raises [DwarfTruncationException] at the point of the bad read;
 * callers isolate the current compilation unit / range list / line program
 * instead of letting the cursor drift over following data.
 */
class ByteReader(
    private val data: ByteArray,
    val start: Int = 0,
    val limit: Int = data.size,
    val littleEndian: Boolean = true,
) {
    var pos: Int = start
        private set

    val remaining: Int get() = limit - pos
    val exhausted: Boolean get() = pos >= limit

    fun seek(newPos: Int) {
        if (newPos < start || newPos > limit) {
            throw DwarfTruncationException("offset ${newPos} outside [${start},${limit})")
        }
        pos = newPos
    }

    fun slice(from: Int, length: Int): ByteReader {
        if (from < start || length < 0 || from + length > limit) {
            throw DwarfTruncationException("slice [$from,+$length) outside section")
        }
        return ByteReader(data, from, from + length, littleEndian)
    }

    fun ensure(n: Int) {
        if (remaining < n) {
            throw DwarfTruncationException("need $n bytes at $pos, ${remaining} left")
        }
    }

    fun u8(): Int = ensure(1).let { data[pos++].toInt() and 0xff }

    fun u16(): Int {
        ensure(2)
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (littleEndian) (b shl 8) or a else (a shl 8) or b
    }

    fun u32(): Long {
        ensure(4)
        var v = 0L
        for (i in 0 until 4) {
            val byte = data[pos + i].toInt() and 0xff
            val shift = if (littleEndian) i * 8 else (3 - i) * 8
            v = v or (byte.toLong() shl shift)
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        ensure(8)
        val bb = ByteBuffer.wrap(data, pos, 8)
            .order(if (littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
        pos += 8
        return bb.long
    }

    fun bytes(n: Int): ByteArray {
        ensure(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun nullTerminatedString(): String {
        val begin = pos
        while (pos < limit && data[pos].toInt() != 0) pos++
        if (pos >= limit) {
            throw DwarfTruncationException("unterminated string at $begin")
        }
        val s = String(data, begin, pos - begin, Charsets.UTF_8)
        pos++ // NUL
        return s
    }

    /** ULEB128; a pathological never-terminating stream is bounded by the section end. */
    fun uleb128(): ULong {
        var result = 0UL
        var shift = 0
        var count = 0
        while (true) {
            val b = u8()
            count++
            if (count > 10 || shift >= 64 && (b and 0x7f) != 0) {
                throw DwarfFormatException("uleb128 overflow")
            }
            result = result or ((b and 0x7f).toULong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
    }

    fun sleb128(): Long {
        var result = 0L
        var shift = 0
        var b = 0
        var count = 0
        while (true) {
            b = u8()
            count++
            if (count > 10) throw DwarfFormatException("sleb128 overflow")
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && b and 0x40 != 0) {
            result = result or (-(1L shl shift))
        }
        return result
    }

    fun uint(size: Int): ULong = when (size) {
        1 -> u8().toULong()
        2 -> u16().toULong()
        4 -> u32().toULong()
        8 -> u64().toULong()
        else -> throw DwarfFormatException("bad integer width $size")
    }
}

/** DWARF 32/64-bit unit length prefix; returned alongside the section-relative end offset. */
data class UnitLength(val length: Long, val is64Bit: Boolean, val end: Int)

fun ByteReader.unitLength(): UnitLength {
    val first = u32()
    return if (first == 0xffffffffUL.toLong()) {
        val len64 = u64()
        UnitLength(len64, true, pos + len64.toIntChecked())
    } else {
        UnitLength(first, false, pos + first.toIntChecked())
    }
}

internal fun Long.toIntChecked(): Int =
    if (this < 0 || this > Int.MAX_VALUE) throw DwarfFormatException("length out of range: $this")
    else toInt()

open class DwarfFormatException(message: String) : IllegalStateException(message)
class DwarfTruncationException(message: String) : DwarfFormatException(message)
