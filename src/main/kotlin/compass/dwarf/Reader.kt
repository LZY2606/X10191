package compass.dwarf

import java.nio.charset.StandardCharsets

/** Raised when a read would leave the backing bytes. Never silently truncate. */
class BoundsException(message: String) : RuntimeException(message)

/** Raised on an unknown DWARF form so the caller can isolate the whole CU. */
class UnknownFormException(val form: Long, offset: Long) :
    RuntimeException("unknown form 0x${form.toString(16)} at offset $offset")

/**
 * Bounds-checked cursor over one section's raw bytes.
 * Every read is checked against [limit]; failures throw rather than returning garbage,
 * which prevents a corrupt section from shifting the cursor and yielding fake results.
 */
class ByteReader(
    val data: ByteArray,
    val base: Int = 0,
    val limit: Int = data.size,
    private var pos: Int = base,
    var littleEndian: Boolean = true,
    var dwarf64: Boolean = false,
    /** Generic 32/64-bit address width derived from the ELF class. */
    var addressSize: Int = 8,
) {
    var bytesRead: Long = 0
        private set
    /** Hard cap for uleb/sleb loops so malformed data cannot spin forever. */
    var maxLebLength: Int = 32

    val position: Int get() = pos

    fun remaining(): Int = limit - pos

    fun seek(absoluteSectionOffset: Long): ByteReader {
        val p = base + absoluteSectionOffset.toInt()
        if (absoluteSectionOffset < 0 || p < base || p > limit) {
            throw BoundsException("seek out of bounds: $absoluteSectionOffset")
        }
        pos = p
        return this
    }

    fun sectionOffset(): Long = (pos - base).toLong()

    fun slice(length: Int): ByteReader {
        if (length < 0 || pos + length > limit) throw BoundsException("slice oob len=$length")
        val sub = ByteReader(data, pos, pos + length, pos, littleEndian, dwarf64, addressSize)
        pos += length
        return sub
    }

    fun subReader(newBase: Int, newLimit: Int): ByteReader =
        ByteReader(data, newBase, newLimit, newBase, littleEndian, dwarf64, addressSize)

    fun u8(): Int {
        if (pos + 1 > limit) throw BoundsException("u8 oob at $pos")
        return data[pos++].toInt() and 0xff
    }

    fun i8(): Int = data[pos++].toInt()

    fun u16(): Int {
        if (pos + 2 > limit) throw BoundsException("u16 oob at $pos")
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (littleEndian) (b shl 8) or a else (a shl 8) or b
    }

    fun u32(): Long {
        if (pos + 4 > limit) throw BoundsException("u32 oob at $pos")
        var v = 0L
        if (littleEndian) {
            for (i in 0..3) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        if (pos + 8 > limit) throw BoundsException("u64 oob at $pos")
        var v = 0L
        if (littleEndian) {
            for (i in 0..7) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    /** DWARF initial-length field: 32-bit size or 0xffffffff + 64-bit size. */
    fun initialLength(): Pair<Long, Boolean> {
        val first = u32()
        return if (first == 0xffffffffL) u64() to true else first to false
    }

    /** Section offset sized according to the enclosing unit (32- or 64-bit DWARF). */
    fun dwarfOffset(): Long = if (dwarf64) u64() else u32()

    fun address(): Long = when (addressSize) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw BoundsException("bad address size $addressSize")
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        var n = 0
        while (true) {
            if (++n > maxLebLength) throw BoundsException("uleb128 too long")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw BoundsException("uleb128 overflow")
        }
        bytesRead += n
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var n = 0
        var b = 0
        while (true) {
            if (++n > maxLebLength) throw BoundsException("sleb128 too long")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw BoundsException("sleb128 overflow")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        bytesRead += n
        return result
    }

    fun cString(): String {
        val start = pos
        while (pos < limit && data[pos].toInt() != 0) pos++
        if (pos >= limit) throw BoundsException("unterminated string")
        val s = String(data, start, pos - start, StandardCharsets.UTF_8)
        pos++
        return s
    }

    fun readBytes(n: Int): ByteArray {
        if (n < 0 || pos + n > limit) throw BoundsException("readBytes oob n=$n")
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun readFixedString(n: Int): String {
        val start = pos
        pos += n
        return String(data, start, n, StandardCharsets.UTF_8)
    }
}
