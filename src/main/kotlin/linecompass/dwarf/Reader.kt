package linecompass.dwarf

import java.nio.charset.StandardCharsets

/**
 * A cursor over a single ELF/DWARF section byte array with hard bounds:
 * reads never escape the section, and every read is charged against a
 * per-section byte budget plus a per-reader jump budget. Out-of-bounds and
 * exhausted-budget conditions throw [DwarfFormatException], which callers
 * isolate per compilation unit / per header so one corrupt structure cannot
 * desynchronise parsing of other structures.
 */
class BoundedReader(
    val data: ByteArray,
    private val base: Int = 0,
    private val length: Int = data.size - base,
    private val label: String = "section",
    val addressSize: Int = 8,
    private val maxJumps: Int = 4096,
) {
    var pos: Int = base
        private set
    val end: Int = base + length
    private var jumps = 0

    init {
        require(base >= 0 && length >= 0 && end <= data.size) { "reader bounds exceed data: $label" }
    }

    val remaining: Int get() = end - pos

    fun seek(newPos: Int, counted: Boolean = true) {
        if (newPos < base || newPos > end) {
            throw DwarfFormatException("reference escapes $label bounds: offset=$newPos")
        }
        if (counted) {
            if (++jumps > maxJumps) throw DwarfFormatException("too many reference jumps in $label")
        }
        pos = newPos
    }

    fun skip(n: Int) {
        if (n < 0) throw DwarfFormatException("negative skip in $label")
        ensure(n)
        pos += n
    }

    fun ensure(n: Int) {
        if (n > remaining) throw DwarfFormatException("unexpected end of $label at $pos (need $n, have $remaining)")
    }

    fun u8(): Int {
        ensure(1)
        return data[pos++].toInt() and 0xff
    }

    fun u16(): Int {
        ensure(2)
        val v = (data[pos].toInt() and 0xff) or
            ((data[pos + 1].toInt() and 0xff) shl 8)
        pos += 2
        return v
    }

    fun u32(): Long {
        ensure(4)
        var v = 0L
        for (i in 0 until 4) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        pos += 4
        return v
    }

    fun u64(): Long {
        ensure(8)
        var v = 0L
        for (i in 0 until 8) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray {
        ensure(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    /** Reads an unsigned LEB128; capped at 16 bytes / 64 value bits. */
    fun uleb(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (++count > 16) throw DwarfFormatException("ULEB128 too long in $label at $pos")
            val b = u8()
            if (shift < 64) {
                result = result or ((b.toLong() and 0x7f) shl shift)
            } else if (b and 0x7f != 0) {
                throw DwarfFormatException("ULEB128 overflow in $label at $pos")
            }
            if (b and 0x80 == 0) break
            shift += 7
        }
        return result
    }

    /** Reads a signed LEB128; capped at 16 bytes. */
    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b = 0
        var count = 0
        while (true) {
            if (++count > 16) throw DwarfFormatException("SLEB128 too long in $label at $pos")
            b = u8()
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && b and 0x40 != 0) {
            result = result or (-1L shl shift)
        }
        return result
    }

    fun cString(): String {
        val start = pos
        while (pos < end && data[pos].toInt() != 0) pos++
        if (pos >= end) throw DwarfFormatException("unterminated string in $label at $start")
        val s = String(data, start, pos - start, StandardCharsets.UTF_8)
        pos++ // NUL
        return s
    }

    fun readBytesAt(offset: Int, n: Int): ByteArray {
        if (offset < base || n < 0 || offset + n > end) {
            throw DwarfFormatException("indirect read escapes $label bounds: offset=$offset n=$n")
        }
        return data.copyOfRange(offset, offset + n)
    }

    /** Read [n] bytes at [offset] as a NUL-terminated string without moving. */
    fun stringAt(offset: Int): String {
        if (offset < base || offset > end) throw DwarfFormatException("string ref escapes $label: $offset")
        var p = offset
        while (p < end && data[p].toInt() != 0) p++
        if (p >= end) throw DwarfFormatException("unterminated indirect string in $label at $offset")
        return String(data, offset, p - offset, StandardCharsets.UTF_8)
    }

    fun cloneAt(offset: Int, addressSize: Int = this.addressSize): BoundedReader =
        BoundedReader(data, offset, end - offset, "$label+$offset", addressSize, maxJumps)
}

class DwarfFormatException(message: String) : RuntimeException(message)

/** A CU/section initial-length pair: returns payload start, 64-bit flag and end offset. */
data class UnitLength(val is64bit: Boolean, val start: Int, val end: Int)

fun readInitialLength(r: BoundedReader): UnitLength {
    val marker = r.u32()
    return if (marker == 0xffffffffL) {
        val len = r.u64()
        if (len <= 12 || len > Int.MAX_VALUE.toLong()) {
            throw DwarfFormatException("bad 64-bit unit length $len")
        }
        val start = r.pos
        UnitLength(true, start, start + len.toInt())
    } else {
        if (marker == 0L || marker > Int.MAX_VALUE.toLong()) {
            throw DwarfFormatException("bad 32-bit unit length $marker")
        }
        val start = r.pos
        UnitLength(false, start, start + marker.toInt())
    }
}
