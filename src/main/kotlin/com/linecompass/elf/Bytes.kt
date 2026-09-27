package com.linecompass.elf

import java.nio.charset.StandardCharsets

/** Thrown when section data is structurally broken; [trustworthy] keeps parsed-but-uncertain parts apart. */
class DwarfParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/** An unknown DWARF form was encountered. The CU is isolated, but the cursor is not allowed to desync. */
class UnsupportedFormException(val form: Int) : RuntimeException("unsupported DW_FORM 0x${form.toString(16)}")

/**
 * Bounded cursor over a single section's raw bytes.
 *
 * Limits enforced here (recursion / length / reference jumps) are the parser's safety rails:
 * a corrupt section must never make the cursor wander into neighbouring data and invent rows.
 */
class Bytes(val data: ByteArray, val name: String = "") {
    var pos: Int = 0
    var end: Int = data.size

    /** Bitness of the enclosing unit: false = 32-bit DWARF, true = 64-bit DWARF. */
    var dwarf64: Boolean = false

    fun remaining(): Int = end - pos
    fun eof(): Boolean = pos >= end
    fun require(count: Int, what: String = "read") {
        if (pos < 0 || pos + count > end) {
            throw DwarfParseException("$name: unexpected end of data at offset 0x${pos.toString(16)} while $what (need $count, have ${end - pos})")
        }
    }

    fun u8(): Int {
        require(1); val v = data[pos].toInt() and 0xff; pos++; return v
    }

    fun i8(): Int {
        require(1); val v = data[pos].toInt(); pos++; return v
    }

    fun u16(): Int {
        require(2)
        val v = (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8)
        pos += 2; return v
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        for (i in 0 until 4) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        pos += 4; return v
    }

    fun i32(): Int {
        require(4)
        var v = 0
        for (i in 0 until 4) v = v or ((data[pos + i].toInt() and 0xff) shl (i * 8))
        pos += 4; return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        for (i in 0 until 7) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        v = v or ((data[pos + 7].toLong()) shl 56)
        pos += 8; return v
    }

    fun bytes(n: Int): ByteArray {
        require(n, "reading $n bytes")
        val out = data.copyOfRange(pos, pos + n); pos += n; return out
    }

    fun skip(n: Long, what: String = "skipping") {
        if (n < 0 || n > remaining()) throw DwarfParseException("$name: invalid skip $n at 0x${pos.toString(16)} while $what")
        pos += n.toInt()
    }

    fun seek(off: Long, bound: Int = data.size, what: String = "seeking") {
        if (off < 0 || off > bound) throw DwarfParseException("$name: out-of-bounds offset 0x${off.toString(16)} while $what")
        pos = off.toInt(); end = bound
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        var n = 0
        while (true) {
            if (++n > MAX_LEB128_BYTES) throw DwarfParseException("$name: ULEB128 too long at 0x${pos.toString(16)}")
            require(1, "ULEB128")
            val b = data[pos++].toInt() and 0xff
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw DwarfParseException("$name: ULEB128 overflow at 0x${pos.toString(16)}")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var n = 0
        var b = 0
        while (true) {
            if (++n > MAX_LEB128_BYTES) throw DwarfParseException("$name: SLEB128 too long at 0x${pos.toString(16)}")
            require(1, "SLEB128")
            b = data[pos++].toInt() and 0xff
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw DwarfParseException("$name: SLEB128 overflow at 0x${pos.toString(16)}")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-(1L shl shift))
        return result
    }

    /** NUL terminated string; missing NUL is reported (never silently scanned past the section). */
    fun cstr(): String {
        val start = pos
        var p = pos
        var n = 0
        while (p < end) {
            if (data[p].toInt() == 0) {
                val s = String(data, start, p - start, StandardCharsets.UTF_8)
                pos = p + 1
                return s
            }
            p++
            if (++n > MAX_STRING_BYTES) throw DwarfParseException("$name: string too long at 0x${start.toString(16)}")
        }
        throw DwarfParseException("$name: unterminated string at 0x${start.toString(16)}")
    }

    fun unitLength(): Long {
        val initial = u32()
        return if (initial == 0xffffffffL) {
            dwarf64 = true
            u64()
        } else {
            dwarf64 = false
            initial
        }
    }

    fun offset(): Long = if (dwarf64) u64() else u32()

    companion object {
        const val MAX_LEB128_BYTES = 16
        const val MAX_STRING_BYTES = 1_000_000
    }
}
