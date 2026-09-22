package compass.dwarf

import compass.Limits

open class DwarfException(message: String) : Exception(message)
class ParseException(message: String) : DwarfException(message)

/** Unknown attribute form: the CU is isolated (truncated) but the cursor must not
 *  continue producing bogus DIEs, so parsing of this CU aborts. */
class UnknownFormException(val form: Long, val at: Int) :
    DwarfException("unknown DWARF form 0x${form.toString(16)} at 0x${at.toString(16)}")

/** Cursor over a byte array with strict bounds checking. */
class Reader(val bytes: ByteArray, var pos: Int = 0, val limit: Int = bytes.size) {
    init {
        require(pos in 0..limit && limit <= bytes.size) { "bad reader window" }
    }

    val eof: Boolean get() = pos >= limit
    fun remaining(): Int = limit - pos

    fun require(n: Int) {
        if (n < 0 || pos > limit - n)
            throw ParseException("read of $n bytes past end at 0x${pos.toString(16)} (limit 0x${limit.toString(16)})")
    }

    fun u8(): Int { require(1); return bytes[pos++].toInt() and 0xFF }
    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        require(2)
        val v = (bytes[pos].toInt() and 0xFF) or ((bytes[pos + 1].toInt() and 0xFF) shl 8)
        pos += 2; return v
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        for (i in 0..3) v = v or ((bytes[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 4; return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        for (i in 0..7) v = v or ((bytes[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 8; return v
    }

    fun bytes(n: Int): ByteArray {
        if (n > Limits.MAX_BLOCK) throw ParseException("block too large: $n")
        require(n)
        val out = bytes.copyOfRange(pos, pos + n)
        pos += n; return out
    }

    fun cstr(): String {
        var end = pos
        val maxEnd = minOf(limit, pos + Limits.MAX_STRING)
        while (end < maxEnd && bytes[end].toInt() != 0) end++
        if (end >= limit) throw ParseException("unterminated string at 0x${pos.toString(16)}")
        val s = String(bytes, pos, end - pos, Charsets.UTF_8)
        pos = end + 1
        return s
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 70) throw ParseException("uleb128 too long at 0x${pos.toString(16)}")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        do {
            b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (shift > 70) throw ParseException("sleb128 too long at 0x${pos.toString(16)}")
        } while (b and 0x80 != 0)
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    /** Section-offset sized read (4 bytes DWARF32, 8 bytes DWARF64). */
    fun offset(dwarf64: Boolean): Long = if (dwarf64) u64() else u32()

    fun addr(addrSize: Int): Long = when (addrSize) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw ParseException("unsupported address size $addrSize")
    }
}
