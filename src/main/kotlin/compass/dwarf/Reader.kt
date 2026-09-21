package compass.dwarf

class DwarfException(message: String) : Exception(message)
class UnknownFormException(val form: Int) : DwarfException("unknown form 0x${form.toString(16)}")

/** Bounds-checked little-endian cursor over a section's bytes. */
class Reader(
    val bytes: ByteArray,
    pos: Int = 0,
    val limit: Int = bytes.size,
    var addrSize: Int = 8,
    var dwarf64: Boolean = false,
) {
    var pos: Int = pos
        set(value) {
            if (value < 0 || value > limit) throw DwarfException("cursor out of bounds: $value (limit $limit)")
            field = value
        }

    val remaining: Int get() = limit - pos
    fun exhausted(): Boolean = pos >= limit

    private fun need(n: Int) {
        if (n < 0 || pos + n > limit) throw DwarfException("read past section end at $pos (+$n, limit $limit)")
    }

    fun u8(): Int { need(1); return bytes[pos++].toInt() and 0xFF }
    fun s8(): Int = u8().toByte().toInt()

    fun u16(): Int { need(2); val v = (bytes[pos].toInt() and 0xFF) or ((bytes[pos + 1].toInt() and 0xFF) shl 8); pos += 2; return v }

    fun u32(): Long {
        need(4)
        var v = 0L
        for (i in 0..3) v = v or ((bytes[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 4
        return v
    }

    fun u64(): Long {
        need(8)
        var v = 0L
        for (i in 0..7) v = v or ((bytes[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 8
        return v
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 63) throw DwarfException("uleb128 too long")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        do {
            b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (shift > 70) throw DwarfException("sleb128 too long")
        } while (b and 0x80 != 0)
        if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
        return result
    }

    fun addr(): Long = when (addrSize) {
        4 -> u32()
        8 -> u64()
        2 -> u16().toLong()
        else -> throw DwarfException("unsupported address size $addrSize")
    }

    /** 32/64-bit DWARF-format offset depending on current unit format. */
    fun formatOffset(): Long = if (dwarf64) u64() else u32()

    fun bytes(n: Int): ByteArray { need(n); val out = bytes.copyOfRange(pos, pos + n); pos += n; return out }

    fun cstring(): String {
        val start = pos
        while (pos < limit && bytes[pos].toInt() != 0) pos++
        if (pos >= limit) throw DwarfException("unterminated string at $start")
        val s = String(bytes, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun fork(pos: Int, limit: Int = this.limit): Reader {
        if (pos < 0 || limit > this.limit || pos > limit) throw DwarfException("fork out of bounds")
        return Reader(bytes, pos, limit, addrSize, dwarf64)
    }
}
