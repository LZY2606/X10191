package compass.dwarf

class DwarfException(msg: String) : Exception(msg)

/** A bounded, limit-enforcing cursor over one DWARF section. */
class Reader(
    val bytes: ByteArray,
    var pos: Int = 0,
    var littleEndian: Boolean = true,
    var dwarf64: Boolean = false,
    val maxOffset: Int = bytes.size,
) {
    val size: Int get() = maxOffset

    fun remaining() = maxOffset - pos

    fun require(n: Int, what: String) {
        if (n < 0 || pos + n > maxOffset) throw DwarfException("truncated $what at 0x${pos.toString(16)} (need $n, have $remaining())")
    }

    fun u8(): Int { require(1, "u8"); return bytes[pos++].toInt() and 0xff }

    fun u16(): Int {
        require(2, "u16")
        val v = if (littleEndian) (bytes[pos].toInt() and 0xff) or ((bytes[pos + 1].toInt() and 0xff) shl 8)
        else ((bytes[pos].toInt() and 0xff) shl 8) or (bytes[pos + 1].toInt() and 0xff)
        pos += 2; return v
    }

    fun u32(): Long {
        require(4, "u32")
        var v = 0L
        if (littleEndian) for (i in 0..3) v = v or ((bytes[pos + i].toLong() and 0xff) shl (8 * i))
        else for (i in 0..3) v = (v shl 8) or (bytes[pos + i].toLong() and 0xff)
        pos += 4; return v
    }

    fun u64(): Long {
        require(8, "u64")
        var v = 0L
        if (littleEndian) for (i in 0..7) v = v or ((bytes[pos + i].toLong() and 0xff) shl (8 * i))
        else for (i in 0..7) v = (v shl 8) or (bytes[pos + i].toLong() and 0xff)
        pos += 8; return v
    }

    fun offset(): Long = if (dwarf64) u64() else u32()

    fun uleb(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            if (shift >= 64 && (b and 0x7f) != 0) throw DwarfException("ULEB128 overflow at 0x${(pos - 1).toString(16)}")
            result = result or ((b.toLong() and 0x7f) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift > 70) throw DwarfException("ULEB128 too long at 0x${pos.toString(16)}")
        }
    }

    fun sleb(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
            if (shift > 70) throw DwarfException("SLEB128 too long at 0x${pos.toString(16)}")
        }
    }

    fun bytes(n: Int): ByteArray {
        require(n, "bytes($n)")
        val r = bytes.copyOfRange(pos, pos + n); pos += n; return r
    }

    fun cstring(): String {
        val start = pos
        while (pos < maxOffset && bytes[pos] != 0.toByte()) pos++
        if (pos >= maxOffset) throw DwarfException("unterminated string at 0x${start.toString(16)}")
        val s = String(bytes, start, pos - start, Charsets.UTF_8)
        pos++ // skip NUL
        return s
    }

    fun addr(addrSize: Int): Long = when (addrSize) {
        4 -> u32()
        8 -> u64()
        2 -> u16().toLong()
        else -> throw DwarfException("unsupported address size $addrSize")
    }

    fun cloneAt(newPos: Int): Reader {
        if (newPos < 0 || newPos > maxOffset) throw DwarfException("seek out of bounds: 0x${newPos.toString(16)}")
        val r = Reader(bytes, newPos, littleEndian, dwarf64, maxOffset)
        return r
    }
}
