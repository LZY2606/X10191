package compass.dwarf

/** Bounded little-endian cursor over a section's bytes.
 *  All reads are bounds-checked; a corrupt section raises DwarfException
 *  instead of producing misaligned garbage. */
class DwarfException(message: String) : Exception(message)

class Reader(
    val bytes: ByteArray,
    var pos: Int = 0,
    val limit: Int = bytes.size,
    val label: String = "section"
) {
    val remaining: Int get() = limit - pos
    fun exhausted(): Boolean = pos >= limit

    private fun need(n: Int) {
        if (n < 0 || pos + n > limit || pos + n > bytes.size)
            throw DwarfException("$label: read of $n bytes at 0x${pos.toString(16)} exceeds limit 0x${limit.toString(16)}")
    }

    fun seek(newPos: Int) {
        if (newPos < 0 || newPos > limit)
            throw DwarfException("$label: seek to 0x${newPos.toString(16)} out of bounds [0, 0x${limit.toString(16)})")
        pos = newPos
    }

    fun forkAt(offset: Int, newLimit: Int = limit): Reader {
        if (offset < 0 || offset > limit || newLimit > limit)
            throw DwarfException("$label: fork at 0x${offset.toString(16)} out of bounds")
        return Reader(bytes, offset, newLimit, label)
    }

    fun u8(): Int { need(1); return bytes[pos++].toInt() and 0xFF }
    fun u16(): Int { need(2); val v = (bytes[pos].toInt() and 0xFF) or ((bytes[pos + 1].toInt() and 0xFF) shl 8); pos += 2; return v }
    fun u32(): Long {
        need(4)
        var v = 0L
        for (i in 0..3) v = v or ((bytes[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 4; return v
    }
    fun u64(): Long {
        need(8)
        var v = 0L
        for (i in 0..7) v = v or ((bytes[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 8; return v
    }
    fun bytes(n: Int): ByteArray { need(n); val out = bytes.copyOfRange(pos, pos + n); pos += n; return out }

    fun uleb128(): Long {
        var result = 0L; var shift = 0
        while (true) {
            if (shift > 63) throw DwarfException("$label: uleb128 too long at 0x${pos.toString(16)}")
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
    }

    fun sleb128(): Long {
        var result = 0L; var shift = 0
        while (true) {
            if (shift > 63) throw DwarfException("$label: sleb128 too long at 0x${pos.toString(16)}")
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
        }
    }

    fun cstring(): String {
        val start = pos
        while (true) {
            if (pos >= limit) throw DwarfException("$label: unterminated string at 0x${start.toString(16)}")
            if (bytes[pos++].toInt() == 0) break
        }
        return String(bytes, start, pos - 1 - start, Charsets.UTF_8)
    }

    /** DWARF 32/64-bit initial length. Returns (length, is64). */
    fun initialLength(): Pair<Long, Boolean> {
        val first = u32()
        return when (first) {
            0xFFFFFFFFL -> Pair(u64(), true)
            in 0xFFFFFFF0L..0xFFFFFFFEL -> throw DwarfException("$label: reserved initial length 0x${first.toString(16)}")
            else -> Pair(first, false)
        }
    }

    fun addr(addrSize: Int): Long = when (addrSize) {
        4 -> u32()
        8 -> u64()
        else -> throw DwarfException("$label: unsupported address size $addrSize")
    }
}
