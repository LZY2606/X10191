package compass.elf

/** Bounded little/big-endian cursor over a byte array. All reads are bounds-checked;
 *  hitting the end throws [Truncated] so callers can isolate the damaged unit
 *  instead of letting a misaligned cursor keep producing phantom results. */
class Truncated(msg: String) : Exception(msg)

class Reader(
    val data: ByteArray,
    var pos: Int = 0,
    val limit: Int = data.size,
    var bigEndian: Boolean = false,
) {
    val remaining: Int get() = limit - pos
    fun exhausted(): Boolean = pos >= limit

    private fun need(n: Int) {
        if (n < 0 || pos + n > limit) throw Truncated("read of $n bytes at $pos exceeds limit $limit")
    }

    fun u8(): Int { need(1); return data[pos++].toInt() and 0xFF }
    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        need(2)
        val v = if (bigEndian)
            ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        else
            (data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8)
        pos += 2
        return v
    }

    fun u32(): Long {
        need(4)
        var v = 0L
        if (bigEndian) for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        else for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        pos += 4
        return v
    }

    fun u64(): Long {
        need(8)
        var v = 0L
        if (bigEndian) for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        else for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        pos += 8
        return v
    }

    fun uleb128(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 63) throw Truncated("uleb128 too long at $pos")
        }
        return result
    }

    fun sleb128(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        do {
            b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (shift > 70) throw Truncated("sleb128 too long at $pos")
        } while (b and 0x80 != 0)
        if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
        return result
    }

    fun bytes(n: Int): ByteArray { need(n); val out = data.copyOfRange(pos, pos + n); pos += n; return out }

    fun cstring(): String {
        val start = pos
        while (pos < limit && data[pos].toInt() != 0) pos++
        if (pos >= limit) throw Truncated("unterminated string at $start")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun fork(at: Int): Reader {
        if (at < 0 || at > limit) throw Truncated("fork offset $at out of bounds [0,$limit]")
        return Reader(data, at, limit, bigEndian)
    }
}
