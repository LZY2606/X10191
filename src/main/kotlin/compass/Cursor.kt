package compass

open class DwarfException(msg: String) : Exception(msg)
class UnknownFormException(val form: Long, msg: String) : DwarfException(msg)

/** Bounds-checked little/big-endian cursor over a byte window. */
class Cursor(
    val buf: ByteArray,
    var pos: Int,
    val end: Int,
    val littleEndian: Boolean = true
) {
    init { require(pos in 0..end && end <= buf.size) { "bad cursor window" } }

    fun remaining(): Int = end - pos
    fun hasRemaining(): Boolean = pos < end

    private fun require(n: Int) {
        if (n < 0 || pos + n > end) throw DwarfException("cursor overrun at $pos need $n end $end")
    }

    fun skip(n: Int) { require(n); pos += n }

    fun u8(): Int { require(1); return buf[pos++].toInt() and 0xFF }
    fun s8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        require(2)
        val b0 = buf[pos].toInt() and 0xFF; val b1 = buf[pos + 1].toInt() and 0xFF
        pos += 2
        return if (littleEndian) b0 or (b1 shl 8) else (b0 shl 8) or b1
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        if (littleEndian) {
            for (i in 0..3) v = v or ((buf[pos + i].toLong() and 0xFF) shl (8 * i))
        } else {
            for (i in 0..3) v = (v shl 8) or (buf[pos + i].toLong() and 0xFF)
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        if (littleEndian) {
            for (i in 0..7) v = v or ((buf[pos + i].toLong() and 0xFF) shl (8 * i))
        } else {
            for (i in 0..7) v = (v shl 8) or (buf[pos + i].toLong() and 0xFF)
        }
        pos += 8
        return v
    }

    fun uleb(): Long {
        var result = 0L; var shift = 0
        while (true) {
            if (shift > 63) throw DwarfException("uleb too long at $pos")
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L; var shift = 0; var b: Int
        while (true) {
            if (shift > 63) throw DwarfException("sleb too long at $pos")
            b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
        return result
    }

    fun bytes(n: Int): ByteArray { require(n); val r = buf.copyOfRange(pos, pos + n); pos += n; return r }

    fun cstr(): String {
        var e = pos
        while (e < end && buf[e] != 0.toByte()) e++
        if (e >= end) throw DwarfException("unterminated string at $pos")
        val s = String(buf, pos, e - pos, Charsets.UTF_8)
        pos = e + 1
        return s
    }

    fun addr(size: Int): Long = when (size) {
        4 -> u32()
        8 -> u64()
        2 -> u16().toLong()
        else -> throw DwarfException("unsupported addr size $size")
    }

    fun cloneAt(p: Int, e: Int = end): Cursor {
        if (p < 0 || e > end || p > e) throw DwarfException("clone out of bounds $p..$e")
        return Cursor(buf, p, e, littleEndian)
    }
}
