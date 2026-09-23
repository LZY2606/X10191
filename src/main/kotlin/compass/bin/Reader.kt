package compass.bin

class DwarfException(message: String) : Exception(message)
class UnknownFormException(val form: Long, message: String) : DwarfException(message)

/** Bounds-checked little/big-endian cursor over a byte slice. */
class Reader(
    val bytes: ByteArray,
    var pos: Int = 0,
    val limit: Int = bytes.size,
    val littleEndian: Boolean = true,
    val ctx: String = ""
) {
    init {
        require(pos in 0..limit && limit <= bytes.size) { "bad reader window $pos..$limit/${bytes.size}" }
    }

    fun remaining(): Int = limit - pos

    private fun need(n: Int) {
        if (n < 0 || pos + n > limit) throw DwarfException("[$ctx] read of $n bytes at 0x${pos.toString(16)} overruns limit 0x${limit.toString(16)}")
    }

    fun u8(): Int { need(1); return bytes[pos++].toInt() and 0xFF }
    fun i8(): Int { need(1); return bytes[pos++].toInt() }

    fun u16(): Int {
        need(2)
        val v = if (littleEndian)
            (bytes[pos].toInt() and 0xFF) or ((bytes[pos + 1].toInt() and 0xFF) shl 8)
        else
            ((bytes[pos].toInt() and 0xFF) shl 8) or (bytes[pos + 1].toInt() and 0xFF)
        pos += 2
        return v
    }

    fun u32(): Long {
        need(4)
        var v = 0L
        if (littleEndian) for (i in 3 downTo 0) v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
        else for (i in 0..3) v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
        pos += 4
        return v
    }

    fun u64(): Long {
        need(8)
        var v = 0L
        if (littleEndian) for (i in 7 downTo 0) v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
        else for (i in 0..7) v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
        pos += 8
        return v
    }

    fun uint(size: Int): Long = when (size) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw DwarfException("[$ctx] unsupported uint size $size")
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift > 70) throw DwarfException("[$ctx] uleb128 too long at 0x${pos.toString(16)}")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        while (true) {
            b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift > 70) throw DwarfException("[$ctx] sleb128 too long at 0x${pos.toString(16)}")
        }
        if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
        return result
    }

    fun cstring(): String {
        val start = pos
        while (pos < limit && bytes[pos].toInt() != 0) pos++
        if (pos >= limit) throw DwarfException("[$ctx] unterminated string at 0x${start.toString(16)}")
        val s = String(bytes, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun bytes(n: Int): ByteArray {
        need(n)
        val out = bytes.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun skip(n: Long) {
        if (n < 0 || n > Int.MAX_VALUE || pos + n > limit)
            throw DwarfException("[$ctx] skip of $n at 0x${pos.toString(16)} overruns limit 0x${limit.toString(16)}")
        pos += n.toInt()
    }

    fun fork(pos: Int, limit: Int = this.limit, ctx: String = this.ctx): Reader =
        Reader(bytes, pos, limit, littleEndian, ctx)
}
