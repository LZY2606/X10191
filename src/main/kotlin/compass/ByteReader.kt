package compass

/**
 * Bounded little-endian cursor over a byte array. Every read is bounds checked;
 * section parsers never wander outside their own window, so a corrupt section can
 * produce an [EndException] that the owning CU can isolate instead of poisoning
 * later results with a misaligned cursor.
 */
class ByteReader(val data: ByteArray, var pos: Int = 0, val end: Int = data.size) {

    class EndException(message: String) : RuntimeException(message)

    val remaining: Int get() = end - pos

    fun require(n: Int) {
        if (n < 0 || pos + n > end || pos < 0) {
            throw EndException("read out of bounds: need $n bytes at $pos, end=$end")
        }
    }

    fun seek(p: Int) {
        if (p < 0 || p > end) throw EndException("seek out of bounds: $p > $end")
        pos = p
    }

    fun skip(n: Int) = require(n).also { pos += n }

    fun u8(): Int { require(1); return data[pos].toInt() and 0xff }
    fun u16(): Int { require(2); val v = (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8); pos += 2; return v }
    fun u32(): Long {
        require(4)
        var v = 0L
        for (i in 0 until 4) v = v or ((data[pos + i].toLong() and 0xff) shl (8 * i))
        pos += 4
        return v
    }
    fun u64(): Long {
        require(8)
        var v = 0L
        for (i in 0 until 8) v = v or ((data[pos + i].toLong() and 0xff) shl (8 * i))
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (++count > MAX_LEB_BYTES) throw EndException("uleb128 too long")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw EndException("uleb128 overflow")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        var count = 0
        while (true) {
            if (++count > MAX_LEB_BYTES) throw EndException("sleb128 too long")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw EndException("sleb128 overflow")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun cString(): String {
        val start = pos
        while (pos < end && data[pos].toInt() != 0) pos++
        if (pos >= end) throw EndException("unterminated string")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    /** Fixed-length address for an 8/4 byte address size. */
    fun addr(size: Int): Long = when (size) {
        8 -> u64()
        4 -> u32()
        2 -> u16().toLong()
        1 -> u8().toLong()
        else -> throw EndException("bad address size $size")
    }

    /** 4- or 8-byte section offset / reference. */
    fun offset(size: Int): Long = when (size) {
        4 -> u32()
        8 -> u64()
        else -> throw EndException("bad offset size $size")
    }

    companion object {
        const val MAX_LEB_BYTES = 16
    }
}

/** Reference whose base section depends on the form; kept raw until resolution. */
data class Ref(val form: Int, val value: Long)
