package compass

class ParseException(message: String) : Exception(message)

/** 带边界的二进制游标。任何越界都会抛 ParseException，绝不让游标悄悄滑走。 */
class BinReader(val buf: ByteArray, var pos: Int = 0, val littleEndian: Boolean = true) {
    val size: Int get() = buf.size
    fun remaining(): Int = buf.size - pos

    fun require(n: Int) {
        if (n < 0 || pos < 0 || pos + n > buf.size || pos + n < pos)
            throw ParseException("越界读取 pos=$pos need=$n size=${buf.size}")
    }

    fun seek(p: Int) {
        if (p < 0 || p > buf.size) throw ParseException("越界定位 pos=$p size=${buf.size}")
        pos = p
    }

    fun skip(n: Int) { require(n); pos += n }

    fun u8(): Int { require(1); return buf[pos++].toInt() and 0xFF }
    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        require(2)
        val b0 = u8(); val b1 = u8()
        return if (littleEndian) b0 or (b1 shl 8) else (b0 shl 8) or b1
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        if (littleEndian) for (i in 0..3) v = v or (u8().toLong() shl (8 * i))
        else for (i in 0..3) v = (v shl 8) or u8().toLong()
        return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        if (littleEndian) for (i in 0..7) v = v or (u8().toLong() shl (8 * i))
        else for (i in 0..7) v = (v shl 8) or u8().toLong()
        return v
    }

    fun uleb(): Long {
        var result = 0L; var shift = 0
        for (i in 0 until 10) {
            val b = u8()
            if (shift < 64) result = result or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
        throw ParseException("ULEB128 超过长度上限 pos=$pos")
    }

    fun sleb(): Long {
        var result = 0L; var shift = 0
        for (i in 0 until 10) {
            val b = u8()
            result = result or ((b and 0x7F).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
        }
        throw ParseException("SLEB128 超过长度上限 pos=$pos")
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val r = buf.copyOfRange(pos, pos + n)
        pos += n
        return r
    }

    fun cstring(max: Int = 1 shl 20): String {
        var end = pos
        while (end < buf.size && buf[end] != 0.toByte()) {
            end++
            if (end - pos > max) throw ParseException("字符串超过长度上限 pos=$pos")
        }
        if (end >= buf.size) throw ParseException("字符串未终止 pos=$pos")
        val s = String(buf, pos, end - pos, Charsets.UTF_8)
        pos = end + 1
        return s
    }
}

fun hex(v: Long): String = "0x" + java.lang.Long.toHexString(v)
