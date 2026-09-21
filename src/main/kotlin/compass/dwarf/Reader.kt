package compass.dwarf

class ParseException(message: String) : Exception(message)

/** Bounds-checked little-endian cursor. Every read is checked so a corrupt
 *  section aborts the current unit instead of producing phantom results. */
class Reader(val data: ByteArray, var pos: Int, val end: Int) {
    constructor(data: ByteArray) : this(data, 0, data.size)

    val remaining: Int get() = end - pos

    fun require(n: Int, what: String) {
        if (n < 0 || pos + n > end) throw ParseException("越界读取 $what: pos=$pos 需要=$n 界限=$end")
    }

    fun u8(): Int { require(1, "u8"); return data[pos++].toInt() and 0xFF }
    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        require(2, "u16")
        val v = (data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8)
        pos += 2; return v
    }

    fun u32(): Long {
        require(4, "u32")
        var v = 0L
        for (i in 0..3) v = v or ((data[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 4; return v
    }

    fun u64(): Long {
        require(8, "u64")
        var v = 0L
        for (i in 0..7) v = v or ((data[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 8; return v
    }

    fun bytes(n: Int): ByteArray { require(n, "bytes($n)"); val r = data.copyOfRange(pos, pos + n); pos += n; return r }

    fun cstring(): String {
        val sb = StringBuilder()
        while (true) {
            val b = u8()
            if (b == 0) break
            sb.append(b.toChar())
        }
        return sb.toString()
    }

    fun uleb(): Long {
        var r = 0L; var s = 0
        while (true) {
            val b = u8()
            r = r or ((b and 0x7F).toLong() shl s)
            if (b and 0x80 == 0) break
            s += 7
            if (s > 63) throw ParseException("ULEB128 过长 pos=$pos")
        }
        return r
    }

    fun sleb(): Long {
        var r = 0L; var s = 0
        while (true) {
            val b = u8()
            r = r or ((b and 0x7F).toLong() shl s)
            s += 7
            if (b and 0x80 == 0) {
                if (s < 64 && (b and 0x40) != 0) r = r or (-1L shl s)
                break
            }
            if (s > 63) throw ParseException("SLEB128 过长 pos=$pos")
        }
        return r
    }

    fun uint(size: Int): Long = when (size) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw ParseException("非法整数宽度 $size")
    }
}
