package compass.elf

/** Bounds-checked reader. Every access is checked so corrupt sections cannot desync silently. */
class ByteReader(val data: ByteArray, var pos: Int = 0) {
    val size: Int get() = data.size
    fun remaining(): Int = size - pos

    fun require(n: Int, what: String = "read") {
        if (n < 0 || pos < 0 || pos.toLong() + n > size.toLong()) {
            throw ParseException("越界读取: $what @$pos 需要 $n 字节, 剩余 ${(size - pos).coerceAtLeast(0)}")
        }
    }

    fun seek(p: Int) {
        if (p < 0 || p > size) throw ParseException("游标越界: $p / $size")
        pos = p
    }

    fun u8(what: String = "u8"): Int {
        require(1, what)
        return data[pos++].toInt() and 0xff
    }

    fun u16(le: Boolean, what: String = "u16"): Int {
        require(2, what)
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (le) a or (b shl 8) else (a shl 8) or b
    }

    fun u32(le: Boolean, what: String = "u32"): Long {
        require(4, what)
        var v = 0L
        if (le) for (i in 0 until 4) v = v or ((data[pos + i].toInt() and 0xff).toLong() shl (8 * i))
        else for (i in 0 until 4) v = (v shl 8) or (data[pos + i].toInt() and 0xff).toLong()
        pos += 4
        return v
    }

    fun u64(le: Boolean, what: String = "u64"): Long {
        require(8, what)
        var v = 0L
        if (le) for (i in 0 until 8) v = v or ((data[pos + i].toInt() and 0xff).toLong() shl (8 * i))
        else for (i in 0 until 8) v = (v shl 8) or (data[pos + i].toInt() and 0xff).toLong()
        pos += 8
        return v
    }

    fun bytes(n: Int, what: String = "bytes"): ByteArray {
        require(n, what)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun take(n: Int, what: String = "slice"): ByteSlice {
        require(n, what)
        val s = ByteSlice(data, pos, n)
        pos += n
        return s
    }
}

/** A view into a backing array without copying. */
class ByteSlice(val data: ByteArray, val offset: Int, val length: Int) {
    fun reader(): ByteReader = ByteReader(data, offset)
    fun exactOrNull(p: Int, n: Int): ByteSlice? {
        if (p < 0 || n < 0 || p.toLong() + n > length.toLong()) return null
        return ByteSlice(data, offset + p, n)
    }
    fun u8at(p: Int): Int = data[offset + p].toInt() and 0xff
}

class ParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
