package compass.binary

/** 越界读取：所有 section 解析都在有界 reader 上进行，避免游标扫到相邻 section。 */
class BinaryBoundsException(message: String) : RuntimeException(message)

/** 遇到无法安全继续的结构（未知 form、损坏长度），调用方应隔离当前 CU/表，而不是错位续读。 */
class ParseAbortException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

class ByteReader(
    val data: ByteArray,
    var pos: Int = 0,
    val end: Int = data.size,
    val littleEndian: Boolean = true,
) {
    init {
        if (pos < 0 || end > data.size || pos > end) throw BinaryBoundsException("reader 区间非法")
    }

    fun remaining(): Int = end - pos
    fun require(n: Int) {
        if (n < 0 || pos > end - n) {
            throw BinaryBoundsException("读取越界: 需要 $n 字节, 剩余 ${end - pos} (pos=$pos,end=$end)")
        }
    }

    fun u8(): Int { require(1); return data[pos++].toInt() and 0xff }
    fun i8(): Int { require(1); return data[pos++].toInt() }

    fun u16(): Int { require(2); val b0 = data[pos].toInt() and 0xff; val b1 = data[pos + 1].toInt() and 0xff; pos += 2
        return if (littleEndian) (b1 shl 8) or b0 else (b0 shl 8) or b1 }
    fun i16(): Int = u16().toShort().toInt()

    fun u32(): Long { require(4); var v = 0L
        if (littleEndian) for (i in 0..3) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        else for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        pos += 4; return v }
    fun i32(): Int = u32().toInt()

    fun u64(): Long { require(8); var v = 0L
        if (littleEndian) for (i in 0..7) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        else for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        pos += 8; return v }
    fun i64(): Long = u64()

    fun readN(n: Int): ByteArray { require(n); val out = data.copyOfRange(pos, pos + n); pos += n; return out }
    fun slice(pos: Int, end: Int): ByteReader {
        if (pos < 0 || end > this.end || pos > end) throw BinaryBoundsException("slice 越界")
        return ByteReader(data, pos, end, littleEndian)
    }

    fun seek(newPos: Int) { if (newPos < pos || newPos > end) throw BinaryBoundsException("seek 越界"); pos = newPos }
    fun align(n: Int) { if (n > 1) { val r = pos % n; if (r != 0) require(n - r).also { pos += n - r } } }

    fun uleb(maxBytes: Int = 16): Long {
        var result = 0L; var shift = 0; var count = 0
        while (true) {
            if (++count > maxBytes) throw ParseAbortException("ULEB128 超出 $maxBytes 字节")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if ((b and 0x80) == 0) return result
            shift += 7
            if (shift >= 64) throw ParseAbortException("ULEB128 超过 64 位")
        }
    }

    fun sleb(maxBytes: Int = 16): Long {
        var result = 0L; var shift = 0; var b = 0; var count = 0
        while (true) {
            if (++count > maxBytes) throw ParseAbortException("SLEB128 超出 $maxBytes 字节")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if ((b and 0x80) == 0) break
        }
        if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
        return result
    }

    /** DWARF 初始长度：0xffffffff 后接 8 字节长度表示 DWARF64。返回 (内容起点, 内容终点, dwarf64)。 */
    fun initialLength(maxLen: Int = Int.MAX_VALUE): Triple<Int, Int, Boolean> {
        val first = u32()
        if (first == 0xffffffffL) {
            val len = u64()
            if (len < 0 || len > maxLen.toLong()) throw ParseAbortException("DWARF64 长度非法: $len")
            val start = pos; val endEx = start + len.toInt()
            if (endEx > end) throw BinaryBoundsException("DWARF64 声明长度越界")
            return Triple(start, endEx, true)
        }
        val len = first.toInt()
        val start = pos; val endEx = start + len
        if (endEx > end) throw BinaryBoundsException("DWARF 声明长度越界: $len")
        return Triple(start, endEx, false)
    }

    fun cString(maxLen: Int = 1 shl 20): String {
        val start = pos
        var p = pos
        while (p < end && data[p].toInt() != 0) p++
        if (p >= end) throw BinaryBoundsException("未终止的字符串")
        if (p - start > maxLen) throw ParseAbortException("字符串超过 ${maxLen} 字节")
        val s = String(data, start, p - start, Charsets.UTF_8)
        pos = p + 1
        return s
    }

    fun hexDump(n: Int = 16): String {
        val take = minOf(n, remaining())
        return (0 until take).joinToString(" ") { "%02x".format(data[pos + it].toInt() and 0xff) }
    }
}
