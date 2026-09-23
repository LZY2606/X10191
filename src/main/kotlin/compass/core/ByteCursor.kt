package compass.core

/**
 * 有界只读游标：所有越界访问都抛出 [CursorException]，由上层隔离，
 * 保证解析器不会在损坏 section 上游标错位后继续产生伪结果。
 */
class ByteCursor(val data: ByteArray, private val base: Int = 0, val size: Int = data.size - base) {
    var pos: Int = 0
    var limit: Int = size
    var jumpCount: Int = 0
        private set

    fun slice(sectionOffset: Int, length: Int): ByteCursor {
        if (sectionOffset < 0 || length < 0 || sectionOffset + length > size) {
            throw CursorException("切片越界: offset=$sectionOffset length=$length size=$size")
        }
        return ByteCursor(data, base + sectionOffset, length)
    }

    fun remaining(): Int = limit - pos
    fun require(n: Int) {
        if (n < 0 || pos + n > limit) throw CursorException("意外结束: 需要 $n 字节, 剩余 ${limit - pos}")
    }

    fun u8(): Int { require(1); return data[base + pos++].toInt() and 0xFF }
    fun i8(): Int { require(1); return data[base + pos++].toInt() }

    fun u16(): Int { require(2); val b = base + pos; pos += 2
        return (data[b].toInt() and 0xFF) or ((data[b + 1].toInt() and 0xFF) shl 8) }

    fun u32(): Long { require(4); val b = base + pos; pos += 4
        var v = 0L
        for (i in 0 until 4) v = v or ((data[b + i].toLong() and 0xFFL) shl (8 * i))
        return v }

    fun i32(): Int = u32().toInt()
    fun i64(): Long { require(8); val b = base + pos; pos += 8
        var v = 0L
        for (i in 0 until 8) v = v or ((data[b + i].toLong() and 0xFFL) shl (8 * i))
        return v }

    fun bytes(n: Int): ByteArray { require(n); val out = data.copyOfRange(base + pos, base + pos + n); pos += n; return out }

    fun uleb128(): Long {
        var result = 0L; var shift = 0; var count = 0
        while (true) {
            if (++count > MAX_LEB_BYTES) throw CursorException("ULEB128 过长")
            val b = u8()
            result = result or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw CursorException("ULEB128 超出 64 位")
        }
        return result
    }

    fun sleb128(): Long {
        var result = 0L; var shift = 0; var b = 0; var count = 0
        while (true) {
            if (++count > MAX_LEB_BYTES) throw CursorException("SLEB128 过长")
            b = u8()
            result = result or ((b and 0x7F).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw CursorException("SLEB128 超出 64 位")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    /** 受跳转次数限制的绝对定位（用于 section 引用）。 */
    fun jump(sectionOffset: Long, maxJumps: Int) {
        if (++jumpCount > maxJumps) throw CursorException("引用跳转次数超过上限 $maxJumps")
        val off = sectionOffset.toInt()
        if (off < 0 || off > limit) throw CursorException("越界引用: offset=$off size=$limit")
        pos = off
    }

    fun readCStringAt(sectionOffset: Long): String {
        val off = sectionOffset.toInt()
        if (off < 0 || off >= size) throw CursorException("字符串越界: $off")
        var end = off
        while (end < size && data[base + end].toInt() != 0) end++
        if (end >= size) throw CursorException("字符串未终止于 $off")
        return String(data, base + off, end - off, Charsets.UTF_8)
    }

    companion object { const val MAX_LEB_BYTES = 16 }
}

class CursorException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
