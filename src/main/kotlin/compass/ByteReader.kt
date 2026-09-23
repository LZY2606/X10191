package compass

import java.nio.ByteOrder

/**
 * 受限字节游标：所有读取都带边界检查，越界抛 [ByteCursorException]。
 * LEB128 有最大字节数，避免损坏数据造成无限读取。
 */
class ByteCursorException(message: String) : RuntimeException(message)

class ByteReader(
    val data: ByteArray,
    val littleEndian: Boolean = true,
    offset: Int = 0,
    val end: Int = data.size,
) {
    var pos: Int = offset
        private set

    val remaining: Int get() = end - pos

    fun seek(newPos: Int): ByteReader {
        if (newPos < 0 || newPos > end) throw ByteCursorException("seek 越界: $newPos (end=$end)")
        pos = newPos
        return this
    }

    fun require(n: Int) {
        if (n < 0) throw ByteCursorException("负长度读取")
        if (pos + n > end) throw ByteCursorException("读取越界: 需要 $n 字节, pos=$pos end=$end")
    }

    fun u8(): Int {
        require(1)
        return data[pos++].toInt() and 0xff
    }

    fun s8(): Int {
        require(1)
        return data[pos++].toInt()
    }

    fun u16(): Int {
        require(2)
        val v = if (littleEndian)
            (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8)
        else
            ((data[pos].toInt() and 0xff) shl 8) or (data[pos + 1].toInt() and 0xff)
        pos += 2
        return v
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        if (littleEndian) {
            for (i in 0..3) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        if (littleEndian) {
            for (i in 0..7) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun readCString(): String {
        val start = pos
        while (pos < end && data[pos].toInt() != 0) pos++
        if (pos >= end) throw ByteCursorException("未终止的字符串 (start=$start)")
        val out = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return out
    }

    fun readStringAt(offset: Int): String? {
        if (offset < 0 || offset >= end) return null
        var p = offset
        while (p < end && data[p].toInt() != 0) p++
        if (p >= end) return null
        return String(data, offset, p - offset, Charsets.UTF_8)
    }

    fun uleb(maxBytes: Int = 16): ULong {
        var result = 0UL
        var shift = 0
        var count = 0
        while (true) {
            if (++count > maxBytes) throw ByteCursorException("ULEB128 超长 (>$maxBytes)")
            val b = u8()
            result = result or ((b and 0x7f).toULong() shl shift)
            if ((b and 0x80) == 0) break
            shift += 7
            if (shift >= 64) throw ByteCursorException("ULEB128 溢出")
        }
        return result
    }

    fun sleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var b: Int
        var count = 0
        while (true) {
            if (++count > maxBytes) throw ByteCursorException("SLEB128 超长 (>$maxBytes)")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if ((b and 0x80) == 0) break
            if (shift >= 64) throw ByteCursorException("SLEB128 溢出")
        }
        if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
        return result
    }

    fun skip(n: Int) {
        require(n)
        pos += n
    }

    fun order(): ByteOrder =
        if (littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN

    inline fun <T> bounded(maxBytes: Int, block: ByteReader.() -> T): T {
        val endBefore = end
        val newEnd = minOf(pos + maxBytes, endBefore)
        val sub = ByteReader(data, littleEndian, pos, newEnd)
        val result = sub.block()
        return result
    }
}
