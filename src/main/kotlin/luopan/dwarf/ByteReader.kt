package luopan.dwarf

import java.nio.charset.StandardCharsets

/**
 * 带边界保护的字节游标：
 * - 任何越界读取都抛出 [DwarfBoundsException]，调用方必须在 section 级别隔离，
 *   绝不允许游标错位后继续解析（会产生伪结果）。
 * - 支持 8/16/32/64 位读取、定长 form、LEB128、DWARF initial length（带 64 位 DWARF 标记）。
 */
class ByteReader(private val data: ByteArray, private val littleEndian: Boolean) {
    var pos: Int = 0
        private set
    val size: Int get() = data.size

    fun seek(p: Int): ByteReader {
        if (p < 0 || p > data.size) throw DwarfBoundsException("seek out of bounds: $p > ${data.size}")
        pos = p
        return this
    }

    fun remaining(): Int = data.size - pos

    fun u8(): Int {
        if (pos + 1 > data.size) throw DwarfBoundsException("u8 overflow at $pos")
        return data[pos++].toInt() and 0xff
    }

    fun u16(): Int {
        if (pos + 2 > data.size) throw DwarfBoundsException("u16 overflow at $pos")
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (littleEndian) (a or (b shl 8)) else ((a shl 8) or b)
    }

    fun u32(): Long {
        if (pos + 4 > data.size) throw DwarfBoundsException("u32 overflow at $pos")
        var v = 0L
        if (littleEndian) {
            for (i in 0 until 4) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 0 until 4) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        if (pos + 8 > data.size) throw DwarfBoundsException("u64 overflow at $pos")
        var v = 0L
        if (littleEndian) {
            for (i in 0 until 8) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 0 until 8) v = ((v shl 8) or (data[pos + i].toLong() and 0xff))
        }
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray {
        if (n < 0 || pos + n > data.size) throw DwarfBoundsException("bytes($n) overflow at $pos")
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun skip(n: Int) {
        if (n < 0 || pos + n > data.size) throw DwarfBoundsException("skip($n) overflow at $pos")
        pos += n
    }

    fun nullTerminatedString(maxLen: Int = Int.MAX_VALUE): String {
        val start = pos
        var end = pos
        var guard = 0
        while (end < data.size && data[end].toInt() != 0) {
            end++
            if (++guard > maxLen) throw DwarfBoundsException("string too long at $start")
        }
        if (end >= data.size) throw DwarfBoundsException("unterminated string at $start")
        val s = String(data, start, end - start, StandardCharsets.UTF_8)
        pos = end + 1
        return s
    }

    /** 无符号 LEB128，带字节数上限，返回 (值, 消耗字节数)。 */
    fun uleb128(maxBytes: Int = 16): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var n = 0
        while (true) {
            if (++n > maxBytes) throw DwarfBoundsException("uleb128 too long at $pos")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw DwarfBoundsException("uleb128 overflow at $pos")
        }
        return result to n
    }

    /** 有符号 LEB128。 */
    fun sleb128(maxBytes: Int = 16): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var n = 0
        var b = 0
        while (true) {
            if (++n > maxBytes) throw DwarfBoundsException("sleb128 too long at $pos")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw DwarfBoundsException("sleb128 overflow at $pos")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result to n
    }

    /** 读取 DWARF initial length；返回 (length 字段值（不含自身）, 内容起点, 是否 64 位 DWARF)。 */
    fun initialLength(): Triple<Long, Int, Boolean> {
        val first = u32()
        if (first == 0xffffffffL) {
            val len = u64()
            if (len < 0 || len > Int.MAX_VALUE.toLong()) throw DwarfBoundsException("bad 64-bit dwarf length")
            return Triple(len, pos, true)
        }
        return Triple(first, pos, false)
    }

    fun readFixed(size: Int): Long = when (size) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw DwarfBoundsException("unsupported fixed size $size")
    }

    companion object {
        fun of(data: ByteArray, littleEndian: Boolean = true): ByteReader = ByteReader(data, littleEndian)
        fun empty(littleEndian: Boolean = true): ByteReader = ByteReader(ByteArray(0), littleEndian)
    }
}

class DwarfBoundsException(message: String) : RuntimeException(message)
class DwarfFormatException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
class UnsupportedFormException(val form: Int, message: String = "unsupported form 0x${form.toString(16)}") :
    RuntimeException(message)
