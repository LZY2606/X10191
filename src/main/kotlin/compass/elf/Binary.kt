package compass.elf

import java.nio.ByteBuffer
import java.nio.ByteOrder

open class BinaryParseException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * 有界小端/大端读取器：所有读操作都不能越过 section 边界。
 * 未知 form 时必须通过 [skipForm] 安全跳过，避免游标错位产生伪结果。
 */
class Reader(val buf: ByteBuffer, val endian: ByteOrder) {
    val size: Int = buf.limit()
    var pos: Int = 0
        private set
    var dwarf64: Boolean = false
    var addressSize: Int = 8

    constructor(bytes: ByteArray, endian: ByteOrder) : this(ByteBuffer.wrap(bytes), endian)

    init {
        buf.order(endian)
    }

    fun remaining(): Int = size - pos
    fun eof(): Boolean = pos >= size
    fun seek(p: Int) {
        if (p < 0 || p > size) throw BinaryParseException("reader 越界 seek=$p size=$size")
        pos = p
    }

    fun need(n: Int) {
        if (n < 0 || pos + n > size) throw BinaryParseException("reader 越界 pos=$pos need=$n size=$size")
    }

    fun u1(): Int {
        need(1); val v = buf.get(pos).toInt() and 0xff; pos += 1; return v
    }

    fun s1(): Int {
        need(1); val v = buf.get(pos).toInt(); pos += 1; return v
    }

    fun u2(): Int {
        need(2); val v = buf.getShort(pos).toInt() and 0xffff; pos += 2; return v
    }

    fun u4(): Int {
        need(4); val v = buf.getInt(pos); pos += 4; return v
    }

    fun u4long(): Long = u4().toLong() and 0xffffffffL

    fun u8(): Long {
        need(8); val v = buf.getLong(pos); pos += 8; return v
    }

    fun bytes(n: Int): ByteArray {
        need(n); val out = ByteArray(n); buf.duplicate().position(pos).get(out); pos += n; return out
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        var guard = 0
        while (true) {
            if (++guard > 20) throw BinaryParseException("ULEB128 过长")
            val b = u1()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 63) throw BinaryParseException("ULEB128 超出 64 位")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        var guard = 0
        while (true) {
            if (++guard > 20) throw BinaryParseException("SLEB128 过长")
            b = u1()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift > 63) throw BinaryParseException("SLEB128 超出 64 位")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun cString(): String {
        val start = pos
        while (pos < size && buf.get(pos).toInt() != 0) pos++
        if (pos >= size) throw BinaryParseException("未终止的字符串")
        val s = String(bytes(pos - start), Charsets.UTF_8)
        pos += 1
        return s
    }

    fun initialLength(): Long {
        val len = u4()
        return when (len) {
            0xffffffffL.toInt() -> { dwarf64 = true; u8() }
            in 0..0xfffffff0 -> { dwarf64 = false; len.toLong() and 0xffffffffL }
            else -> throw BinaryParseException("保留的 32 位 DWARF 长度 0x${len.toString(16)}")
        }
    }

    fun refLen(): Int = if (dwarf64) 8 else 4

    fun readRef(): Long = if (dwarf64) u8() else u4long()

    fun addr(): Long = when (addressSize) {
        1 -> u1().toLong()
        2 -> u2().toLong()
        4 -> u4long()
        8 -> u8()
        else -> throw BinaryParseException("不支持的地址大小 $addressSize")
    }

    /** 从当前位置取 [n] 字节的独立子 reader，随后父 reader 跳过 n 字节。 */
    fun slice(n: Int): Reader {
        val b = bytes(n)
        return Reader(b, endian)
    }
}
