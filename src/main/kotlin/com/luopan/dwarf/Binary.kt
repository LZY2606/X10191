package com.luopan.dwarf

/**
 * 有界字节读取器。所有越界访问统一抛出 [DwarfReadException]，
 * 解析层在 CU / section 粒度捕获它并记录诊断，避免游标错位后产生伪结果。
 */
class Binary(
    val bytes: ByteArray,
    val start: Int = 0,
    val size: Int = bytes.size - start,
    val endian: Endian = Endian.LITTLE,
) {
    val end: Int = start + size
    var pos: Int = start

    init {
        require(start >= 0 && size >= 0 && end <= bytes.size) { "binary window out of bounds" }
    }

    fun seek(p: Int) {
        if (p < start || p > end) throw DwarfReadException("seek out of bounds: $p (window $start..$end)")
        pos = p
    }

    fun require(n: Int) {
        if (n < 0 || pos + n > end) throw DwarfReadException("read $n bytes out of bounds at $pos (window end $end)")
    }

    fun u1(): Int {
        require(1); val v = bytes[pos].toInt() and 0xff; pos++; return v
    }

    fun s1(): Int = bytes[pos++].toInt()

    fun s4(): Int {
        require(4)
        var v = 0
        if (endian == Endian.LITTLE) {
            for (i in 3 downTo 0) v = (v shl 8) or (bytes[pos + i].toInt() and 0xff)
        } else {
            for (i in 0..3) v = (v shl 8) or (bytes[pos + i].toInt() and 0xff)
        }
        pos += 4
        return v
    }

    fun u2(): Int {
        require(2)
        val a = bytes[pos].toInt() and 0xff
        val b = bytes[pos + 1].toInt() and 0xff
        pos += 2
        return if (endian == Endian.LITTLE) a or (b shl 8) else b or (a shl 8)
    }

    fun u4(): Int {
        require(4)
        var v = 0
        if (endian == Endian.LITTLE) {
            for (i in 3 downTo 0) v = (v shl 8) or (bytes[pos + i].toInt() and 0xff)
        } else {
            for (i in 0..3) v = (v shl 8) or (bytes[pos + i].toInt() and 0xff)
        }
        pos += 4
        return v
    }

    fun u8(): Long {
        require(8)
        var v = 0L
        if (endian == Endian.LITTLE) {
            for (i in 7 downTo 0) v = (v shl 8) or (bytes[pos + i].toLong() and 0xff)
        } else {
            for (i in 0..7) v = (v shl 8) or (bytes[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    fun uint(bytes: Int): Long = when (bytes) {
        1 -> u1().toLong()
        2 -> u2().toLong()
        4 -> u4().toLong() and 0xffffffffL
        8 -> u8()
        else -> throw DwarfReadException("unsupported integer size $bytes")
    }

    fun readBytes(n: Int): ByteArray {
        require(n)
        val out = bytes.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    /** ULEB128，带硬性长度上限（10/20 字节）防止恶意 varint 拖垮解析。 */
    fun uleb(maxBytes: Int = 20): Long {
        var result = 0L
        var shift = 0
        var i = 0
        while (true) {
            if (++i > maxBytes) throw DwarfReadException("uleb128 too long")
            val b = u1()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw DwarfReadException("uleb128 overflow")
        }
    }

    fun sleb(maxBytes: Int = 20): Long {
        var result = 0L
        var shift = 0
        var i = 0
        var b = 0
        while (true) {
            if (++i > maxBytes) throw DwarfReadException("sleb128 too long")
            b = u1()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw DwarfReadException("sleb128 overflow")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    /** 以零结尾字符串，无界长度保护（section 结束即终止）。 */
    fun cstring(): String {
        val begin = pos
        while (pos < end && bytes[pos] != 0.toByte()) pos++
        if (pos >= end) throw DwarfReadException("unterminated cstring at $begin")
        val s = String(bytes, begin, pos - begin, Charsets.UTF_8)
        pos++
        return s
    }

    fun available(): Int = end - pos

    fun windowAt(offset: Int, length: Int, endian: Endian = this.endian): Binary {
        if (offset < 0 || length < 0 || offset + length > bytes.size)
            throw DwarfReadException("window $offset+$length out of section (size=${bytes.size})")
        return Binary(bytes, offset, length, endian)
    }
}

enum class Endian { LITTLE, BIG }

class DwarfReadException(message: String) : RuntimeException(message)

/**
 * 引用跳转账本：ref4/ref_addr/str_offsets/addrx 等间接访问统一在此登记，
 * 防止恶意/损坏 section 通过循环引用造成无限跳转。
 */
class JumpBudget(private val maxJumps: Int = 4096) {
    private var used = 0
    fun jump() {
        if (++used > maxJumps) throw DwarfReadException("reference jump budget exceeded ($maxJumps)")
    }
}
