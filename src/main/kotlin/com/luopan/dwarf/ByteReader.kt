package com.luopan.dwarf

import java.nio.ByteBuffer
import java.nio.ByteOrder

class BoundsException(message: String) : RuntimeException(message)

class ByteReader(
    val data: ByteArray,
    val endian: Endianness = Endianness.LE,
    val startOffset: Int = 0,
    val endOffset: Int = data.size,
) {
    var pos: Int = startOffset

    val order: ByteOrder get() = if (endian == Endianness.LE) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN

    init {
        require(startOffset in 0..endOffset && endOffset <= data.size) { "bad reader window" }
    }

    val remaining: Int get() = endOffset - pos
    fun seek(p: Int) {
        if (p < startOffset || p > endOffset) throw BoundsException("seek out of bounds: $p window=[$startOffset,$endOffset)")
        pos = p
    }

    fun require(n: Int) {
        if (n < 0 || pos + n > endOffset) {
            throw BoundsException("read past bounds: pos=$pos need=$n end=$endOffset")
        }
    }

    fun u1(): Int { require(1); return data[pos++].toInt() and 0xff }
    fun i1(): Int { require(1); return data[pos++].toInt() }
    fun u2(): Int { require(2); val v = ByteBuffer.wrap(data, pos, 2).order(order).short; pos += 2; return v.toInt() and 0xffff }
    fun i2(): Int { require(2); val v = ByteBuffer.wrap(data, pos, 2).order(order).short; pos += 2; return v.toInt() }
    fun u4(): Long { require(4); val v = ByteBuffer.wrap(data, pos, 4).order(order).int; pos += 4; return v.toLong() and 0xffffffffL }
    fun i4(): Int { require(4); val v = ByteBuffer.wrap(data, pos, 4).order(order).int; pos += 4; return v }
    fun u8(): Long { require(8); val v = ByteBuffer.wrap(data, pos, 8).order(order).long; pos += 8; return v }
    fun bytes(n: Int): ByteArray { require(n); val out = data.copyOfRange(pos, pos + n); pos += n; return out }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (++count > Limits.MAX_LEB128_BYTES) throw BoundsException("uleb128 too long")
            val b = u1()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift > 63) throw BoundsException("uleb128 overflow")
        }
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        var count = 0
        while (true) {
            if (++count > Limits.MAX_LEB128_BYTES) throw BoundsException("sleb128 too long")
            b = u1()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift > 63) throw BoundsException("sleb128 overflow")
        }
        if (shift < 64 && b and 0x40 != 0) {
            result = result or (-(1L shl shift))
        }
        return result
    }

    fun cString(): String {
        val begin = pos
        while (pos < endOffset && data[pos].toInt() != 0) pos++
        if (pos >= endOffset) throw BoundsException("unterminated c-string")
        val out = String(data, begin, pos - begin, Charsets.UTF_8)
        pos++
        return out
    }

    fun cStringAt(abs: Int): String {
        if (abs < 0 || abs >= endOffset) throw BoundsException("cstring offset out of bounds: $abs")
        var p = abs
        while (p < endOffset && data[p].toInt() != 0) p++
        if (p >= endOffset) throw BoundsException("unterminated c-string at $abs")
        return String(data, abs, p - abs, Charsets.UTF_8)
    }

    fun window(start: Int, end: Int): ByteReader {
        if (start < 0 || end < start || end > data.size) throw BoundsException("bad sub-window: [$start,$end)")
        return ByteReader(data, endian, start, end)
    }

    fun sliceAt(start: Int, size: Int): ByteArray {
        if (start < 0 || size < 0 || start + size > data.size) throw BoundsException("slice out of bounds")
        return data.copyOfRange(start, start + size)
    }
}

object Limits {
    const val MAX_LEB128_BYTES = 16
    const val MAX_RECURSION = 200
    const val MAX_REF_HOPS = 64
    const val MAX_FORM_PER_DIE = 1024
    const val MAX_DIES_PER_CU = 2_000_000
    const val MAX_ROWS_PER_PROGRAM = 2_000_000
    const val MAX_RANGES = 1_000_000
    const val MAX_CUS = 200_000
    const val MAX_ABBREV_TABLES = 10_000
    const val MAX_LINE_PROGRAMS = 200_000
    const val MAX_FILE_NAME_BYTES = 4096
    const val MAX_SECTION_BYTES_STORED = 512L * 1024 * 1024
}
