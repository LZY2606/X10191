package com.compass.util

import java.nio.ByteOrder

/**
 * 有界字节读取器：所有读取都在声明范围内进行。
 * 越界会把持有者标记为 damaged（不抛异常打断表级游标），
 * 调用方负责在 damaged 后停止当前 compilation unit 的派生解析。
 */
class ByteReader(
    val data: ByteArray,
    val order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    val base: Int = 0,
    val limit: Int = data.size,
) {
    var pos: Int = base
    val warnings = mutableListOf<String>()
    var damaged: Boolean = false
        private set

    fun fork(start: Int, end: Int): ByteReader = ByteReader(data, order, start, end)

    fun damage(message: String): Nothing {
        if (!damaged || warnings.isEmpty() || warnings.last() != message) warnings.add(message)
        damaged = true
        throw BoundsException(message)
    }

    fun warn(message: String) {
        if (warnings.lastOrNull() != message) warnings.add(message)
    }

    fun remaining(): Int = limit - pos

    fun seek(p: Int) {
        if (p < base || p > limit) damage("seek 越界: $p 不在 [$base,$limit)")
        pos = p
    }

    fun align4() {
        val mod = (pos - base) and 3
        if (mod != 0) skip(4 - mod)
    }

    fun skip(n: Int) {
        if (n < 0 || pos + n > limit) damage("跳过 $n 字节越界")
        pos += n
    }

    fun u8(): Int {
        if (pos + 1 > limit) damage("u8 读取越界 @$pos")
        return data[pos++].toInt() and 0xff
    }

    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        if (pos + 2 > limit) damage("u16 读取越界 @$pos")
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (order == ByteOrder.LITTLE_ENDIAN) (b shl 8) or a else (a shl 8) or b
    }

    fun i16(): Int = u16().toShort().toInt()

    fun u32(): Long {
        if (pos + 4 > limit) damage("u32 读取越界 @$pos")
        var v = 0L
        if (order == ByteOrder.LITTLE_ENDIAN) {
            for (i in 0..3) v = v or ((data[pos + i].toLong() and 0xff) shl (8 * i))
        } else {
            for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }

    fun i32(): Int = u32().toInt()

    fun u64(): Long {
        if (pos + 8 > limit) damage("u64 读取越界 @$pos")
        var v = 0L
        if (order == ByteOrder.LITTLE_ENDIAN) {
            for (i in 0..7) v = v or ((data[pos + i].toLong() and 0xff) shl (8 * i))
        } else {
            for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    fun readBytes(n: Int): ByteArray {
        if (n < 0 || pos + n > limit) damage("读取 $n 字节越界 @$pos")
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun uleb(): Long = ulebCap(Int.MAX_VALUE)

    fun ulebCap(maxBytes: Int): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            val b = u8()
            count++
            if (count > maxBytes) damage("ULEB128 超长 (>$maxBytes)")
            if (count > 10) damage("ULEB128 超过 10 字节")
            result = result or ((b.toLong() and 0x7f) shl shift)
            if ((b and 0x80) == 0) break
            shift += 7
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b = 0
        var count = 0
        while (true) {
            b = u8()
            count++
            if (count > 10) damage("SLEB128 超过 10 字节")
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if ((b and 0x80) == 0) break
        }
        if ((b and 0x40) != 0 && shift < 64) result = result or (-1L shl shift)
        return result
    }

    fun cString(): String {
        val start = pos
        while (pos < limit && data[pos] != 0.toByte()) pos++
        if (pos >= limit) damage("未终止的字符串 @$start")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun sizedInt(offsetSize: Int): Long = when (offsetSize) {
        4 -> u32()
        8 -> u64()
        else -> error("非法 offsetSize=$offsetSize")
    }
}

class BoundsException(message: String) : Exception(message)

class UnknownFormException(val form: Int) : Exception("未知 DW_FORM 0x${form.toString(16)}")
