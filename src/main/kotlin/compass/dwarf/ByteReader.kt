package compass.dwarf

import compass.model.BoundsException
import compass.model.Endian
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 定长缓冲读取器：所有读取都显式声明边界（section 边界 / CU 边界）。
 * 超出范围抛 [BoundsException]，由上层按 CU 隔离，绝不静默继续。
 */
class ByteReader(private val data: ByteArray, val base: Int = 0, val length: Int = data.size - base) {
    var pos: Int = 0
        private set

    val remaining: Int get() = length - pos

    fun seek(off: Int) {
        if (off < 0 || off > length) throw BoundsException("seek $off out of [0,$length]")
        pos = off
    }

    fun require(n: Int) {
        if (n < 0 || pos + n > length)
            throw BoundsException("need $n bytes at $pos in section of $length")
    }

    fun readByte(): Int {
        require(1)
        return data[base + pos++].toInt() and 0xff
    }

    fun readBytes(n: Int): ByteArray {
        require(n)
        val out = data.copyOfRange(base + pos, base + pos + n)
        pos += n
        return out
    }

    fun readU16(endian: Endian): Int {
        require(2)
        var v = 0
        if (endian == Endian.LITTLE) {
            v = (data[base + pos].toInt() and 0xff) or ((data[base + pos + 1].toInt() and 0xff) shl 8)
        } else {
            v = ((data[base + pos].toInt() and 0xff) shl 8) or (data[base + pos + 1].toInt() and 0xff)
        }
        pos += 2
        return v
    }

    fun readU32(endian: Endian): Long {
        require(4)
        var v = 0L
        repeat(4) { i ->
            val b = data[base + pos + i].toInt() and 0xff
            v = v or (b.toLong() shl (8 * if (endian == Endian.LITTLE) i else 3 - i))
        }
        pos += 4
        return v and 0xffffffffL
    }

    fun readU64(endian: Endian): Long {
        require(8)
        var v = 0L
        repeat(8) { i ->
            val b = data[base + pos + i].toInt() and 0xff
            v = v or (b.toLong() shl (8 * if (endian == Endian.LITTLE) i else 7 - i))
        }
        pos += 8
        return v
    }

    fun readAddress(size: Int, endian: Endian): Long = when (size) {
        1 -> readByte().toLong()
        2 -> readU16(endian).toLong()
        4 -> readU32(endian)
        8 -> readU64(endian)
        else -> throw BoundsException("bad address size $size")
    }

    fun readBytesOf(size: Int, endian: Endian): Long = when (size) {
        4 -> readU32(endian)
        8 -> readU64(endian)
        else -> throw BoundsException("bad dwarf offset size $size")
    }

    fun readULEB128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        while (true) {
            if (++n > maxBytes) throw BoundsException("uleb128 too long")
            val b = readByte()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw BoundsException("uleb128 overflow")
        }
        return result
    }

    fun readSLEB128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        var b = 0
        while (true) {
            if (++n > maxBytes) throw BoundsException("sleb128 too long")
            b = readByte()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw BoundsException("sleb128 overflow")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    /** 以 NUL 结尾的字符串；不返回 NUL。 */
    fun readNullTerminated(): String {
        val start = pos
        while (pos < length && data[base + pos].toInt() != 0) pos++
        if (pos >= length) throw BoundsException("unterminated string at $start")
        val s = String(data, base + start, pos - start, Charsets.UTF_8)
        pos++ // skip NUL
        return s
    }

    fun slice(start: Int, len: Int): ByteReader {
        if (start < 0 || len < 0 || start + len > length)
            throw BoundsException("slice [$start,$start+${len}) out of [0,$length]")
        return ByteReader(data, base + start, len)
    }

    /** 32/64 位 DWARF 初始长度：返回 (内容长度, 格式 32|64, 内容起点)。 */
    fun readInitialLength(endian: Endian): Triple<Long, Int, Int> {
        val first = readU32(endian)
        if (first == 0xffffffffL) {
            val len64 = readU64(endian)
            return Triple(len64, 64, pos)
        }
        return Triple(first, 32, pos)
    }
}

fun ByteArray.hexView(max: Int = 16): String {
    val n = minOf(size, max)
    val sb = StringBuilder()
    for (i in 0 until n) sb.append(String.format("%02x", this[i].toInt() and 0xff))
    return sb.toString()
}

fun longToBytes(v: Long, endian: Endian, size: Int): ByteArray {
    val bb = ByteBuffer.allocate(size)
    bb.order(if (endian == Endian.LITTLE) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
    if (size == 8) bb.putLong(v) else bb.putInt(v.toInt())
    return bb.array()
}
