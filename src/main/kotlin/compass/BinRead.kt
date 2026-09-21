package compass

import java.nio.charset.StandardCharsets

/**
 * 有界的小端字节读取器。所有越界访问抛 [BinException]，由上层隔离损坏数据。
 */
class BinReader(val data: ByteArray, var pos: Int = 0) {
    val size: Int get() = data.size

    fun seek(p: Int) {
        if (p < 0 || p > data.size) throw BinException("越界读取 offset=$p size=${data.size}")
        pos = p
    }

    fun require(n: Int) {
        if (n < 0 || pos + n > data.size || pos + n < pos)
            throw BinException("越界读取 offset=$pos need=$n size=${data.size}")
    }

    fun u1(): Int { require(1); return data[pos].toInt() and 0xff }
    fun u2(): Int { require(2); val v = (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8); pos += 2; return v }
    fun u4(): Int {
        require(4)
        var v = 0
        for (i in 0 until 4) v = v or ((data[pos + i].toInt() and 0xff) shl (i * 8))
        pos += 4
        return v
    }

    fun u8(): Long {
        require(8)
        var v = 0L
        for (i in 0 until 8) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    /** NUL 结尾字符串（不跨出 data 末尾；若无 NUL 则读到末尾）。 */
    fun cString(): String {
        val start = pos
        var end = pos
        while (end < data.size && data[end].toInt() != 0) end++
        val s = String(data, start, end - start, StandardCharsets.UTF_8)
        pos = if (end < data.size) end + 1 else end
        return s
    }

    fun uleb128(maxBytes: Int = 16): ULong {
        var result = 0UL
        var shift = 0
        var count = 0
        while (true) {
            if (++count > maxBytes) throw BinException("ULEB128 过长（>$maxBytes 字节），数据可能损坏")
            val b = u1()
            result = result or ((b and 0x7f).toULong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw BinException("ULEB128 超过 64 位")
        }
        return result
    }

    fun sleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var b = 0
        var count = 0
        while (true) {
            if (++count > maxBytes) throw BinException("SLEB128 过长（>$maxBytes 字节），数据可能损坏")
            b = u1()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw BinException("SLEB128 超过 64 位")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun uN(width: Int): Long = when (width) {
        1 -> u1().toLong()
        2 -> u2().toLong()
        4 -> u4().toLong() and 0xffffffffL
        8 -> u8()
        else -> throw BinException("不支持的整数宽度 $width")
    }
}

class BinException(message: String, cause: Throwable? = null) : Exception(message, cause)

fun encodeUleb128(value: ULong): ByteArray {
    var v = value
    val out = java.io.ByteArrayOutputStream()
    do {
        var b = (v and 0x7fUL).toInt()
        v = v shr 7
        if (v != 0UL) b = b or 0x80
        out.write(b)
    } while (v != 0UL)
    return out.toByteArray()
}

fun encodeSleb128(value: Long): ByteArray {
    var v = value
    val out = java.io.ByteArrayOutputStream()
    while (true) {
        var b = (v and 0x7f).toInt()
        val sign = b and 0x40 != 0
        v = v shr 7
        val done = (v == 0L && !sign) || (v == -1L && sign)
        if (!done) b = b or 0x80
        out.write(b)
        if (done) break
    }
    return out.toByteArray()
}

fun u32le(v: Int): ByteArray = byteArrayOf(
    (v and 0xff).toByte(), ((v ushr 8) and 0xff).toByte(),
    ((v ushr 16) and 0xff).toByte(), ((v ushr 24) and 0xff).toByte()
)

fun u64le(v: Long): ByteArray = ByteArray(8) { i -> ((v ushr (i * 8)) and 0xff).toByte() }

fun u16le(v: Int): ByteArray = byteArrayOf((v and 0xff).toByte(), ((v ushr 8) and 0xff).toByte())
