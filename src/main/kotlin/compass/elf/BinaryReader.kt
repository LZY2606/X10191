package compass.elf

import java.nio.ByteOrder

/**
 * Safe cursor over a byte array. Every access is bounds-checked: out-of-range
 * reads throw [ByteTruncatedException] so callers can isolate a bad section
 * instead of silently producing bogus values.
 */
class BinaryReader(
    val data: ByteArray,
    var pos: Int = 0,
    var order: ByteOrder = ByteOrder.LITTLE_ENDIAN
) {
    val size: Int get() = data.size
    val remaining: Int get() = data.size - pos
    fun seek(p: Int) {
        if (p < 0 || p > data.size) throw ByteTruncatedException("seek to $p (size=${data.size})")
        pos = p
    }

    fun require(n: Int) {
        if (pos + n > data.size || pos + n < 0)
            throw ByteTruncatedException("need $n bytes at $pos, only $remaining remain")
    }

    fun u8(): Int { require(1); return data[pos++].toInt() and 0xff }
    fun s8(): Int { require(1); return data[pos++].toInt() }

    fun u16(): Int {
        require(2)
        val b0 = data[pos].toInt() and 0xff
        val b1 = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (order == ByteOrder.LITTLE_ENDIAN) (b1 shl 8) or b0 else (b0 shl 8) or b1
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        if (order == ByteOrder.LITTLE_ENDIAN) {
            for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }

    fun s32(): Int = u32().toInt()
    fun u64(): Long {
        require(8)
        var v = 0L
        if (order == ByteOrder.LITTLE_ENDIAN) {
            for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
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

    /** Zero terminated string; returns "" and advances to end on truncation. */
    fun cString(): String {
        val start = pos
        var end = start
        while (end < data.size && data[end].toInt() != 0) end++
        val s = String(data, start, end - start, Charsets.UTF_8)
        pos = if (end < data.size) end + 1 else data.size
        return s
    }

    fun uleb128(): Long = readUleb(this)
    fun sleb128(): Long = readSleb(this)

    fun sliceAt(offset: Int, length: Int? = null): BinaryReader {
        val end = if (length == null) data.size else offset + length
        if (offset < 0 || end > data.size || (length != null && length < 0))
            throw ByteTruncatedException("slice [$offset,$end) out of [0,${data.size})")
        return BinaryReader(data, offset, order)
    }

    /** A bounded sub-reader that cannot escape its window. */
    fun window(offset: Int, length: Int): BinaryReader {
        if (offset < 0 || length < 0 || offset + length > data.size)
            throw ByteTruncatedException("window [$offset,+$length) out of [0,${data.size})")
        return BinaryReader(data.copyOfRange(offset, offset + length), 0, order)
    }
}

class ByteTruncatedException(message: String) : RuntimeException(message)

fun readUleb(r: BinaryReader): Long {
    var result = 0L
    var shift = 0
    var count = 0
    while (true) {
        if (++count > 16) throw ByteTruncatedException("ULEB128 too long at ${r.pos}")
        val b = r.u8()
        result = result or ((b and 0x7f).toLong() shl shift)
        if (b and 0x80 == 0) break
        shift += 7
        if (shift >= 64) throw ByteTruncatedException("ULEB128 overflow")
    }
    return result
}

fun readSleb(r: BinaryReader): Long {
    var result = 0L
    var shift = 0
    var b = 0
    var count = 0
    while (true) {
        if (++count > 16) throw ByteTruncatedException("SLEB128 too long at ${r.pos}")
        b = r.u8()
        result = result or ((b and 0x7f).toLong() shl shift)
        shift += 7
        if (b and 0x80 == 0) break
        if (shift >= 64) throw ByteTruncatedException("SLEB128 overflow")
    }
    if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
    return result
}
