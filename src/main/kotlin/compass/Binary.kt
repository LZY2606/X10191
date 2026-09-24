package compass

import java.math.BigInteger

class CursorException(message: String, val safeOffset: Long? = null) : RuntimeException(message)

class ByteReader(private val data: ByteArray, val base: Int = 0) {
    var pos: Int = base
    val length: Int get() = data.size

    constructor(bytes: ByteArray, offset: Long, size: Long) : this(slice(bytes, offset, size), 0)

    fun remaining(): Int = data.size - pos
    fun require(count: Int) {
        if (count < 0 || pos + count < pos || pos + count > data.size) throw CursorException("unexpected end of data", pos.toLong())
    }

    fun readBytes(count: Int): ByteArray {
        require(count)
        return data.copyOfRange(pos, pos + count).also { pos += count }
    }

    fun u8(): Int = readBytes(1)[0].toInt() and 0xff
    fun s8(): Int = readBytes(1)[0].toInt()
    fun u16(endian: Int): Int {
        val b = readBytes(2)
        val v = if (endian == 1) (b[0].toInt() and 255) or ((b[1].toInt() and 255) shl 8)
        else ((b[0].toInt() and 255) shl 8) or (b[1].toInt() and 255)
        return v and 0xffff
    }

    fun u32(endian: Int): Long {
        val b = readBytes(4)
        var v = 0L
        for (i in 0 until 4) {
            val byte = b[if (endian == 1) i else 3 - i].toInt() and 255
            v = (v shl 8) or byte.toLong()
        }
        return v ushr 0
    }

    fun u64(endian: Int): Long {
        val b = readBytes(8)
        var v = 0L
        for (i in 0 until 8) {
            val byte = b[if (endian == 1) i else 7 - i].toInt() and 255
            v = (v shl 8) or byte.toLong()
        }
        return v
    }

    fun uleb(maxBytes: Int = 32): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            val byte = u8()
            count++
            if (count > maxBytes) throw CursorException("ULEB128 too long", pos.toLong())
            result = result or ((byte and 0x7f).toLong() shl shift)
            if (byte and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw CursorException("ULEB128 overflow", pos.toLong())
        }
    }

    fun sleb(maxBytes: Int = 32): Long {
        var result = 0L
        var shift = 0
        var count = 0
        var byte = 0
        while (true) {
            byte = u8()
            count++
            if (count > maxBytes) throw CursorException("SLEB128 too long", pos.toLong())
            result = result or ((byte and 0x7f).toLong() shl shift)
            shift += 7
            if (byte and 0x80 == 0) break
        }
        if (shift < 64 && byte and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun uint(bytes: Int, endian: Int): Long = when (bytes) {
        1 -> u8().toLong()
        2 -> u16(endian).toLong()
        4 -> u32(endian)
        8 -> u64(endian)
        else -> throw CursorException("unsupported integer width $bytes")
    }

    fun sizedInt(bytes: Int, endian: Int, signed: Boolean): BigInteger {
        val raw = readBytes(bytes)
        val ordered = if (endian == 1) raw else raw.reversedArray()
        var v = BigInteger.ZERO
        for (b in ordered) v = (v shl 8) or BigInteger.valueOf((b.toInt() and 255).toLong())
        if (signed && ordered.isNotEmpty() && (ordered.last().toInt() and 0x80) != 0) {
            v = v - BigInteger.ONE.shiftLeft(bytes * 8)
        }
        return v
    }

    fun string(): String {
        val start = pos
        while (pos < data.size && data[pos] != 0.toByte()) pos++
        if (pos >= data.size) throw CursorException("unterminated string", start.toLong())
        val result = data.copyOfRange(start, pos).toString(Charsets.UTF_8)
        pos++
        return result
    }

    fun stringAt(offset: Long): String {
        if (offset < 0 || offset >= data.size) throw CursorException("string offset out of bounds", offset)
        pos = offset.toInt()
        return string()
    }

    fun sizedString(count: Int): String = readBytes(count).toString(Charsets.UTF_8)
}

fun sha256Hex(bytes: ByteArray): String {
    val digest = java.security.MessageDigest.getInstance("SHA-256")
    return digest.digest(bytes).joinToString("") { "%02x".format(it) }
}


private fun slice(bytes: ByteArray, offset: Long, size: Long): ByteArray {
    val end = offset + size
    if (offset < 0 || size < 0 || offset > bytes.size || end > bytes.size || end < offset) throw CursorException("range out of bounds")
    return bytes.copyOfRange(offset.toInt(), end.toInt())
}
