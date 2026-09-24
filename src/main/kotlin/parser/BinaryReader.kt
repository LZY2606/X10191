package parser

import java.nio.charset.StandardCharsets

class ParseException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Bounded cursor over a section's raw bytes. Every read is range checked against the
 * section end; a jump beyond the bounds throws ParseException instead of silently
 * producing garbage rows. LEB128 decoding is length-limited.
 */
class BinaryReader(private val data: ByteArray, val start: Int = 0, private val end: Int = data.size) {
    var pos: Int = start
    val size: Int get() = end - start

    fun remaining(): Int = end - pos
    fun seek(p: Int) {
        if (p < start || p > end) throw ParseException("cursor out of bounds: offset=$p section=[$start,$end)")
        pos = p
    }
    fun skip(n: Int) = seek(pos + n)
    fun atEnd(): Boolean = pos >= end

    fun u8(): Int {
        if (pos + 1 > end) throw ParseException("unexpected end of section reading u8 at $pos (end=$end)")
        return data[pos++].toInt() and 0xff
    }
    fun u16(): Int {
        if (pos + 2 > end) throw ParseException("unexpected end of section reading u16 at $pos")
        val v = (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8)
        pos += 2
        return v
    }
    fun u32(): Long {
        if (pos + 4 > end) throw ParseException("unexpected end of section reading u32 at $pos")
        var v = 0L
        for (i in 0 until 4) v = v or ((data[pos + i].toLong() and 0xff) shl (8 * i))
        pos += 4
        return v
    }
    fun u64(): Long {
        if (pos + 8 > end) throw ParseException("unexpected end of section reading u64 at $pos")
        var v = 0L
        for (i in 0 until 8) v = v or ((data[pos + i].toLong() and 0xff) shl (8 * i))
        pos += 8
        return v
    }
    fun bytes(n: Int): ByteArray {
        if (n < 0 || pos + n > end) throw ParseException("block read out of bounds: n=$n at $pos")
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }
    fun byte(n: Int): Byte {
        if (pos + n > end) throw ParseException("byte read out of bounds")
        return data[pos + n - 1]
    }
    fun readU(size: Int): Long = when (size) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw ParseException("unsupported integer size $size")
    }

    fun uleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var i = 0
        while (true) {
            if (i++ >= maxBytes) throw ParseException("ULEB128 too long at $pos")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw ParseException("ULEB128 overflow at $pos")
        }
        return result
    }

    fun sleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var i = 0
        var b = 0
        while (true) {
            if (i++ >= maxBytes) throw ParseException("SLEB128 too long at $pos")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw ParseException("SLEB128 overflow at $pos")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun cstr(): String {
        val begin = pos
        while (pos < end && data[pos].toInt() != 0) pos++
        if (pos >= end) throw ParseException("unterminated string at $begin")
        val s = String(data, begin, pos - begin, StandardCharsets.UTF_8)
        pos++ // skip NUL
        return s
    }
    fun cstrAt(off: Int): String {
        if (off < 0 || off >= end) throw ParseException("string offset out of bounds: $off")
        var p = off
        while (p < end && data[p].toInt() != 0) p++
        if (p >= end) throw ParseException("unterminated string at $off")
        return String(data, off, p - off, StandardCharsets.UTF_8)
    }
    fun cstrAtOrNull(off: Long): String? {
        if (off < 0 || off >= end) return null
        var p = off.toInt()
        while (p < end && data[p].toInt() != 0) p++
        if (p >= end) return null
        return String(data, off.toInt(), p - off.toInt(), StandardCharsets.UTF_8)
    }
    fun subReader(off: Int, len: Int): BinaryReader {
        if (off < 0 || len < 0 || off + len > end) throw ParseException("sub-reader out of bounds: off=$off len=$len")
        return BinaryReader(data, off, off + len)
    }
    fun sha256Prefix(n: Int = 32): String {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val take = minOf(n, end - start)
        md.update(data, start, take)
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
