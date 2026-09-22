package compass.elf

import java.nio.charset.StandardCharsets

/**
 * Strict, bounded reader over one byte section/array. Every read is bounds
 * checked; running past the end throws [ReadLimitExceeded] rather than
 * silently producing bogus values (which would desynchronise a cursor).
 */
class ByteReader(val data: ByteArray, val base: Int = 0, val size: Int = data.size - base) {
    var pos: Int = 0
        private set

    val remaining: Int get() = size - pos
    val atEnd: Boolean get() = remaining <= 0

    fun seek(p: Int) {
        if (p < 0 || p > size) throw ReadLimitExceeded("seek $p out of [0,$size]")
        pos = p
    }

    fun skip(n: Int) = seek(pos + n)

    private fun need(n: Int) {
        if (n < 0 || pos + n > size) throw ReadLimitExceeded("read $n bytes at $pos exceeds $size")
    }

    fun u1(): Int { need(1); return data[base + pos++].toInt() and 0xff }
    fun u2(): Int { need(2); val v = (data[base + pos].toInt() and 0xff) or ((data[base + pos + 1].toInt() and 0xff) shl 8); pos += 2; return v }
    fun u4(): Int { need(4); var v = 0; for (i in 0 until 4) v = v or ((data[base + pos + i].toInt() and 0xff) shl (8 * i)); pos += 4; return v }
    fun u8(): Long { need(8); var v = 0L; for (i in 0 until 8) v = v or ((data[base + pos + i].toLong() and 0xff) shl (8 * i)); pos += 8; return v }
    fun s4(): Int = u4()
    fun s8(): Long = u8()

    fun bytes(n: Int): ByteArray { need(n); val out = data.copyOfRange(base + pos, base + pos + n); pos += n; return out }

    fun uword(bytes: Int): Long = when (bytes) {
        1 -> u1().toLong()
        2 -> u2().toLong()
        4 -> u4().toLong() and 0xffffffffL
        8 -> u8()
        else -> error("unsupported word size $bytes")
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (++count > MAX_LEB_BYTES) throw ReadLimitExceeded("ULEB128 too long at $pos")
            val b = u1()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw ReadLimitExceeded("ULEB128 overflow at $pos")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        var count = 0
        while (true) {
            if (++count > MAX_LEB_BYTES) throw ReadLimitExceeded("SLEB128 too long at $pos")
            b = u1()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw ReadLimitExceeded("SLEB128 overflow at $pos")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    /** NUL terminated UTF-8 string; max length capped. */
    fun cString(maxLen: Int = MAX_STRING): String {
        val start = base + pos
        var end = start
        var n = 0
        while (end < base + size && data[end].toInt() != 0) {
            end++; if (++n > maxLen) throw ReadLimitExceeded("cstring too long at $pos")
        }
        if (end >= base + size) throw ReadLimitExceeded("unterminated cstring at $pos")
        pos = end - base + 1
        return String(data, start, end - start, StandardCharsets.UTF_8)
    }

    /** Fixed-length cstring read (debug_line file entries are not NUL bounded). */
    fun stringAt(abs: Int, maxLen: Int = MAX_STRING): String {
        if (abs < 0 || abs >= size) throw ReadLimitExceeded("string ref $abs out of section size $size")
        var end = abs
        var n = 0
        while (end < size && data[base + end].toInt() != 0) { end++; if (++n > maxLen) throw ReadLimitExceeded("string too long at $abs") }
        return String(data, base + abs, end - abs, StandardCharsets.UTF_8)
    }

    fun subReader(offset: Int, length: Int): ByteReader {
        if (offset < 0 || length < 0 || offset + length > size)
            throw ReadLimitExceeded("subreader [$offset,$length) exceeds $size")
        return ByteReader(data, base + offset, length)
    }

    fun save(): Int = pos
    fun restore(p: Int) { pos = p }

    companion object {
        const val MAX_LEB_BYTES = 16
        const val MAX_STRING = 1 shl 20
    }
}

class ReadLimitExceeded(message: String) : RuntimeException(message)
