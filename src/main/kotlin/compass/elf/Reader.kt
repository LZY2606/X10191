package compass.elf

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Bounded, little-endian/big-endian aware cursor over a byte array.
 * Every access is bounds-checked: callers get a [ParseError] instead of
 * silent corruption when a section is truncated, so a damaged section can
 * never make the cursor drift into fabricated results.
 */
class Reader(val data: ByteArray, val order: ByteOrder, private val label: String = "data") {
    val buf: ByteBuffer = ByteBuffer.wrap(data).order(order)
    var pos: Int = 0
        private set

    fun seek(p: Int): Reader {
        if (p < 0 || p > data.size) throw ParseError("$label: seek out of bounds: $p (size=${data.size})")
        pos = p
        buf.position(p)
        return this
    }

    fun remaining(): Int = data.size - pos
    fun require(n: Int) {
        if (n < 0 || pos + n > data.size)
            throw ParseError("$label: unexpected end at $pos, need $n bytes (size=${data.size})")
    }

    fun u8(): Int { require(1); val v = buf.get().toInt() and 0xff; pos++; return v }
    fun s8(): Int { require(1); val v = buf.get().toInt(); pos++; return v }
    fun u16(): Int { require(2); val v = buf.short.toInt() and 0xffff; pos += 2; return v }
    fun u32(): Long { require(4); val v = buf.int.toLong() and 0xffffffffL; pos += 4; return v }
    fun s32(): Int { require(4); val v = buf.int; pos += 4; return v }
    fun u64(): Long { require(8); val v = buf.long; pos += 8; return v }

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = ByteArray(n)
        buf.get(out)
        pos += n
        return out
    }

    fun zeroString(): String {
        val start = pos
        while (pos < data.size && data[pos] != 0.toByte()) pos++
        if (pos >= data.size) throw ParseError("$label: unterminated string at $start")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun zeroStringAt(off: Int): String {
        if (off < 0 || off >= data.size) throw ParseError("$label: string offset $off out of bounds")
        val end = generateSequence(off) { it + 1 }.firstOrNull { it >= data.size || data[it] == 0.toByte() }
            ?: throw ParseError("$label: unterminated string at $off")
        return String(data, off, end - off, Charsets.UTF_8)
    }

    fun uleb128(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (++count > MAX_LEB_BYTES) throw ParseError("$label: uleb128 too long at $pos")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw ParseError("$label: uleb128 overflow at $pos")
        }
    }

    fun sleb128(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        var b: Int
        do {
            if (++count > MAX_LEB_BYTES) throw ParseError("$label: sleb128 too long at $pos")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
        } while (b and 0x80 != 0)
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun slice(len: Int, subLabel: String): Reader {
        val b = bytes(len)
        return Reader(b, order, "$label/$subLabel")
    }

    companion object {
        const val MAX_LEB_BYTES = 16
    }
}

class ParseError(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
