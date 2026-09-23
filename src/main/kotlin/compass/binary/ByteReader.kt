package compass.binary

/** Raised when a debug section cannot be decoded safely at or after the current cursor. */
class DwarfCorruptException(message: String) : RuntimeException(message)

/**
 * Bounded little/big endian reader. Every access is bounds-checked so that a truncated or
 * malicious section never walks the cursor past the end of the buffer.
 */
class ByteReader(val data: ByteArray, private val le: Boolean = true, start: Int = 0) {
    var pos: Int = start
        private set

    val remaining: Int get() = data.size - pos

    fun seek(p: Int) {
        if (p < 0 || p > data.size) throw DwarfCorruptException("seek out of bounds: $p > ${data.size}")
        pos = p
    }

    fun skip(n: Int) = seek(pos + n)

    inline fun <T> at(p: Int, block: () -> T): T {
        val saved = pos
        seek(p)
        try {
            return block()
        } finally {
            pos = saved
        }
    }

    fun ensure(n: Int) {
        if (n < 0 || pos.toLong() + n > data.size.toLong()) {
            throw DwarfCorruptException("unexpected end of data at offset $pos (need $n bytes, have ${data.size - pos})")
        }
    }

    fun u8(): Int {
        ensure(1)
        return data[pos++].toInt() and 0xff
    }

    fun u16(): Int {
        ensure(2)
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (le) (b shl 8) or a else (a shl 8) or b
    }

    fun u32(): Long {
        ensure(4)
        var v = 0L
        if (le) {
            for (i in 0 until 4) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 0 until 4) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }

    fun i32(): Int = u32().toInt()

    fun u64(): Long {
        ensure(8)
        var v = 0L
        if (le) {
            for (i in 0 until 8) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 0 until 8) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    fun word(bytes: Int): Long = when (bytes) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw DwarfCorruptException("unsupported address width $bytes")
    }

    fun bytes(n: Int): ByteArray {
        ensure(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun cstring(limit: Int = data.size): String {
        val start = pos
        var end = pos
        while (end < limit && data[end].toInt() != 0) end++
        if (end >= limit) throw DwarfCorruptException("unterminated string starting at $start")
        val s = String(data, start, end - start, Charsets.UTF_8)
        pos = end + 1
        return s
    }

    fun uleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            val b = u8()
            count++
            if (count > maxBytes) throw DwarfCorruptException("ULEB128 too long")
            if (shift < 64) result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        return result
    }

    fun sleb(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var count = 0
        var b = 0
        while (true) {
            b = u8()
            count++
            if (count > maxBytes) throw DwarfCorruptException("SLEB128 too long")
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-(1L shl shift))
        return result
    }
}
