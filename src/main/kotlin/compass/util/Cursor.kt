package compass.util

/** Bounds-checked cursor over a section's raw bytes. All reads fail loudly instead of producing phantom values. */
class Cursor(val data: ByteArray, var pos: Int = 0) {
    val size: Int get() = data.size
    val remaining: Int get() = data.size - pos

    fun seek(p: Int): Cursor {
        if (p < 0 || p > data.size) throw ParseException("seek out of bounds: $p / ${data.size}")
        pos = p
        return this
    }

    fun require(n: Int) {
        if (pos < 0 || n < 0 || pos + n > data.size)
            throw ParseException("unexpected end of data at $pos (need $n, have ${data.size - pos})")
    }

    fun u8(): Int { require(1); return data[pos++].toInt() and 0xff }
    fun i8(): Int { require(1); return data[pos++].toInt() }

    fun u16(): Int {
        require(2)
        val v = (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8)
        pos += 2; return v
    }

    fun i16(): Int = u16().toShort().toInt()

    fun u32(): Long {
        require(4)
        var v = 0L
        for (i in 0..3) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        pos += 4; return v
    }

    fun i32(): Int = u32().toInt()

    fun u64(): Long {
        require(8)
        var v = 0L
        for (i in 0..7) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        pos += 8; return v
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun bytesRest(): ByteArray = bytes(remaining)

    /** NUL terminated C string. */
    fun cstring(): String {
        val start = pos
        while (pos < data.size && data[pos] != 0.toByte()) pos++
        if (pos >= data.size) throw ParseException("unterminated string at $start")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun uleb128(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (count++ > MAX_LEB_BYTES) throw ParseException("ULEB128 too long at ${pos - count}")
            require(1)
            val b = data[pos++].toInt() and 0xff
            if (shift < 64) result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        return result
    }

    fun uleb128Int(): Int = uleb128().let {
        if (it < 0 || it > Int.MAX_VALUE.toLong()) throw ParseException("ULEB128 value out of int range: $it")
        it.toInt()
    }

    fun sleb128(): Long {
        var result = 0L
        var shift = 0
        var b = 0
        var count = 0
        while (true) {
            if (count++ > MAX_LEB_BYTES) throw ParseException("SLEB128 too long at ${pos - count}")
            require(1)
            b = data[pos++].toInt() and 0xff
            if (shift < 64) result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    companion object {
        const val MAX_LEB_BYTES = 10
    }
}

/** A cursor with a hard hop-count guard for section reference chasing. */
class BoundedCursor(data: ByteArray, pos: Int = 0, val maxHops: Int = 64) : Cursor(data, pos) {
    var hops: Int = 0
        private set

    fun hop(what: String = "reference") {
        if (++hops > maxHops) throw ParseException("too many $what hops (>$maxHops), possible reference cycle")
    }
}

class ParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
