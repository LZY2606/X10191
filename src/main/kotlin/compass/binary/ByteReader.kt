package compass.binary

/**
 * Bounded, little-endian cursor over a byte array.
 * Every bounds failure is fatal for the current parse unit, so corrupt
 * sections cannot make the cursor wander and emit fake records.
 */
class ByteReader(
    val data: ByteArray,
    private val base: Int = 0,
    private val limit: Int = data.size,
    var pos: Int = base,
) {
    init {
        require(base in 0..limit && limit <= data.size) { "bad reader window" }
    }

    fun remaining(): Int = limit - pos

    fun seek(p: Int) {
        if (p < base || p > limit) throw ParseException("offset 0x${p.toString(16)} outside window [0x${base.toString(16)},0x${limit.toString(16)})")
        pos = p
    }

    fun skip(n: Int) = seek(pos + n)

    fun window(offset: Int, size: Int): ByteReader {
        if (offset < 0 || size < 0 || offset.toLong() + size > data.size.toLong()) {
            throw ParseException("sub-window out of bounds: offset=0x${offset.toString(16)} size=$size total=${data.size}")
        }
        return ByteReader(data, offset, offset + size, offset)
    }

    fun u1(): Int {
        if (pos >= limit) throw ParseException("u1 past end at 0x${pos.toString(16)}")
        return data[pos++].toInt() and 0xff
    }

    fun u2(): Int {
        if (pos + 2 > limit) throw ParseException("u2 past end at 0x${pos.toString(16)}")
        val v = (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8)
        pos += 2
        return v
    }

    fun u4(): Int {
        if (pos + 4 > limit) throw ParseException("u4 past end at 0x${pos.toString(16)}")
        var v = 0
        for (i in 0 until 4) v = v or ((data[pos + i].toInt() and 0xff) shl (i * 8))
        pos += 4
        return v
    }

    fun u8(): Long {
        if (pos + 8 > limit) throw ParseException("u8 past end at 0x${pos.toString(16)}")
        var v = 0L
        for (i in 0 until 8) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8))
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray {
        if (n < 0 || pos + n > limit) throw ParseException("bytes($n) past end at 0x${pos.toString(16)}")
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun zeroString(): String {
        val start = pos
        while (pos < limit && data[pos].toInt() != 0) pos++
        if (pos >= limit) throw ParseException("unterminated string at 0x${start.toString(16)}")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun cStringAt(offset: Int): String {
        if (offset < 0 || offset >= limit) throw ParseException("string offset 0x${offset.toString(16)} out of section (size=$limit)")
        var end = offset
        while (end < limit && data[end].toInt() != 0) end++
        if (end >= limit) throw ParseException("unterminated string at 0x${offset.toString(16)}")
        return String(data, offset, end - offset, Charsets.UTF_8)
    }

    fun uleb(): Long = uleb128(this, maxBytes = 16, signed = false)
    fun sleb(): Long = sleb128(this, maxBytes = 16)
}

class ParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

internal fun uleb128(r: ByteReader, maxBytes: Int, signed: Boolean): Long {
    var result = 0L
    var shift = 0
    var i = 0
    while (true) {
        val b = r.u1()
        i++
        if (i > maxBytes) throw ParseException("uleb128 too long (> $maxBytes bytes)")
        result = result or ((b.toLong() and 0x7f) shl shift)
        if (b and 0x80 == 0) return result
        shift += 7
        if (shift >= 64) throw ParseException("uleb128 overflow")
    }
}

internal fun sleb128(r: ByteReader, maxBytes: Int): Long {
    var result = 0L
    var shift = 0
    var i = 0
    var b = 0
    while (true) {
        b = r.u1()
        i++
        if (i > maxBytes) throw ParseException("sleb128 too long (> $maxBytes bytes)")
        result = result or ((b.toLong() and 0x7f) shl shift)
        shift += 7
        if (b and 0x80 == 0) break
        if (shift >= 64) throw ParseException("sleb128 overflow")
    }
    if (shift < 64 && (b and 0x40) != 0) {
        result = result or (-1L shl shift)
    }
    return result
}

/** Small bounded writer used by fixture builders. */
class ByteWriter(initial: Int = 64) {
    var data: ByteArray = ByteArray(initial)
        private set
    var size: Int = 0
        private set

    private fun ensure(extra: Int) {
        if (size + extra <= data.size) return
        var n = data.size * 2
        if (n < size + extra) n = size + extra
        data = data.copyOf(n)
    }

    fun u1(v: Int): ByteWriter {
        ensure(1); data[size++] = (v and 0xff).toByte(); return this
    }

    fun u2(v: Int): ByteWriter {
        ensure(2)
        data[size++] = (v and 0xff).toByte()
        data[size++] = ((v ushr 8) and 0xff).toByte()
        return this
    }

    fun u4(v: Int): ByteWriter {
        ensure(4)
        for (i in 0 until 3) data[size++] = ((v ushr (i * 8)) and 0xff).toByte()
        data[size++] = ((v ushr 24) and 0xff).toByte()
        return this
    }

    fun u8(v: Long): ByteWriter {
        ensure(8)
        for (i in 0 until 7) data[size++] = ((v ushr (i * 8)) and 0xff).toByte()
        data[size++] = ((v ushr 56) and 0xff).toByte()
        return this
    }

    fun bytes(b: ByteArray): ByteWriter {
        ensure(b.size); System.arraycopy(b, 0, data, size, b.size); size += b.size; return this
    }

    fun cstring(s: String): ByteWriter = bytes(s.toByteArray(Charsets.UTF_8)).u1(0)

    fun patchU4(offset: Int, v: Int) {
        for (i in 0 until 3) data[offset + i] = ((v ushr (i * 8)) and 0xff).toByte()
        data[offset + 3] = ((v ushr 24) and 0xff).toByte()
    }

    fun patchU8(offset: Int, v: Long) {
        for (i in 0 until 7) data[offset + i] = ((v ushr (i * 8)) and 0xff).toByte()
        data[offset + 7] = ((v ushr 56) and 0xff).toByte()
    }

    fun build(): ByteArray = data.copyOf(size)

    fun position(): Int = size
}

/** ULEB128 maximum encoded length for a given bit width (5 bytes for 32-bit, 10 for 64). */
fun writeUleb(w: ByteWriter, v: Long): ByteWriter {
    var x = v
    while (true) {
        val b = (x and 0x7f).toInt()
        x = x ushr 7
        if (x == 0L) {
            w.u1(b)
            return w
        }
        w.u1(b or 0x80)
    }
}

fun writeSleb(w: ByteWriter, v: Long): ByteWriter {
    var x = v
    while (true) {
        val b = (x and 0x7f).toInt()
        val sign = b and 0x40 != 0
        x = x shr 7
        val done = (x == 0L && !sign) || (x == -1L && sign)
        if (done) {
            w.u1(b)
            return w
        }
        w.u1(b or 0x80)
    }
}
