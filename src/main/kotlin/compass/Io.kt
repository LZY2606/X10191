package compass

/** Bounds-checked little-endian cursor over a byte array. */
class Reader(val bytes: ByteArray, var off: Int = 0) {
    class Truncated(msg: String) : Exception(msg)

    val size: Int get() = bytes.size
    fun remaining(): Int = bytes.size - off
    fun seek(pos: Int) {
        if (pos < 0 || pos > bytes.size) throw Truncated("seek out of bounds: $pos")
        off = pos
    }
    private fun need(n: Int) {
        if (n < 0 || off + n > bytes.size) throw Truncated("need $n bytes at $off, size ${bytes.size}")
    }
    fun u8(): Int { need(1); return bytes[off++].toInt() and 0xFF }
    fun i8(): Int = u8().toByte().toInt()
    fun u16(): Int { need(2); val v = (bytes[off].toInt() and 0xFF) or ((bytes[off + 1].toInt() and 0xFF) shl 8); off += 2; return v }
    fun u32(): Long {
        need(4)
        var v = 0L
        for (i in 0..3) v = v or ((bytes[off + i].toLong() and 0xFF) shl (8 * i))
        off += 4
        return v
    }
    fun u64(): Long {
        need(8)
        var v = 0L
        for (i in 0..7) v = v or ((bytes[off + i].toLong() and 0xFF) shl (8 * i))
        off += 8
        return v
    }
    fun uleb(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 63) throw Truncated("uleb128 too long")
        }
        return result
    }
    fun sleb(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                break
            }
            if (shift > 63) throw Truncated("sleb128 too long")
        }
        return result
    }
    fun cstr(): String {
        val sb = StringBuilder()
        while (true) {
            val b = u8()
            if (b == 0) break
            sb.append(b.toChar())
        }
        return sb.toString()
    }
    fun bytes(n: Int): ByteArray { need(n); val v = bytes.copyOfRange(off, off + n); off += n; return v }
    fun addr(size: Int): Long = when (size) {
        4 -> u32()
        8 -> u64()
        2 -> u16().toLong()
        else -> throw Truncated("unsupported address size $size")
    }
}
