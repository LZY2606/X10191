package compass.dwarf

/** Bounds-checked little/big endian byte cursor with hard length limits. */
class Cursor(
    val data: ByteArray,
    var pos: Int,
    val end: Int,
    val littleEndian: Boolean = true,
) {
    class ParseException(message: String) : Exception(message)

    val remaining: Int get() = end - pos
    fun exhausted(): Boolean = pos >= end

    fun require(n: Int, what: String) {
        if (n < 0 || pos + n > end) throw ParseException("unexpected end while reading $what at 0x${pos.toString(16)}")
    }

    fun u8(what: String = "u8"): Int {
        require(1, what); return data[pos++].toInt() and 0xFF
    }

    fun i8(what: String = "i8"): Int = u8(what).toByte().toInt()

    fun u16(what: String = "u16"): Int {
        require(2, what)
        val b0 = data[pos].toInt() and 0xFF; val b1 = data[pos + 1].toInt() and 0xFF
        pos += 2
        return if (littleEndian) b0 or (b1 shl 8) else (b0 shl 8) or b1
    }

    fun u32(what: String = "u32"): Long {
        require(4, what)
        var v = 0L
        if (littleEndian) for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        else for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        pos += 4
        return v
    }

    fun u64(what: String = "u64"): Long {
        require(8, what)
        var v = 0L
        if (littleEndian) for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        else for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        pos += 8
        return v
    }

    fun uleb(what: String = "uleb128"): Long {
        var result = 0L; var shift = 0; var count = 0
        while (true) {
            val b = u8(what)
            count++
            if (count > 10) throw ParseException("uleb128 too long at 0x${pos.toString(16)}")
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
        }
        return result
    }

    fun sleb(what: String = "sleb128"): Long {
        var result = 0L; var shift = 0; var count = 0
        while (true) {
            val b = u8(what)
            count++
            if (count > 10) throw ParseException("sleb128 too long at 0x${pos.toString(16)}")
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                break
            }
        }
        return result
    }

    fun bytes(n: Int, what: String = "bytes"): ByteArray {
        require(n, what)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun cstring(what: String = "cstring"): String {
        val start = pos
        while (pos < end && data[pos].toInt() != 0) pos++
        if (pos >= end) throw ParseException("unterminated string at 0x${start.toString(16)}")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun seek(newPos: Int, what: String = "seek") {
        if (newPos < 0 || newPos > end) throw ParseException("$what out of bounds: 0x${newPos.toString(16)}")
        pos = newPos
    }

    fun slice(start: Int, length: Int): Cursor {
        if (start < 0 || length < 0 || start + length > end) throw ParseException("slice out of bounds")
        return Cursor(data, start, start + length, littleEndian)
    }
}

object Limits {
    const val MAX_DEPTH = 128
    const val MAX_DIES_PER_CU = 200_000
    const val MAX_ATTRS_PER_DIE = 1_024
    const val MAX_LINE_ROWS = 2_000_000
    const val MAX_RANGES = 500_000
    const val MAX_ABBREV_ATTRS = 4_096
    const val MAX_SECTION_SIZE = 512L * 1024 * 1024
}
