package compass.dwarf

/** Bounds-checked cursor over a byte array. */
class Reader(
    val data: ByteArray,
    var pos: Int = 0,
    val limit: Int = data.size,
    val littleEndian: Boolean = true
) {
    fun remaining(): Int = limit - pos

    fun require(n: Int, what: String) {
        if (n < 0 || pos + n > limit) {
            throw DwarfParseException("truncated $what at offset $pos (need $n bytes, ${remaining()} left)")
        }
    }

    fun u8(): Int {
        require(1, "u8")
        return data[pos++].toInt() and 0xFF
    }

    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        require(2, "u16")
        val b0 = data[pos].toInt() and 0xFF
        val b1 = data[pos + 1].toInt() and 0xFF
        pos += 2
        return if (littleEndian) (b1 shl 8) or b0 else (b0 shl 8) or b1
    }

    fun u32(): Long {
        require(4, "u32")
        var v = 0L
        if (littleEndian) {
            for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        } else {
            for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        require(8, "u64")
        var v = 0L
        if (littleEndian) {
            for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        } else {
            for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        }
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray {
        require(n, "bytes($n)")
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            if (shift >= 64 && (b and 0x7F) != 0) throw DwarfParseException("ULEB128 overflow at offset ${pos - 1}")
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 70) throw DwarfParseException("ULEB128 too long at offset $pos")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        while (true) {
            b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (shift > 70) throw DwarfParseException("SLEB128 too long at offset $pos")
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
        return result
    }

    fun cstring(): String {
        val start = pos
        while (pos < limit && data[pos].toInt() != 0) pos++
        if (pos >= limit) throw DwarfParseException("unterminated string at offset $start")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun skip(n: Long) {
        if (n < 0 || pos + n > limit) throw DwarfParseException("skip of $n out of bounds at offset $pos")
        pos += n.toInt()
    }

    fun cloneAt(newPos: Int): Reader {
        if (newPos < 0 || newPos > limit) throw DwarfParseException("seek out of bounds: $newPos (limit $limit)")
        return Reader(data, newPos, limit, littleEndian)
    }
}

open class DwarfParseException(message: String) : Exception(message)

/** Raised when an attribute uses a FORM this build does not implement. */
class UnknownFormException(val form: Int, val attrName: String) :
    DwarfParseException("unknown DW_FORM 0x${form.toString(16)} on $attrName")

/** Raised when a defensive limit (depth / count / jump) is exceeded. */
class LimitExceededException(message: String) : DwarfParseException(message)
