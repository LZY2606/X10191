package compass.dwarf

class DwarfParseException(message: String) : Exception(message)
class UnknownFormException(val form: Int, message: String) : Exception(message)

/** Bounds-checked cursor over a byte slice. Every read validates the limit so a
 *  corrupt section can never push the cursor out of alignment silently. */
class ByteReader(
    val data: ByteArray,
    var pos: Int = 0,
    val limit: Int = data.size,
    val bigEndian: Boolean = false
) {
    fun remaining(): Int = limit - pos

    private fun require(n: Int) {
        if (n < 0 || pos < 0 || pos + n > limit || pos + n < pos) {
            throw DwarfParseException("read of $n bytes at $pos exceeds limit $limit")
        }
    }

    fun u1(): Int { require(1); return data[pos++].toInt() and 0xFF }
    fun i1(): Int = u1().toByte().toInt()

    fun u2(): Int {
        require(2)
        val v = if (bigEndian) {
            (data[pos].toInt() and 0xFF shl 8) or (data[pos + 1].toInt() and 0xFF)
        } else {
            (data[pos].toInt() and 0xFF) or (data[pos + 1].toInt() and 0xFF shl 8)
        }
        pos += 2
        return v
    }

    fun u4(): Long {
        require(4)
        var v = 0L
        if (bigEndian) {
            for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        } else {
            for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        }
        pos += 4
        return v
    }

    fun u8(): Long {
        require(8)
        var v = 0L
        if (bigEndian) {
            for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        } else {
            for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        }
        pos += 8
        return v
    }

    fun uint(size: Int): Long = when (size) {
        1 -> u1().toLong()
        2 -> u2().toLong()
        4 -> u4()
        8 -> u8()
        else -> throw DwarfParseException("unsupported uint size $size")
    }

    fun uleb128(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u1()
            if (shift >= 64 && (b and 0x7F) != 0) throw DwarfParseException("uleb128 overflow at $pos")
            result = result or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift > 70) throw DwarfParseException("uleb128 too long at $pos")
        }
    }

    fun sleb128(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u1()
            result = result or ((b and 0x7F).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
            if (shift > 70) throw DwarfParseException("sleb128 too long at $pos")
        }
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun cstring(): String {
        val start = pos
        var end = pos
        while (true) {
            require(1)
            if (data[end].toInt() == 0) break
            end++
            pos++
        }
        pos++ // consume NUL
        return String(data, start, end - start, Charsets.UTF_8)
    }

    fun slice(pos: Int, limit: Int): ByteReader {
        if (pos < 0 || limit < pos || limit > this.limit) {
            throw DwarfParseException("bad slice $pos..$limit within $limit")
        }
        return ByteReader(data, pos, limit, bigEndian)
    }
}
