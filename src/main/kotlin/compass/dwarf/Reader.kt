package compass.dwarf

open class DwarfException(message: String) : Exception(message)
class UnknownFormException(val form: Long) : DwarfException("unknown attribute form 0x${form.toString(16)}")

/**
 * Bounds-checked cursor over a DWARF section. All reads are little/big-endian aware.
 * A read budget guards against pathological sections causing unbounded work.
 */
class Reader(
    val bytes: ByteArray,
    var pos: Int = 0,
    val limit: Int = bytes.size,
    val littleEndian: Boolean = true,
    val maxRead: Long = 1L shl 32
) {
    private var bytesRead: Long = 0

    fun remaining(): Int = limit - pos
    fun eof(): Boolean = pos >= limit

    private fun need(n: Int) {
        if (n < 0 || pos + n > limit) {
            throw DwarfException("read of $n bytes past section end at offset 0x${pos.toString(16)} (limit 0x${limit.toString(16)})")
        }
        bytesRead += n
        if (bytesRead > maxRead) throw DwarfException("read budget exceeded")
    }

    fun u8(): Int {
        need(1)
        return bytes[pos++].toInt() and 0xFF
    }

    fun u16(): Int {
        need(2)
        val b = bytes
        val v = if (littleEndian) {
            (b[pos].toInt() and 0xFF) or ((b[pos + 1].toInt() and 0xFF) shl 8)
        } else {
            ((b[pos].toInt() and 0xFF) shl 8) or (b[pos + 1].toInt() and 0xFF)
        }
        pos += 2
        return v
    }

    fun u32(): Long {
        need(4)
        val b = bytes
        var v = 0L
        if (littleEndian) {
            for (i in 3 downTo 0) v = (v shl 8) or (b[pos + i].toLong() and 0xFF)
        } else {
            for (i in 0..3) v = (v shl 8) or (b[pos + i].toLong() and 0xFF)
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        need(8)
        val b = bytes
        var v = 0L
        if (littleEndian) {
            for (i in 7 downTo 0) v = (v shl 8) or (b[pos + i].toLong() and 0xFF)
        } else {
            for (i in 0..7) v = (v shl 8) or (b[pos + i].toLong() and 0xFF)
        }
        pos += 8
        return v
    }

    fun addr(addrSize: Int): Long = when (addrSize) {
        4 -> u32()
        8 -> u64()
        2 -> u16().toLong()
        else -> throw DwarfException("unsupported address size $addrSize")
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        repeat(10) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
        throw DwarfException("uleb128 too long at offset 0x${pos.toString(16)}")
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        repeat(10) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
        }
        throw DwarfException("sleb128 too long at offset 0x${pos.toString(16)}")
    }

    fun bytes(n: Int): ByteArray {
        need(n)
        val out = bytes.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun cstr(): String {
        val start = pos
        while (pos < limit && bytes[pos].toInt() != 0) pos++
        if (pos >= limit) throw DwarfException("unterminated string at offset 0x${start.toString(16)}")
        val s = String(bytes, start, pos - start, Charsets.UTF_8)
        pos++ // skip NUL
        return s
    }

    fun cloneAt(newPos: Int): Reader {
        if (newPos < 0 || newPos > limit) throw DwarfException("cursor jump out of bounds: 0x${newPos.toString(16)}")
        return Reader(bytes, newPos, limit, littleEndian, maxRead)
    }
}

/** Read a bounded NUL-terminated string from an arbitrary offset of a section; null if invalid. */
fun boundedCstr(bytes: ByteArray, offset: Long): String? {
    if (offset < 0 || offset >= bytes.size) return null
    var end = offset.toInt()
    while (end < bytes.size && bytes[end].toInt() != 0) end++
    if (end >= bytes.size) return null
    return String(bytes, offset.toInt(), end - offset.toInt(), Charsets.UTF_8)
}
