package compass.dwarf

class DwarfException(message: String) : Exception(message)
class UnknownFormException(val form: Int) : DwarfException("unknown DW_FORM 0x${form.toString(16)}")

/** Bounds-checked little/big-endian cursor over a section's bytes. */
class Reader(val data: ByteArray, val sectionName: String = "?", var pos: Int = 0, val bigEndian: Boolean = false) {
    val size: Int get() = data.size
    fun remaining(): Int = size - pos
    fun eof(): Boolean = pos >= size

    fun require(n: Int) {
        if (n < 0 || pos + n > size) throw DwarfException("section $sectionName: read of $n bytes at 0x${pos.toString(16)} out of bounds (size 0x${size.toString(16)})")
    }

    fun seek(p: Int) {
        if (p < 0 || p > size) throw DwarfException("section $sectionName: seek to 0x${p.toString(16)} out of bounds")
        pos = p
    }

    fun u8(): Int { require(1); return data[pos++].toInt() and 0xFF }
    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        require(2)
        val b0 = data[pos].toInt() and 0xFF; val b1 = data[pos + 1].toInt() and 0xFF
        pos += 2
        return if (bigEndian) (b0 shl 8) or b1 else (b1 shl 8) or b0
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        if (bigEndian) { for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xFF) }
        else { for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF) }
        pos += 4
        return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        if (bigEndian) { for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xFF) }
        else { for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xFF) }
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray { require(n); val r = data.copyOfRange(pos, pos + n); pos += n; return r }

    fun cstring(): String {
        var end = pos
        while (end < size && data[end] != 0.toByte()) end++
        if (end >= size) throw DwarfException("section $sectionName: unterminated string at 0x${pos.toString(16)}")
        val s = String(data, pos, end - pos, Charsets.UTF_8)
        pos = end + 1
        return s
    }

    fun cstringAt(offset: Long): String {
        if (offset < 0 || offset >= size) throw DwarfException("section $sectionName: string offset 0x${offset.toString(16)} out of bounds")
        val save = pos; pos = offset.toInt()
        val s = cstring(); pos = save
        return s
    }

    fun uleb128(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 70) throw DwarfException("section $sectionName: uleb128 too long at 0x${pos.toString(16)}")
        }
        return result
    }

    fun sleb128(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                break
            }
            if (shift > 70) throw DwarfException("section $sectionName: sleb128 too long at 0x${pos.toString(16)}")
        }
        return result
    }

    /** DWARF32/64 initial length. Returns Pair(length, is64). Cursor ends after length field. */
    fun initialLength(): Pair<Long, Boolean> {
        val w = u32()
        if (w == 0xFFFFFFFFL) return u64() to true
        if (w >= 0xFFFFFFF0L) throw DwarfException("section $sectionName: reserved initial length 0x${w.toString(16)}")
        return w to false
    }
}
