package compass

/** Bounds-checked little/big-endian cursor. Any overrun throws DwarfTruncated so the
 *  caller can degrade the current unit instead of producing misaligned garbage. */
class DwarfTruncated(msg: String) : Exception(msg)

class Cursor(val buf: ByteArray, var pos: Int, val end: Int, val little: Boolean = true) {
    init { require(pos in 0..end && end <= buf.size) { "cursor bounds invalid" } }

    fun remaining(): Int = end - pos
    fun hasRemaining(): Boolean = pos < end

    private fun need(n: Int) {
        if (n < 0 || pos + n > end) throw DwarfTruncated("need $n bytes at $pos, only ${end - pos} left")
    }

    fun u8(): Int { need(1); return buf[pos++].toInt() and 0xFF }
    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        need(2)
        val v = if (little) (buf[pos].toInt() and 0xFF) or ((buf[pos + 1].toInt() and 0xFF) shl 8)
        else ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
        pos += 2; return v
    }

    fun u32(): Long {
        need(4)
        var v = 0L
        if (little) for (i in 3 downTo 0) v = (v shl 8) or (buf[pos + i].toLong() and 0xFF)
        else for (i in 0..3) v = (v shl 8) or (buf[pos + i].toLong() and 0xFF)
        pos += 4; return v
    }

    fun u64(): Long {
        need(8)
        var v = 0L
        if (little) for (i in 7 downTo 0) v = (v shl 8) or (buf[pos + i].toLong() and 0xFF)
        else for (i in 0..7) v = (v shl 8) or (buf[pos + i].toLong() and 0xFF)
        pos += 8; return v
    }

    fun u32Or64(is64: Boolean): Long = if (is64) u64() else u32()

    fun uleb(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            if (shift >= 64 && (b and 0x7f) != 0) throw DwarfTruncated("uleb128 overflow at $pos")
            result = result or ((b.toLong() and 0x7f) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 70) throw DwarfTruncated("uleb128 too long at $pos")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                break
            }
            if (shift > 70) throw DwarfTruncated("sleb128 too long at $pos")
        }
        return result
    }

    fun bytes(n: Int): ByteArray { need(n); val out = buf.copyOfRange(pos, pos + n); pos += n; return out }

    fun cstring(): String {
        val start = pos
        while (pos < end && buf[pos] != 0.toByte()) pos++
        if (pos >= end) throw DwarfTruncated("unterminated string at $start")
        val s = String(buf, start, pos - start, Charsets.UTF_8)
        pos++ // skip NUL
        return s
    }

    fun cstringAt(offset: Long): String? {
        if (offset < 0 || offset >= end) return null
        val save = pos
        pos = offset.toInt()
        val s = try { cstring() } catch (e: DwarfTruncated) { null }
        pos = save
        return s
    }
}
