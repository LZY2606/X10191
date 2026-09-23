package compass.dwarf

open class DwarfException(msg: String) : Exception(msg)
class UnknownFormException(val form: Int) : DwarfException("unknown DW_FORM 0x${form.toString(16)}")
class LimitExceededException(msg: String) : DwarfException(msg)

/** Hard safety limits so corrupt sections cannot hang or crash the parser. */
data class DwarfLimits(
    val maxDieDepth: Int = 64,
    val maxDiesPerUnit: Int = 200_000,
    val maxAttrsPerDie: Int = 1_024,
    val maxLineRows: Int = 1_000_000,
    val maxAbbrevAttrs: Int = 4_096,
    val maxLebBytes: Int = 10,
    val maxIndirect: Int = 2,
)

/** Bounds-checked cursor over a section byte range. Never reads past [end]. */
class Cursor(
    val bytes: ByteArray,
    var pos: Int,
    val end: Int = bytes.size,
    val littleEndian: Boolean = true,
) {
    init { require(pos in 0..end && end <= bytes.size) { "cursor bounds invalid" } }

    fun remaining(): Int = end - pos
    fun exhausted(): Boolean = pos >= end

    fun require(n: Int) {
        if (n < 0 || pos > end - n) throw DwarfException("cursor overrun at 0x${pos.toString(16)} need $n bytes, section end 0x${end.toString(16)}")
    }

    fun skip(n: Int) { require(n); pos += n }

    fun u8(): Int { require(1); return bytes[pos++].toInt() and 0xFF }

    fun u16(): Int {
        require(2)
        val b0 = bytes[pos].toInt() and 0xFF
        val b1 = bytes[pos + 1].toInt() and 0xFF
        pos += 2
        return if (littleEndian) b0 or (b1 shl 8) else (b0 shl 8) or b1
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        if (littleEndian) for (i in 3 downTo 0) v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
        else for (i in 0..3) v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
        pos += 4
        return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        if (littleEndian) for (i in 7 downTo 0) v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
        else for (i in 0..7) v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
        pos += 8
        return v
    }

    fun usize(n: Int): Long = when (n) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw DwarfException("unsupported int size $n")
    }

    fun uleb(limits: DwarfLimits = DwarfLimits()): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (count >= limits.maxLebBytes) throw LimitExceededException("ULEB128 too long at 0x${pos.toString(16)}")
            val b = u8()
            count++
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
        }
        return result
    }

    fun sleb(limits: DwarfLimits = DwarfLimits()): Long {
        var result = 0L
        var shift = 0
        var count = 0
        var b: Int
        while (true) {
            if (count >= limits.maxLebBytes) throw LimitExceededException("SLEB128 too long at 0x${pos.toString(16)}")
            b = u8()
            count++
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
        return result
    }

    fun bytes(n: Int): ByteArray { require(n); val r = bytes.copyOfRange(pos, pos + n); pos += n; return r }

    fun cstring(): String {
        var endPos = pos
        while (endPos < end && bytes[endPos] != 0.toByte()) endPos++
        if (endPos >= end) throw DwarfException("unterminated string at 0x${pos.toString(16)}")
        val s = String(bytes, pos, endPos - pos, Charsets.UTF_8)
        pos = endPos + 1
        return s
    }

    fun clone(): Cursor = Cursor(bytes, pos, end, littleEndian)
}
