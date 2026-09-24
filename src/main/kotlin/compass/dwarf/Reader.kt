package compass.dwarf

open class DwarfException(msg: String) : Exception(msg)
class UnknownFormException(val form: Long, msg: String) : DwarfException(msg)

/** 有界字节游标:所有读取都做边界检查,越界即抛异常,绝不让游标悄悄错位。 */
class Reader(val bytes: ByteArray, val littleEndian: Boolean = true, var pos: Int = 0, val limit: Int = bytes.size) {
    init { require(limit <= bytes.size) { "limit 越界" } }

    val remaining: Int get() = limit - pos
    fun exhausted() = pos >= limit

    fun seek(p: Int) {
        if (p < 0 || p > limit) throw DwarfException("seek 越界: $p (limit=$limit)")
        pos = p
    }

    fun u8(): Int { check(1); return bytes[pos++].toInt() and 0xff }
    fun u8At(p: Int): Int { if (p < 0 || p + 1 > limit) throw DwarfException("u8 越界 @$p"); return bytes[p].toInt() and 0xff }

    fun u16(): Int { val v = u16At(pos); pos += 2; return v }
    fun u16At(p: Int): Int {
        if (p < 0 || p + 2 > limit) throw DwarfException("u16 越界 @$p")
        val b0 = bytes[p].toInt() and 0xff; val b1 = bytes[p + 1].toInt() and 0xff
        return if (littleEndian) b0 or (b1 shl 8) else (b0 shl 8) or b1
    }

    fun u32(): Long { val v = u32At(pos); pos += 4; return v }
    fun u32At(p: Int): Long {
        if (p < 0 || p + 4 > limit) throw DwarfException("u32 越界 @$p")
        var v = 0L
        if (littleEndian) for (i in 3 downTo 0) v = (v shl 8) or (bytes[p + i].toLong() and 0xff)
        else for (i in 0..3) v = (v shl 8) or (bytes[p + i].toLong() and 0xff)
        return v
    }

    fun u64(): Long { val v = u64At(pos); pos += 8; return v }
    fun u64At(p: Int): Long {
        if (p < 0 || p + 8 > limit) throw DwarfException("u64 越界 @$p")
        var v = 0L
        if (littleEndian) for (i in 7 downTo 0) v = (v shl 8) or (bytes[p + i].toLong() and 0xff)
        else for (i in 0..7) v = (v shl 8) or (bytes[p + i].toLong() and 0xff)
        return v
    }

    fun uleb(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            if (shift >= 64 && (b and 0x7f) != 0) throw DwarfException("uleb128 溢出")
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift > 70) throw DwarfException("uleb128 过长")
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
            if (shift > 70) throw DwarfException("sleb128 过长")
        }
        return result
    }

    fun bytes(n: Int): ByteArray {
        check(n)
        val out = bytes.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun cstring(): String {
        val sb = StringBuilder()
        while (true) {
            val b = u8()
            if (b == 0) break
            sb.append(b.toChar())
        }
        return sb.toString()
    }

    /** 读取 DWARF initial length:返回 (unitLength, offsetSize)。 */
    fun initialLength(): Pair<Long, Int> {
        val w = u32()
        return if (w == 0xffffffffL) Pair(u64(), 8) else Pair(w, 4)
    }

    fun addr(addrSize: Int): Long = when (addrSize) {
        4 -> u32()
        8 -> u64()
        2 -> u16().toLong()
        else -> throw DwarfException("非法 address size $addrSize")
    }

    private fun check(n: Int) {
        if (n < 0 || pos + n > limit) throw DwarfException("读取越界: pos=$pos n=$n limit=$limit")
    }
}
