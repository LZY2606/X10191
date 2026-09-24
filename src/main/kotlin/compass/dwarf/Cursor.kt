package compass.dwarf

open class DwarfException(message: String) : Exception(message)

/** 未知 FORM：可隔离当前 CU，但游标语义不允许继续解析该 CU 的后续 DIE。 */
class UnknownFormException(val form: Int) :
    DwarfException("未知 ${Dw.formName(form)} (0x${form.toString(16)})，无法确定长度，已隔离当前编译单元")

/** 解析安全限制：递归深度、条目数量、引用跳转全部有界。 */
data class Limits(
    val maxDieDepth: Int = 64,
    val maxDiesPerUnit: Int = 200_000,
    val maxAttrsPerDie: Int = 4_096,
    val maxAbbrevEntries: Int = 100_000,
    val maxLineOps: Int = 2_000_000,
    val maxStringScan: Int = 1_000_000,
    val maxRefJumps: Int = 10_000,
    val maxRangeEntries: Int = 1_000_000,
    val maxUnitsPerSection: Int = 100_000,
)

/** 有界小端游标：任何越界读取立即抛错，绝不产生伪数据。 */
class Cursor(val buf: ByteArray, start: Int, val end: Int) {
    var pos: Int = start
        private set

    constructor(buf: ByteArray) : this(buf, 0, buf.size)

    val remaining: Int get() = end - pos

    fun seek(p: Int) {
        if (p < 0 || p > end) throw DwarfException("seek 越界: pos=$p end=$end")
        pos = p
    }

    fun require(n: Int) {
        if (n < 0 || remaining < n)
            throw DwarfException("读取越界: pos=$pos 需要 $n 字节，剩余 $remaining（section 可能损坏）")
    }

    fun u8(): Int {
        require(1); return buf[pos++].toInt() and 0xff
    }

    fun u16(): Int {
        require(2)
        val v = (buf[pos].toInt() and 0xff) or ((buf[pos + 1].toInt() and 0xff) shl 8)
        pos += 2; return v
    }

    fun u24(): Int {
        require(3)
        var v = 0
        for (i in 0..2) v = v or ((buf[pos + i].toInt() and 0xff) shl (8 * i))
        pos += 3; return v
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        for (i in 0..3) v = v or ((buf[pos + i].toLong() and 0xff) shl (8 * i))
        pos += 4; return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        for (i in 0..7) v = v or ((buf[pos + i].toLong() and 0xff) shl (8 * i))
        pos += 8; return v
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val r = buf.copyOfRange(pos, pos + n)
        pos += n; return r
    }

    fun skip(n: Long) {
        if (n < 0 || n > remaining) throw DwarfException("skip 越界: $n 剩余 $remaining")
        pos += n.toInt()
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            if (shift >= 64) throw DwarfException("ULEB128 超过 64 位")
            result = result or ((b.toLong() and 0x7f) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            if (shift >= 64) throw DwarfException("SLEB128 超过 64 位")
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
        }
    }

    fun cstr(limit: Int = 1_000_000): String {
        var n = 0
        while (true) {
            if (pos + n >= end) throw DwarfException("字符串未终止（越界）: pos=$pos")
            if (n > limit) throw DwarfException("字符串超过长度限制 $limit")
            if (buf[pos + n].toInt() == 0) break
            n++
        }
        val s = String(buf, pos, n, Charsets.UTF_8)
        pos += n + 1
        return s
    }
}

fun hexU(v: Long): String {
    if (v < 0) return "0x" + java.lang.Long.toUnsignedString(v, 16)
    return "0x" + v.toString(16)
}

/** 无符号包含判断：start <= a < end（按 64 位无符号）。 */
fun rangeContains(start: Long, end: Long, a: Long): Boolean =
    java.lang.Long.compareUnsigned(a, start) >= 0 && java.lang.Long.compareUnsigned(a, end) < 0
