package compass.util

open class DwarfException(message: String) : Exception(message)
class UnknownFormException(val formCode: Int) :
    DwarfException("unknown DWARF form 0x${formCode.toString(16)}")

/** Bounded little-endian cursor. All reads are range-checked so a corrupt
 *  section can never move the cursor outside its declared limit. */
class Cursor(
    val data: ByteArray,
    var pos: Int,
    val limit: Int,
    val label: String = "section"
) {
    init {
        require(pos in 0..limit && limit <= data.size) {
            "cursor init out of bounds: pos=$pos limit=$limit size=${data.size}"
        }
    }

    val remaining: Int get() = limit - pos
    fun exhausted(): Boolean = pos >= limit

    fun need(n: Int) {
        if (n < 0 || pos + n > limit) {
            throw DwarfException("cursor overrun in $label at 0x${pos.toString(16)}: need $n, have $remaining")
        }
    }

    fun u8(): Int {
        need(1)
        return data[pos++].toInt() and 0xFF
    }

    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        need(2)
        val v = (data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8)
        pos += 2
        return v
    }

    fun u32(): Long {
        need(4)
        var v = 0L
        for (i in 0..3) v = v or ((data[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 4
        return v
    }

    fun u64(): Long {
        need(8)
        var v = 0L
        for (i in 0..7) v = v or ((data[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 8
        return v
    }

    fun addr(size: Int): Long = when (size) {
        4 -> u32()
        8 -> u64()
        else -> throw DwarfException("unsupported address size $size in $label")
    }

    fun offset(is64: Boolean): Long = if (is64) u64() else u32()

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        repeat(10) {
            val b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) return result
        }
        throw DwarfException("uleb128 too long in $label at 0x${pos.toString(16)}")
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        repeat(10) {
            b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
        }
        throw DwarfException("sleb128 too long in $label at 0x${pos.toString(16)}")
    }

    fun bytes(n: Int): ByteArray {
        need(n)
        val r = data.copyOfRange(pos, pos + n)
        pos += n
        return r
    }

    fun cstring(maxLen: Int = 1 shl 20): String {
        val start = pos
        var end = pos
        while (end < limit && data[end] != 0.toByte()) {
            end++
            if (end - start > maxLen) throw DwarfException("string too long in $label")
        }
        if (end >= limit) throw DwarfException("unterminated string in $label at 0x${start.toString(16)}")
        pos = end + 1
        return String(data, start, end - start, Charsets.UTF_8)
    }

    /** Create a sub-cursor; bounds are validated against this cursor's limit. */
    fun fork(newPos: Int, newLimit: Int = limit): Cursor {
        if (newPos < 0 || newLimit > limit || newPos > newLimit) {
            throw DwarfException("fork out of bounds in $label: pos=$newPos limit=$newLimit")
        }
        return Cursor(data, newPos, newLimit, label)
    }
}

fun Long.hex(): String = "0x" + java.lang.Long.toHexString(this)

/** Unsigned-aware comparison helpers for 64-bit addresses held in Long. */
fun addrLt(a: Long, b: Long): Boolean = java.lang.Long.compareUnsigned(a, b) < 0
fun addrLe(a: Long, b: Long): Boolean = java.lang.Long.compareUnsigned(a, b) <= 0
fun addrInRange(addr: Long, begin: Long, end: Long): Boolean =
    addrLe(begin, addr) && addrLt(addr, end)
