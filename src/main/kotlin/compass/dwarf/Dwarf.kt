package compass.dwarf

/**
 * 有界字节视图：所有 DWARF/ELF 解析的唯一游标。
 * 越界读取统一抛 [DwarfBoundsException]，调用方据此隔离损坏数据，
 * 绝不允许游标静默错位后继续产生伪结果。
 */
class ByteView(val data: ByteArray, val base: Int = 0, val size: Int = data.size - base) {
    init {
        if (base < 0 || size < 0 || base + size > data.size) {
            throw DwarfBoundsException("view out of bytes: base=$base size=$size total=${data.size}")
        }
    }

    fun u8(off: Int): Int {
        if (off < 0 || off + 1 > size) throw DwarfBoundsException("u8 at $off (len=$size)")
        return data[base + off].toInt() and 0xff
    }

    fun u16(off: Int): Int = u8(off) or (u8(off + 1) shl 8)

    fun u32(off: Int): Long =
        (u8(off).toLong()) or (u8(off + 1).toLong() shl 8) or
            (u8(off + 2).toLong() shl 16) or (u8(off + 3).toLong() shl 24)

    fun u64(off: Int): Long = u32(off) or (u32(off + 4) shl 32)

    fun bytes(off: Int, len: Int): ByteArray {
        if (len < 0 || off < 0 || off + len > size) throw DwarfBoundsException("bytes at $off len=$len (len=$size)")
        return data.copyOfRange(base + off, base + off + len)
    }

    /** NUL 结尾字符串；没有 NUL 到视图末尾即止（轻微宽容，但不越界）。 */
    fun cString(off: Int): String {
        var end = off
        while (end < size && u8(end) != 0) end++
        return String(data, base + off, end - off, Charsets.UTF_8)
    }

    fun slice(off: Int, len: Int): ByteView {
        if (off < 0 || len < 0 || off + len > size) throw DwarfBoundsException("slice at $off len=$len (len=$size)")
        return ByteView(data, base + off, len)
    }

    /** 相对游标签到式读取器，自带深度/跳转预算。 */
    fun reader(start: Int = 0): Reader = Reader(this, start)

    class Reader(val view: ByteView, var pos: Int = 0) {
        val length: Int get() = view.size
        val eof: Boolean get() = pos >= view.size

        fun u8(): Int = view.u8(pos.also { pos++ })
        fun u16(): Int = view.u16(pos).also { pos += 2 }
        fun u32(): Long = view.u32(pos).also { pos += 4 }
        fun u64(): Long = view.u64(pos).also { pos += 8 }
        fun bytes(n: Int): ByteArray = view.bytes(pos, n).also { pos += n }
        fun seek(p: Int) {
            if (p < 0 || p > view.size) throw DwarfBoundsException("seek $p (len=$view.size)")
            pos = p
        }

        fun cString(): String {
            val s = view.cString(pos)
            pos += s.length + 1
            return s
        }

        fun leb128(): Long {
            var result = 0L
            var shift = 0
            var count = 0
            while (true) {
                if (++count > 10) throw DwarfFormatException("LEB128 too long at $pos")
                val b = u8()
                result = result or ((b and 0x7f).toLong() shl shift)
                if (b and 0x80 == 0) {
                    if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl (shift + 7))
                    return result
                }
                shift += 7
                if (shift >= 64) throw DwarfFormatException("LEB128 overflow at $pos")
            }
        }

        fun uleb128(): Long {
            var result = 0L
            var shift = 0
            var count = 0
            while (true) {
                if (++count > 10) throw DwarfFormatException("ULEB128 too long at $pos")
                val b = u8()
                result = result or ((b and 0x7f).toLong() shl shift)
                if (b and 0x80 == 0) return result
                shift += 7
                if (shift > 63) throw DwarfFormatException("ULEB128 overflow at $pos")
            }
        }
    }
}

open class DwarfException(message: String, cause: Throwable? = null) : Exception(message, cause)
class DwarfBoundsException(message: String) : DwarfException(message)
class DwarfFormatException(message: String) : DwarfException(message)

/** 未知 DW_FORM / DW_AT：隔离当前 DIE，其余 CU 仍可解析。 */
class UnknownFormException(val form: Long, message: String) : DwarfException(message)
