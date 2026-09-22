package compass.dwarf

/** 有界字节视图：所有读取都带边界检查，越界即抛 [CursorException]。 */
class ByteView(val data: ByteArray, val base: Int = 0, val end: Int = data.size) {
    init {
        require(base >= 0 && end <= data.size && base <= end)
    }

    constructor(data: ByteArray, base: Int, length: Long) : this(data, base, base + length.toInt())

    val size: Int get() = end - base

    fun sub(off: Int, len: Int): ByteView {
        checkBounds(off, len)
        return ByteView(data, base + off, base + off + len)
    }

    fun window(off: Int): ByteView {
        if (off < 0 || base + off > end) throw CursorException("window 越界: $off")
        return ByteView(data, base + off, end)
    }

    private fun checkBounds(off: Int, len: Int) {
        if (off < 0 || len < 0 || base + off > end || base + off + len > end) {
            throw CursorException("读取越界: off=$off len=$len size=${size}")
        }
    }

    fun u8(off: Int): Int {
        checkBounds(off, 1)
        return data[base + off].toInt() and 0xff
    }

    fun s8(off: Int): Int {
        checkBounds(off, 1)
        return data[base + off].toInt()
    }

    fun u16(off: Int): Int {
        checkBounds(off, 2)
        val p = base + off
        return (data[p].toInt() and 0xff) or ((data[p + 1].toInt() and 0xff) shl 8)
    }

    fun u32(off: Int): Long {
        checkBounds(off, 4)
        val p = base + off
        var v = 0L
        for (i in 0 until 4) v = v or ((data[p + i].toLong() and 0xff) shl (8 * i))
        return v
    }

    fun s32(off: Int): Int {
        checkBounds(off, 4)
        val p = base + off
        var v = 0
        for (i in 0 until 4) v = v or ((data[p + i].toInt() and 0xff) shl (8 * i))
        return v
    }

    fun u64(off: Int): Long {
        checkBounds(off, 8)
        val p = base + off
        var v = 0L
        for (i in 0 until 8) v = v or ((data[p + i].toLong() and 0xff) shl (8 * i))
        return v
    }

    fun bytes(off: Int, len: Int): ByteArray {
        checkBounds(off, len)
        return data.copyOfRange(base + off, base + off + len)
    }

    fun cstring(off: Int): String {
        if (off < 0 || base + off >= end) throw CursorException("cstring 越界: $off")
        var p = base + off
        val start = p
        while (p < end && data[p].toInt() != 0) p++
        if (p >= end) throw CursorException("cstring 未终止")
        return String(data, start, p - start, Charsets.UTF_8)
    }
}

class CursorException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/** 顺序游标：读 LEB128、定长整数、跳过表单字节。所有越界都走 [CursorException]。 */
class Cursor(val view: ByteView) {
    var pos: Int = 0
        private set

    val remaining: Int get() = view.size - pos

    fun seek(p: Int) {
        if (p < 0 || p > view.size) throw CursorException("seek 越界: $p")
        pos = p
    }

    fun need(n: Int) {
        if (pos + n > view.size) throw CursorException("need 越界: need=$n pos=$pos size=${view.size}")
    }

    fun u8(): Int = view.u8(pos.also { pos++ })
    fun s8(): Int = view.s8(pos.also { pos++ })
    fun u16(): Int { val v = view.u16(pos); pos += 2; return v }
    fun u32(): Long { val v = view.u32(pos); pos += 4; return v }
    fun s32(): Int { val v = view.s32(pos); pos += 4; return v }
    fun u64(): Long { val v = view.u64(pos); pos += 8; return v }

    fun take(n: Int): ByteArray {
        val b = view.bytes(pos, n); pos += n; return b
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        var guard = 0
        while (true) {
            if (++guard > 16) throw CursorException("ULEB128 过长")
            val b = u8()
            result = result or ((b.toLong() and 0x7f) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw CursorException("ULEB128 溢出")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b = 0
        var guard = 0
        while (true) {
            if (++guard > 16) throw CursorException("SLEB128 过长")
            b = u8()
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw CursorException("SLEB128 溢出")
        }
        if (shift < 64 && b and 0x40 != 0) {
            result = result or (-(1L shl shift))
        }
        return result
    }
}
