package com.compass.dwarf

import kotlin.experimental.or

/**
 * Bounds-checked cursor over a byte slice. Every read validates the cursor up
 * front so a malformed section can never make the parser walk off the end and
 * silently reinterpret following data.
 */
class Buf(data: ByteArray, private val base: Int = 0, val size: Int = data.size - base) {
    val a: ByteArray = data
    var pos: Int = 0
    val absolutePos: Int get() = base + pos

    fun require(n: Int) {
        if (n < 0 || pos > size - n) {
            throw ParseException("unexpected end of data: need $n bytes at offset ${base + pos}")
        }
    }

    fun u8(): Int {
        require(1)
        return a[base + pos++].toInt() and 0xff
    }

    fun u16(): Int {
        require(2)
        val v = (a[base + pos].toInt() and 0xff) or ((a[base + pos + 1].toInt() and 0xff) shl 8)
        pos += 2
        return v
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        for (i in 0 until 4) v = v or ((a[base + pos + i].toLong() and 0xff) shl (i * 8))
        pos += 4
        return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        for (i in 0 until 8) v = v or ((a[base + pos + i].toLong() and 0xff) shl (i * 8))
        pos += 8
        return v
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = a.copyOfRange(base + pos, base + pos + n)
        pos += n
        return out
    }

    fun sliceAt(offset: Int, n: Int = size - offset): Buf {
        if (offset < 0 || offset > size || n < 0 || offset + n > size) {
            throw ParseException("slice out of bounds: offset=$offset len=$n size=$size")
        }
        return Buf(a, base + offset, n)
    }

    fun seek(p: Int) {
        if (p < 0 || p > size) throw ParseException("seek out of bounds: $p > $size")
        pos = p
    }

    fun uleb(maxBytes: Int = MAX_LEB): ULong {
        var result = 0UL
        var shift = 0
        var count = 0
        while (true) {
            if (++count > maxBytes) throw ParseException("ULEB128 too long at offset ${base + pos}")
            val b = u8()
            val chunk = (b and 0x7f).toULong()
            if (shift < 64) {
                val s = if (shift > 0) shift else 0
                result = result or (chunk shl s)
            }
            if ((b and 0x80) == 0) break
            shift += 7
        }
        return result
    }

    fun sleb(maxBytes: Int = MAX_LEB): Long {
        var result = 0L
        var shift = 0
        var b = 0
        var count = 0
        while (true) {
            if (++count > maxBytes) throw ParseException("SLEB128 too long at offset ${base + pos}")
            b = u8()
            result = result or (((b and 0x7f).toLong()) shl shift)
            shift += 7
            if ((b and 0x80) == 0) break
        }
        if (shift < 64 && (b and 0x40) != 0) {
            result = result or (-1L shl shift)
        }
        return result
    }

    /** Null terminated string; failing if no terminator exists before the end. */
    fun cstring(): String {
        val start = pos
        while (pos < size && a[base + pos] != 0.toByte()) pos++
        if (pos >= size) throw ParseException("unterminated string at offset ${base + start}")
        val s = String(a, base + start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun cstringAt(off: Int): String {
        if (off < 0 || off >= size) throw ParseException("string offset out of bounds: $off")
        return sliceAt(off).cstring()
    }

    fun unsigned(size: Int): ULong = when (size) {
        1 -> u8().toULong()
        2 -> u16().toULong()
        4 -> u32().toULong()
        8 -> u64().toULong()
        else -> throw ParseException("bad integer width $size")
    }

    companion object {
        const val MAX_LEB = 16
    }
}

class ParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/** How an attribute value was encoded, surfaced in the UI/table version report. */
enum class FormClass { ADDR, CONST, STRING, REF, BLOCK, EXPR, LINEPTR, RNGLIST, LOCLIST, STREPOFFSET, MACPTR, UNKNOWN }

/**
 * Attribute value. Numeric values use Long/ULong; DW_FORM_strp etc. carry an
 * offset that is resolved against the right string table lazily.
 */
sealed class AttrValue {
    class Addr(val v: Long) : AttrValue()
    class Num(val v: Long) : AttrValue()
    class UNum(val v: ULong) : AttrValue()
    class Str(val v: String) : AttrValue()
    /** Offset + which string table (.debug_str vs .debug_line_str). */
    class StrRef(val offset: Long, val lineStr: Boolean = false) : AttrValue()
    class Strx(val index: Int) : AttrValue()
    class Ref(val offset: Int, val formClass: FormClass) : AttrValue()
    class SecOffset(val offset: Long, val formClass: FormClass) : AttrValue()
    class Block(val bytes: ByteArray) : AttrValue()
    class Unknown(val form: Long) : AttrValue()
}
