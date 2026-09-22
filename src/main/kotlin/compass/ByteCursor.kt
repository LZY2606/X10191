package compass

import java.io.EOFException

/**
 * Bounded cursor over a DWARF/ELF section. All reads enforce:
 *  - section end (no cross-section reads),
 *  - explicit remaining-length budgets (unit_length),
 *  - hop counters for indirect forms / reference chasing.
 */
class ByteCursor(val data: ByteArray, val base: Int = 0, val sectionEnd: Int = data.size, val name: String = "section") {
    var pos: Int = base
        private set

    val remaining: Int get() = sectionEnd - pos

    fun seek(p: Int) {
        if (p < base || p > sectionEnd) throw CursorException("$name: seek out of range: $p not in [$base,$sectionEnd)")
        pos = p
    }

    fun skip(n: Int) {
        if (n < 0) throw CursorException("$name: negative skip $n")
        ensure(n)
        pos += n
    }

    fun ensure(n: Int) {
        if (n < 0 || pos + n > sectionEnd) {
            throw CursorException("$name: truncated read at $pos need $n bytes (end=$sectionEnd)")
        }
    }

    fun u8(): Int { ensure(1); return data[pos++].toInt() and 0xff }
    fun s8(): Int { ensure(1); return data[pos++].toInt() }
    fun u16(): Int { ensure(2); val v = (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8); pos += 2; return v }
    fun u32(): Long { ensure(4); var v = 0L; for (i in 0..3) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8)); pos += 4; return v }
    fun s32(): Int = u32().toInt()

    fun u64(): Long { ensure(8); var v = 0L; for (i in 0..7) v = v or ((data[pos + i].toLong() and 0xff) shl (i * 8)); pos += 8; return v }

    fun bytes(n: Int): ByteArray {
        ensure(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun peek(): Int = if (pos < sectionEnd) data[pos].toInt() and 0xff else -1

    fun uleb(maxBytes: Int = MAX_LEB): Long {
        var result = 0L
        var shift = 0
        var i = 0
        while (true) {
            if (++i > maxBytes) throw CursorException("$name: ULEB128 too long at $pos")
            ensure(1)
            val b = data[pos++].toInt() and 0xff
            if (shift < 64) result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64 && (b and 0x7f) != 0) throw CursorException("$name: ULEB128 overflow at $pos")
        }
        return result
    }

    fun sleb(maxBytes: Int = MAX_LEB): Long {
        var result = 0L
        var shift = 0
        var i = 0
        var b = 0
        while (true) {
            if (++i > maxBytes) throw CursorException("$name: SLEB128 too long at $pos")
            ensure(1)
            b = data[pos++].toInt() and 0xff
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
        return result
    }

    /** Read an address of [size] bytes (1,2,4,8) as an unsigned Long. */
    fun address(size: Int): Long = when (size) {
        1 -> u8().toLong()
        2 -> u16().toLong() and 0xffffL
        4 -> u32()
        8 -> u64()
        else -> throw CursorException("$name: bad address size $size")
    }

    /** DWARF fixed-size integer form (data1/data2/data4/data8, sdata/udata via length). */
    fun fixed(n: Int, signed: Boolean = false): Long = when {
        n == 1 -> if (signed) s8().toLong() else u8().toLong()
        n == 2 -> { val v = u16(); if (signed && (v and 0x8000) != 0) (v or -0x10000).toLong() else v.toLong() }
        n == 4 -> if (signed) s32().toLong() else u32()
        n == 8 -> u64()
        else -> throw CursorException("$name: bad fixed size $n")
    }

    fun cString(maxLen: Int = MAX_STRING): String {
        val start = pos
        var end = pos
        var n = 0
        while (true) {
            ensure(1)
            if (data[end].toInt() == 0) break
            end++
            if (++n > maxLen) throw CursorException("$name: string longer than $maxLen at $start")
        }
        val s = String(data, start, end - start, Charsets.UTF_8)
        pos = end + 1
        return s
    }

    fun sub(end: Int = sectionEnd): ByteCursor = ByteCursor(data, pos, end, name)

    companion object {
        const val MAX_LEB = 10
        const val MAX_STRING = 1_000_000
    }
}

class CursorException(message: String) : RuntimeException(message)
