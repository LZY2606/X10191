package compass.dwarf

import java.io.ByteArrayOutputStream

/** Raised when a section is truncated or an index/reference runs out of bounds. */
class DwarfBoundsException(message: String) : RuntimeException(message)

/**
 * Cursor over one section's bytes. Every read is bounds checked; a failure throws
 * [DwarfBoundsException] so the caller can stop exactly at the boundary instead of
 * drifting the cursor and producing fabricated DIEs / rows.
 */
class SectionReader(
    val data: ByteArray,
    val sectionName: String,
    val littleEndian: Boolean,
    var pos: Int = 0,
    /** 4 for DWARF 32-bit offsets, 8 for the 64-bit offset format. */
    val dwarfOffsetSize: Int = 4
) {
    val size: Int get() = data.size

    fun clone(pos: Int = this.pos, dwarfOffsetSize: Int = this.dwarfOffsetSize): SectionReader =
        SectionReader(data, sectionName, littleEndian, pos, dwarfOffsetSize)

    fun require(needed: Int) {
        if (pos < 0 || pos + needed > data.size)
            throw DwarfBoundsException("$sectionName: 需要 $needed 字节 @$pos，但段长度只有 ${data.size}")
    }

    fun seek(newPos: Int) {
        if (newPos < 0 || newPos > data.size)
            throw DwarfBoundsException("$sectionName: 跳转越界 @$newPos（段长度 ${data.size}）")
        pos = newPos
    }

    fun u8(): Int { require(1); val v = data[pos].toInt() and 0xff; pos++; return v }
    fun i8(): Int { require(1); val v = data[pos].toInt(); pos++; return v }

    fun u16(): Int {
        require(2)
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (littleEndian) (b shl 8) or a else (a shl 8) or b
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        for (i in 0 until 4) {
            val byte = data[pos + i].toInt() and 0xff
            v = if (littleEndian) v or (byte.toLong() shl (8 * i))
            else (v shl 8) or byte.toLong()
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        for (i in 0 until 8) {
            val byte = data[pos + i].toInt() and 0xff
            v = if (littleEndian) v or (byte.toLong() shl (8 * i))
            else (v shl 8) or byte.toLong()
        }
        pos += 8
        return v
    }

    fun u(offsetSize: Int): Long = when (offsetSize) {
        1 -> u8().toLong(); 2 -> u16().toLong(); 4 -> u32(); 8 -> u64()
        else -> throw DwarfBoundsException("非法 offset 宽度 $offsetSize")
    }

    fun dwarfOffset(): Long = u(dwarfOffsetSize)

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (++count > MAX_LEB_BYTES) throw DwarfBoundsException("$sectionName: ULEB128 超长 @${pos - 1}")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw DwarfBoundsException("$sectionName: ULEB128 超 64 位")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b = 0
        var count = 0
        while (true) {
            if (++count > MAX_LEB_BYTES) throw DwarfBoundsException("$sectionName: SLEB128 超长 @${pos - 1}")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw DwarfBoundsException("$sectionName: SLEB128 超 64 位")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun bytes(n: Int): ByteArray {
        require(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    /** NUL-terminated UTF-8 string. */
    fun cString(): String {
        val start = pos
        while (pos < data.size && data[pos].toInt() != 0) pos++
        if (pos >= data.size) throw DwarfBoundsException("$sectionName: 字符串未在段内结束 @$start")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++ // consume NUL
        return s
    }

    fun readInitialLength(): InitialLength {
        val first = u32()
        if (first == 0xffffffffL) {
            val len = u64()
            if (len < 0 || len > Int.MAX_VALUE.toLong())
                throw DwarfBoundsException("$sectionName: 64 位单元长度超出实现限制")
            return InitialLength(len.toInt(), 8, pos, false)
        }
        if (first in 0xfffffff0L..0xfffffffeL)
            throw DwarfBoundsException("$sectionName: 保留的 unit length 值 0x${first.toString(16)}")
        return InitialLength(first.toInt(), 4, pos, true)
    }

    companion object {
        const val MAX_LEB_BYTES = 16
    }
}

data class InitialLength(val unitLength: Int, val offsetSize: Int, val headerEndPos: Int, val is32: Boolean)

/** Read an LEB at a temporary position without moving the cursor. */
fun SectionReader.peekUleb(at: Int): Long = clone(at).uleb()

fun SectionReader.readToEnd(): String {
    val out = ByteArrayOutputStream()
    return String(bytes(size - pos), Charsets.UTF_8)
}
