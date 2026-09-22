package compass.elf

import java.nio.charset.StandardCharsets

class DwarfParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * Bounded little-endian (or big-endian) cursor over a single section's bytes.
 * Every read is bounds-checked; all accessors throw [DwarfParseException] on corruption.
 */
class ByteReader(
    val data: ByteArray,
    private val bigEndian: Boolean = false,
    private val sectionName: String = "?"
) {
    var pos: Int = 0

    fun remaining(): Int = data.size - pos
    fun require(n: Int) {
        if (n < 0 || pos + n > data.size || pos + n < pos) {
            throw DwarfParseException(
                "$sectionName: read out of bounds at offset 0x${pos.toString(16)} need $n of ${data.size}"
            )
        }
    }

    fun seek(off: Int) {
        if (off < 0 || off > data.size) {
            throw DwarfParseException("$sectionName: seek out of bounds 0x${off.toString(16)} / ${data.size}")
        }
        pos = off
    }

    fun u8(): Int {
        require(1); return data[pos++].toInt() and 0xff
    }
    fun u16(): Int {
        require(2)
        val a = data[pos].toInt() and 0xff
        val b = data[pos + 1].toInt() and 0xff
        pos += 2
        return if (bigEndian) (a shl 8) or b else (b shl 8) or a
    }
    fun u32(): Long {
        require(4)
        var v = 0L
        if (bigEndian) {
            for (i in 0 until 4) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 3 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }
    fun u64(): Long {
        require(8)
        var v = 0L
        if (bigEndian) {
            for (i in 0 until 8) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        } else {
            for (i in 7 downTo 0) v = (v shl 8) or (data[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    fun readUInt(sz: Int): Long = when (sz) {
        4 -> u32()
        8 -> u64()
        else -> throw DwarfParseException("$sectionName: bad offset size $sz")
    }

    fun uleb128(maxBytes: Int = 16): ULong {
        var result = 0L
        var shift = 0
        var bytes = 0
        while (true) {
            if (++bytes > maxBytes) throw DwarfParseException("$sectionName: uleb128 too long at 0x${pos.toString(16)}")
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw DwarfParseException("$sectionName: uleb128 overflow")
        }
        return result.toULong()
    }

    fun sleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var bytes = 0
        var b = 0
        while (true) {
            if (++bytes > maxBytes) throw DwarfParseException("$sectionName: sleb128 too long")
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw DwarfParseException("$sectionName: sleb128 overflow")
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

    /** NUL terminated UTF-8 string starting at [start]; leaves [pos] untouched. */
    fun cStringAt(start: Int): String {
        var end = start
        if (start < 0 || start >= data.size) {
            throw DwarfParseException("$sectionName: string offset 0x${start.toString(16)} out of bounds")
        }
        while (end < data.size && data[end].toInt() != 0) end++
        if (end >= data.size) throw DwarfParseException("$sectionName: unterminated string at 0x${start.toString(16)}")
        return String(data, start, end - start, StandardCharsets.UTF_8)
    }
}
