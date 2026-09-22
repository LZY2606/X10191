package compass.binary

import java.nio.ByteOrder

/**
 * Bounds-checked cursor over a byte array. Every read validates range up front
 * so a corrupt section raises [DwarfParseException] instead of producing bytes
 * from adjacent sections.
 */
class ByteReader(
    val bytes: ByteArray,
    val sectionName: String = "<bytes>",
    val base: Int = 0,
    end: Int = bytes.size,
    val endian: ByteOrder = ByteOrder.LITTLE_ENDIAN,
) {
    var pos: Int = base
        private set
    val endExclusive: Int = end

    val remaining: Int get() = endExclusive - pos
    val size: Int get() = endExclusive - base

    fun seek(newPos: Int) {
        if (newPos < base || newPos > endExclusive) {
            throw DwarfParseException("$sectionName: seek 0x${newPos.toString(16)} outside section [0x${base.toString(16)},0x${endExclusive.toString(16)})")
        }
        pos = newPos
    }

    fun require(n: Int) {
        if (n < 0) throw DwarfParseException("$sectionName: negative read $n")
        if (pos + n > endExclusive) {
            throw DwarfParseException(
                "$sectionName: unexpected end at 0x${pos.toString(16)}, need $n bytes, have ${endExclusive - pos}",
            )
        }
    }

    fun u8(): Int {
        require(1)
        return bytes[pos].toInt() and 0xff
    }

    fun u16(): Int {
        require(2)
        val p = pos
        pos = p + 2
        return if (endian == ByteOrder.LITTLE_ENDIAN) {
            (bytes[p].toInt() and 0xff) or ((bytes[p + 1].toInt() and 0xff) shl 8)
        } else {
            ((bytes[p].toInt() and 0xff) shl 8) or (bytes[p + 1].toInt() and 0xff)
        }
    }

    fun u32(): Long {
        require(4)
        val p = pos
        pos = p + 4
        var v = 0L
        if (endian == ByteOrder.LITTLE_ENDIAN) {
            for (i in 0 until 4) v = v or ((bytes[p + i].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 0 until 4) v = (v shl 8) or (bytes[p + i].toLong() and 0xff)
        }
        return v
    }

    fun u64(): Long {
        require(8)
        val p = pos
        pos = p + 8
        var v = 0L
        if (endian == ByteOrder.LITTLE_ENDIAN) {
            for (i in 0 until 8) v = v or ((bytes[p + i].toLong() and 0xff) shl (i * 8))
        } else {
            for (i in 0 until 8) v = (v shl 8) or (bytes[p + i].toLong() and 0xff)
        }
        return v
    }

    fun uint(size: Int): Long = when (size) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw DwarfParseException("$sectionName: unsupported integer size $size")
    }

    fun readBytes(n: Int): ByteArray {
        require(n)
        val out = bytes.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun readNullTerminatedString(): String {
        val start = pos
        var p = pos
        while (p < endExclusive && bytes[p].toInt() != 0) p++
        if (p >= endExclusive) {
            throw DwarfParseException("$sectionName: unterminated string at 0x${start.toString(16)}")
        }
        val s = String(bytes, start, p - start, Charsets.UTF_8)
        pos = p + 1
        return s
    }

    /** Read a fixed-length string without requiring NUL (line header include_directories DWARF4). */
    fun readStringAt(offset: Int): String {
        if (offset < 0 || offset >= bytes.size) {
            throw DwarfParseException("$sectionName: string offset 0x${offset.toString(16)} out of bounds")
        }
        var p = offset
        while (p < bytes.size && bytes[p].toInt() != 0) p++
        return String(bytes, offset, p - offset, Charsets.UTF_8)
    }

    fun skip(n: Int) {
        require(n)
        pos += n
    }

    /**
     * Parse the DWARF "unit_length" / "initial length" preamble.
     * Returns [InitialLength]; caller should read content until [InitialLength.endOffset].
     */
    fun initialLength(): InitialLength {
        val start = pos
        val first = u32()
        return if (first == 0xffffffffL) {
            val len64 = u64()
            if (len64 < 0 || len64 > Int.MAX_VALUE.toLong()) {
                throw DwarfParseException("$sectionName: 64-bit DWARF length $len64 too large at 0x${start.toString(16)}")
            }
            val len = len64.toInt()
            val contentStart = pos
            val end = contentStart + len
            if (end > endExclusive || end < contentStart) {
                throw DwarfParseException("$sectionName: 64-bit unit length overruns section at 0x${start.toString(16)}")
            }
            InitialLength(true, contentStart, end)
        } else {
            val len = first.toInt()
            val contentStart = pos
            val end = contentStart + len
            if (end > endExclusive || end < contentStart) {
                throw DwarfParseException("$sectionName: 32-bit unit length $len overruns section at 0x${start.toString(16)}")
            }
            InitialLength(false, contentStart, end)
        }
    }

    fun subReader(baseOffset: Int, endOffset: Int, name: String = sectionName): ByteReader {
        if (baseOffset < this.base || endOffset > endExclusive || baseOffset > endOffset) {
            throw DwarfParseException("$sectionName: cannot slice [0x${baseOffset.toString(16)},0x${endOffset.toString(16)})")
        }
        return ByteReader(bytes, name, baseOffset, endOffset, endian)
    }

    /** Unsigned LEB128 with bounded number of bytes and bit-width validation. */
    fun uleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        while (true) {
            val b = u8()
            n++
            if (shift < 64) {
                result = result or ((b.toLong() and 0x7f) shl shift)
            } else if (b and 0x7f != 0) {
                throw DwarfParseException("$sectionName: ULEB128 overflow at 0x${(pos - 1).toString(16)}")
            }
            if (b and 0x80 == 0) return result
            shift += 7
            if (n >= maxBytes) throw DwarfParseException("$sectionName: ULEB128 exceeded $maxBytes bytes")
        }
    }

    fun sleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        var b = 0
        while (true) {
            b = u8()
            n++
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (n >= maxBytes) throw DwarfParseException("$sectionName: SLEB128 exceeded $maxBytes bytes")
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }
}

data class InitialLength(val dwarf64: Boolean, val contentStart: Int, val endOffset: Int) {
    val addressSize: Int get() = if (dwarf64) 8 else 4
}

class DwarfParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
