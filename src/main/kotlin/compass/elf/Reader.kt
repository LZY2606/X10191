package compass.elf

import compass.model.Endian

/** Thrown when any read crosses the declared bound of a section/CU. */
class BinaryTruncatedException(message: String) : RuntimeException(message)

/**
 * Cursor over a byte array with strict bounds checking.
 * All DWARF/ELF parsing goes through this so a truncated or corrupt
 * section can never silently desynchronize into garbage results.
 */
class Reader(val data: ByteArray, private val endian: Endian, val base: Int = 0) {
    var pos: Int = base
        private set

    /** Absolute end for this reader's logical window. */
    val end: Int = if (base == 0) data.size else minOf(data.size, base + data.size)

    init {
        require(base >= 0 && base <= data.size) { "bad reader base" }
    }

    fun remaining(): Int = end - pos
    fun seek(p: Int) {
        if (p < base || p > end) throw BinaryTruncatedException("seek $p outside [${base},${end})")
        pos = p
    }
    fun skip(n: Int) = seek(pos + n)

    fun require(n: Int) {
        if (n < 0 || pos + n > end)
            throw BinaryTruncatedException("need $n bytes at $pos, have ${end - pos}")
    }

    fun u8(): Int { require(1); return data[pos].toInt() and 0xff; }
    fun i8(): Int { require(1); return data[pos].toInt() }
    fun u16(): Int { require(2); val a = data[pos].toInt() and 0xff; val b = data[pos+1].toInt() and 0xff; return if (endian.big) (a shl 8) or b else (b shl 8) or a }
    fun u32(): Long { require(4); var v = 0L; for (i in 0 until 4) { val x = data[pos + i].toInt() and 0xffL; v = if (endian.big) (v shl 8) or x else v or (x shl (i * 8)) }; return v }
    fun i32(): Int { require(4); var v = 0; for (i in 0 until 4) { val x = data[pos + i].toInt() and 0xff; v = if (endian.big) (v shl 8) or x else v or (x shl (i * 8)) }; return v }
    fun u64(): Long { require(8); var v = 0L; for (i in 0 until 8) { val x = data[pos + i].toInt() and 0xffL; v = if (endian.big) (v shl 8) or x else v or (x shl (i * 8)) }; return v }

    fun bytes(n: Int): ByteArray { require(n); val out = data.copyOfRange(pos, pos + n); pos += n; return out }
    fun bytesAt(off: Int, n: Int): ByteArray {
        if (off < 0 || n < 0 || off + n > data.size) throw BinaryTruncatedException("bytesAt $off+$n")
        return data.copyOfRange(off, off + n)
    }

    fun cStringAt(off: Int): String {
        if (off < 0 || off >= data.size) throw BinaryTruncatedException("cstr at $off")
        var e = off
        while (e < data.size && data[e].toInt() != 0) e++
        return String(data, off, e - off, Charsets.UTF_8)
    }

    fun uleb128(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        while (true) {
            if (count++ >= 10) throw BinaryTruncatedException("uleb128 too long at $pos")
            val b = u8()
            result = result or ((b.toLong() and 0x7f) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 64) throw BinaryTruncatedException("uleb128 overflow at $pos")
        }
        return result
    }

    fun uleb128at(off: Int): Long { seek(off); return uleb128() }

    fun sleb128(): Long {
        var result = 0L
        var shift = 0
        var count = 0
        var b = 0
        while (true) {
            if (count++ >= 10) throw BinaryTruncatedException("sleb128 too long at $pos")
            b = u8()
            result = result or ((b.toLong() and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) break
            if (shift >= 64) throw BinaryTruncatedException("sleb128 overflow at $pos")
        }
        if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
        return result
    }

    /** Result of reading a DWARF unit length: inner window [start,end), 64-bit flag. */
    data class InitialLength(val start: Int, val end: Int, val dwarf64: Boolean)

    /**
     * Read a DWARF "length" prefixed block. Handles 32/64-bit DWARF forms and
     * rejects bodies that run past the section, preventing cursor desync.
     */
    fun initialLength(): InitialLength {
        val marker = u32()
        val dwarf64: Boolean
        val bodyLen: Long
        if (marker == 0xffffffffL) {
            dwarf64 = true
            bodyLen = u64()
        } else {
            dwarf64 = false
            bodyLen = marker
        }
        val start = pos
        val finish = start + bodyLen
        if (bodyLen < 0 || finish > end)
            throw BinaryTruncatedException("unit length exceeds section")
        return InitialLength(start, finish.toInt(), dwarf64)
    }

    fun at(p: Int): Reader { pos = p; return this }
}
