package com.compass.dwarf

import java.nio.ByteBuffer
import java.nio.ByteOrder

class BinaryCursor(data: ByteArray, val base: Long = 0, littleEndian: Boolean = true) {
    private val buffer = ByteBuffer.wrap(data).order(if (littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
    val size = data.size
    var position = 0
        private set

    fun remaining(): Int = size - position
    fun require(count: Int, what: String = "read") {
        if (count < 0 || position < 0 || position > size - count) {
            throw DwarfParseException("Unexpected end of section at ${position + base}: $what")
        }
    }

    fun seek(newPosition: Long, what: String = "seek") {
        val p = (newPosition - base).toInt()
        require(p in 0..size) { throw DwarfParseException("Out of bounds $what: $newPosition") }
        position = p
        buffer.position(p)
    }

    fun localSeek(newPosition: Int) = seek(base + newPosition.toLong())
    fun absolutePosition(): Long = base + position
    fun u8(): Int { require(1); return buffer.get(position++).toInt() and 0xff }
    fun i8(): Int { require(1); return buffer.get(position++).toInt() }
    fun u16(): Int { require(2); val v = buffer.getShort(position).toInt() and 0xffff; position += 2; return v }
    fun u32(): Long { require(4); val v = buffer.getInt(position).toLong() and 0xffffffffL; position += 4; return v }
    fun i32(): Int { require(4); val v = buffer.getInt(position); position += 4; return v }
    fun u64(): Long { require(8); val v = buffer.getLong(position); position += 8; return v }
    fun bytes(count: Int): ByteArray {
        require(count)
        val out = ByteArray(count)
        System.arraycopy(buffer.array(), position, out, 0, count)
        position += count
        return out
    }

    fun skip(count: Int) { require(count); position += count }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        repeat(16) {
            require(1, "ULEB128")
            val byte = u8()
            result = result or ((byte and 0x7f).toLong() shl shift)
            if (byte and 0x80 == 0) return result
            shift += 7
        }
        throw DwarfParseException("ULEB128 too long")
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var byte = 0
        repeat(16) {
            require(1, "SLEB128")
            byte = u8()
            result = result or ((byte and 0x7f).toLong() shl shift)
            shift += 7
            if (byte and 0x80 == 0) {
                if (byte and 0x40 != 0) result = result or (-1L shl shift)
                return result
            }
        }
        throw DwarfParseException("SLEB128 too long")
    }

    fun cString(): String {
        require(1, "string")
        val start = position
        while (position < size && buffer.get(position) != 0.toByte()) position++
        require(1, "string terminator")
        val text = String(buffer.array(), start, position - start, Charsets.UTF_8)
        position++
        return text
    }

    fun cStringAt(localOffset: Long): String {
        val old = position
        localSeek(localOffset.toInt())
        val text = cString()
        position = old
        buffer.position(old)
        return text
    }

    fun sectionBytes(offset: Long, length: Long): ByteArray {
        val p = (offset - base).toInt()
        if (p < 0 || length < 0 || p > size - length.toInt()) throw DwarfParseException("Section slice out of bounds")
        return bytes(length.toInt()).also { position = p + length.toInt() }
    }

    fun slice(offset: Long = absolutePosition(), length: Int = size - (offset - base).toInt()): BinaryCursor {
        val p = (offset - base).toInt()
        require(length in 0..(size - p)) { throw DwarfParseException("Invalid slice") }
        return BinaryCursor(bytes(0).copyOfRange(p, p + length), offset)
    }
}

class DwarfParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
