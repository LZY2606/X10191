package compass.dwarf

import java.nio.ByteOrder

class CursorOutOfBounds(message: String) : RuntimeException(message)

class ByteReader(
    val data: ByteArray,
    val order: ByteOrder,
    val base: Int = 0,
    val size: Int = data.size - base,
    val sectionName: String = "bytes"
) {
    var position: Int = 0
        private set

    val end: Int get() = size
    val remaining: Int get() = size - position

    fun seek(position: Int) {
        if (position < 0 || position > size) throw CursorOutOfBounds("$sectionName: seek $position outside 0..$size")
        this.position = position
    }

    fun skip(count: Int) = seek(position + count)
    fun take(count: Int): ByteArray {
        if (count < 0 || position + count > size) throw CursorOutOfBounds("$sectionName: read $count at $position")
        return data.copyOfRange(base + position, base + position + count).also { position += count }
    }

    fun u8(): Int = take(1)[0].toInt() and 0xff
    fun u16(): Int {
        val bytes = take(2)
        return if (order == ByteOrder.LITTLE_ENDIAN) (bytes[0].toInt() and 0xff) or ((bytes[1].toInt() and 0xff) shl 8)
        else ((bytes[0].toInt() and 0xff) shl 8) or (bytes[1].toInt() and 0xff)
    }
    fun u32(): Long {
        val bytes = take(4)
        var value = 0L
        if (order == ByteOrder.LITTLE_ENDIAN) for (i in 3 downTo 0) value = (value shl 8) or (bytes[i].toLong() and 0xff)
        else for (i in 0..3) value = (value shl 8) or (bytes[i].toLong() and 0xff)
        return value
    }
    fun u64(): Long {
        val low = if (order == ByteOrder.LITTLE_ENDIAN) u32() else u32()
        val high = if (order == ByteOrder.LITTLE_ENDIAN) u32() else u32()
        return if (order == ByteOrder.LITTLE_ENDIAN) (high shl 32) or low else (low shl 32) or high
    }
    fun read(addressSize: Int): Long = when (addressSize) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw CursorOutOfBounds("unsupported address size $addressSize")
    }

    fun uleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        repeat(maxBytes) {
            val byte = u8()
            result = result or ((byte and 0x7f).toLong() shl shift)
            if (byte and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw CursorOutOfBounds("ULEB128 overflow")
        }
        throw CursorOutOfBounds("ULEB128 too long")
    }

    fun sleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var byte = 0
        repeat(maxBytes) {
            byte = u8()
            result = result or ((byte and 0x7f).toLong() shl shift)
            shift += 7
            if (byte and 0x80 == 0) {
                if (shift < 64 && byte and 0x40 != 0) result = result or (-1L shl shift)
                return result
            }
            if (shift >= 64) throw CursorOutOfBounds("SLEB128 overflow")
        }
        throw CursorOutOfBounds("SLEB128 too long")
    }

    fun nullTerminated(): String {
        val start = position
        while (position < size && data[base + position].toInt() != 0) position++
        if (position >= size) throw CursorOutOfBounds("unterminated string")
        val value = data.copyOfRange(base + start, base + position).toString(Charsets.UTF_8)
        position++
        return value
    }

    fun child(base: Int = this.base + position, size: Int = remaining): ByteReader =
        ByteReader(data, order, base, size, sectionName)
}

data class SectionInfo(
    val name: String,
    val type: Long,
    val flags: Long,
    val address: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val sha256: String
)

data class ElfSegments(
    val sections: List<SectionInfo>,
    val loads: List<MemorySegment>,
    val elfClass: Int,
    val endian: ByteOrder
)

data class MemorySegment(val offset: Long, val virtualAddress: Long, val fileSize: Long, val memorySize: Long, val flags: Int) {
    fun containsLinked(address: Long): Boolean = address in virtualAddress until virtualAddress + memorySize
}
