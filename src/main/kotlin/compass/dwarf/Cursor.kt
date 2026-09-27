package compass.dwarf

/**
 * 受限字节游标：所有读取都做边界检查，任何越界立即抛错，
 * 保证损坏 section 不会让游标静默错位继续产生伪结果。
 */
class Cursor(
    val data: ByteArray,
    var pos: Int = 0,
    val limit: Int = data.size,
    val littleEndian: Boolean = true
) {
    init {
        require(pos in 0..limit && limit <= data.size) { "cursor window out of bounds" }
    }

    fun remaining(): Int = limit - pos
    fun exhausted(): Boolean = pos >= limit

    private fun need(n: Int) {
        if (n < 0 || pos + n > limit) {
            throw CursorError("need $n bytes at 0x${pos.toString(16)} but only ${remaining()} remain")
        }
    }

    fun u8(): Int { need(1); return data[pos++].toInt() and 0xFF }
    fun i8(): Int { need(1); return data[pos++].toInt() }

    fun u16(): Int {
        need(2)
        val b0 = data[pos].toInt() and 0xFF; val b1 = data[pos + 1].toInt() and 0xFF
        pos += 2
        return if (littleEndian) b0 or (b1 shl 8) else (b0 shl 8) or b1
    }

    fun u32(): Long {
        need(4)
        var v = 0L
        if (littleEndian) {
            for (i in 0..3) v = v or ((data[pos + i].toLong() and 0xFF) shl (8 * i))
        } else {
            for (i in 0..3) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        need(8)
        var v = 0L
        if (littleEndian) {
            for (i in 0..7) v = v or ((data[pos + i].toLong() and 0xFF) shl (8 * i))
        } else {
            for (i in 0..7) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        }
        pos += 8
        return v
    }

    fun addr(size: Int): Long = when (size) {
        4 -> u32()
        8 -> u64()
        else -> throw CursorError("unsupported address size $size")
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift > 70) throw CursorError("ULEB128 too long at 0x${pos.toString(16)}")
        }
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
            if (shift > 70) throw CursorError("SLEB128 too long at 0x${pos.toString(16)}")
        }
    }

    fun bytes(n: Int): ByteArray {
        need(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun cstring(): String {
        var end = pos
        while (end < limit && data[end] != 0.toByte()) end++
        if (end >= limit) throw CursorError("unterminated string at 0x${pos.toString(16)}")
        val s = String(data, pos, end - pos, Charsets.UTF_8)
        pos = end + 1
        return s
    }

    fun seek(newPos: Int) {
        if (newPos < 0 || newPos > limit) throw CursorError("seek out of bounds: 0x${newPos.toString(16)}")
        pos = newPos
    }

    fun fork(at: Int = pos): Cursor = Cursor(data, at, limit, littleEndian)
}
