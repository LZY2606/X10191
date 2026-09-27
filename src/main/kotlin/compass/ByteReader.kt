package compass

class DwarfCorrupt(message: String, cause: Throwable? = null) : Exception(message, cause)
class UnknownForm(val form: Long, message: String) : Exception(message)
class DwarfLimit(message: String) : Exception(message)

data class Limits(
    val maxDepth: Int = 64,
    val maxDiesPerCu: Int = 200_000,
    val maxRefJumps: Int = 8,
    val maxRows: Int = 1_000_000,
    val maxRangeEntries: Int = 200_000,
    val maxStringLen: Int = 1 shl 16,
    val maxAbbrevEntries: Int = 200_000,
    val maxCus: Int = 4_096,
)

class ByteReader(
    val data: ByteArray,
    var pos: Int = 0,
    val limit: Int = data.size,
) {
    val remaining: Int get() = limit - pos

    fun requireBytes(n: Int, what: String = "bytes") {
        if (n < 0) throw DwarfCorrupt("negative length for $what at 0x${pos.toString(16)}")
        if (pos > limit - n) {
            throw DwarfCorrupt("truncated $what at 0x${pos.toString(16)}: need $n, have $remaining")
        }
    }

    fun u8(): Int {
        requireBytes(1, "u8")
        return data[pos++].toInt() and 0xFF
    }

    fun i8(): Int = u8().toByte().toInt()

    fun u16(): Int {
        requireBytes(2, "u16")
        var v = 0
        for (i in 0 until 2) v = v or ((data[pos + i].toInt() and 0xFF) shl (8 * i))
        pos += 2
        return v
    }

    fun u32(): Long {
        requireBytes(4, "u32")
        var v = 0L
        for (i in 0 until 4) v = v or ((data[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 4
        return v
    }

    fun u64(): Long {
        requireBytes(8, "u64")
        var v = 0L
        for (i in 0 until 8) v = v or ((data[pos + i].toLong() and 0xFF) shl (8 * i))
        pos += 8
        return v
    }

    fun take(n: Int): ByteArray {
        requireBytes(n, "block")
        val r = data.copyOfRange(pos, pos + n)
        pos += n
        return r
    }

    fun peek(n: Int): ByteArray {
        requireBytes(n, "peek")
        return data.copyOfRange(pos, pos + n)
    }

    fun cstring(): String {
        val start = pos
        while (pos < limit && data[pos] != 0.toByte()) {
            if (pos - start > Limits().maxStringLen) throw DwarfCorrupt("string too long at 0x${start.toString(16)}")
            pos++
        }
        if (pos >= limit) throw DwarfCorrupt("unterminated string at 0x${start.toString(16)}")
        val s = String(data, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7FL) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 70) throw DwarfCorrupt("uleb128 too long at 0x${pos.toString(16)}")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        do {
            b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7FL) shl shift)
            shift += 7
            if (shift > 70) throw DwarfCorrupt("sleb128 too long at 0x${pos.toString(16)}")
        } while (b and 0x80 != 0)
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun addr(size: Int): Long = when (size) {
        1 -> u8().toLong()
        2 -> u16().toLong() and 0xFFFFL
        4 -> u32()
        8 -> u64()
        else -> throw DwarfCorrupt("unsupported address size $size")
    }

    fun offset(dwarf64: Boolean): Long = if (dwarf64) u64() else u32()

    fun jumpTo(target: Int, what: String) {
        if (target < 0 || target > limit) throw DwarfCorrupt("$what points past section end: 0x${target.toString(16)} > 0x${limit.toString(16)}")
        pos = target
    }

    fun alignTo(n: Int) {
        if (n <= 1) return
        val rem = pos % n
        if (rem != 0) pos += n - rem
    }
}

/** Section lookup that records missing/corrupt sections as notes instead of throwing. */
class SectionSet(val map: Map<String, ByteArray>) {
    operator fun get(name: String): ByteArray? = map[name]
    val hasDebug: Boolean get() = map.keys.any { it.startsWith(".debug") }

    fun stringAt(sectionName: String, off: Long, notes: MutableList<String>, tag: String): String {
        val data = map[sectionName]
        if (data == null) {
            notes.add("$tag: 缺少 $sectionName，字符串不可解析")
            return "<missing:$sectionName>"
        }
        if (off < 0 || off >= data.size) {
            notes.add("$tag: 越界引用 $sectionName@0x${off.toString(16)}（section 大小 0x${data.size.toString(16)}）")
            return "<oob>"
        }
        return try {
            ByteReader(data, off.toInt(), data.size).cstring()
        } catch (e: DwarfCorrupt) {
            notes.add("$tag: $sectionName@0x${off.toString(16)} 字符串损坏 (${e.message})")
            "<corrupt>"
        }
    }
}
