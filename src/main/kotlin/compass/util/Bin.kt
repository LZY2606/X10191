package compass.util

import java.security.MessageDigest

/** 越界读取：调用方应把它当作“该 section/CU 不可信”的信号，而不是致命崩溃。 */
class BoundsException(message: String) : RuntimeException(message)

/** 遇到当前实现无法安全跳过的编码（如未知 form），调用方必须隔离当前 CU，不能继续猜游标。 */
class UnsupportedEncodingException(message: String) : RuntimeException(message)

/**
 * 有界、可设大小端的游标读取器。所有读操作都检查剩余长度，ULEB/SLEB 也有字节上限。
 */
class BinReader(
    val buf: ByteArray,
    val base: Int = 0,
    val limit: Int = buf.size,
    val le: Boolean = true,
) {
    var pos: Int = base

    fun remaining(): Int = limit - pos
    fun seek(p: Int) {
        if (p < base || p > limit) throw BoundsException("seek $p out of [$base,$limit)")
        pos = p
    }

    fun slice(start: Int, len: Int): BinReader {
        if (start < base || start + len > limit || len < 0) {
            throw BoundsException("slice [$start,+$len) out of [$base,$limit)")
        }
        return BinReader(buf, start, start + len, le)
    }

    private fun take(n: Int) {
        if (remaining() < n) throw BoundsException("need $n bytes at $pos, remain ${remaining()}")
        pos += n
    }

    fun u8(): Int { take(1); return buf[pos - 1].toInt() and 0xff }
    fun s8(): Int { take(1); return buf[pos - 1].toInt() }
    fun u16(): Int { take(2); val a = pos - 2; return if (le) (buf[a].toInt() and 0xff) or (buf[a + 1].toInt() and 0xff shl 8)
        else (buf[a].toInt() and 0xff shl 8) or (buf[a + 1].toInt() and 0xff) }
    fun u32(): Long { take(4); val a = pos - 4
        var v = 0L
        if (le) for (i in 0..3) v = v or (buf[a + i].toLong() and 0xff shl (8 * i))
        else for (i in 0..3) v = (v shl 8) or (buf[a + i].toLong() and 0xff)
        return v }
    fun u64(): Long { take(8); val a = pos - 4 - 4
        var v = 0L
        if (le) for (i in 0..7) v = v or (buf[a + i].toLong() and 0xff shl (8 * i))
        else for (i in 0..7) v = (v shl 8) or (buf[a + i].toLong() and 0xff)
        return v }

    fun bytes(n: Int): ByteArray { take(n); return buf.copyOfRange(pos - n, pos) }
    fun cstring(): String {
        val start = pos
        while (pos < limit && buf[pos].toInt() != 0) pos++
        if (pos >= limit) throw BoundsException("unterminated cstring at $start")
        val s = String(buf, start, pos - start, Charsets.UTF_8)
        pos++ // 跳过结尾 0
        return s
    }

    fun uleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        while (true) {
            if (++n > maxBytes) throw BoundsException("uleb128 too long (> $maxBytes)")
            val b = u8()
            result = result or (b.toLong() and 0x7f shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw BoundsException("uleb128 overflow")
        }
    }

    fun sleb128(maxBytes: Int = 16): Long {
        var result = 0L
        var shift = 0
        var n = 0
        var b = 0
        while (true) {
            if (++n > maxBytes) throw BoundsException("sleb128 too long (> $maxBytes)")
            b = u8()
            result = result or (b.toLong() and 0x7f shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    companion object {
        fun hex(b: ByteArray, max: Int = 16): String {
            val head = b.copyOfRange(0, minOf(max, b.size)).joinToString(" ") { "%02x".format(it) }
            if (b.size <= max) return head
            val tail = b.copyOfRange(b.size - max, b.size).joinToString(" ") { "%02x".format(it) }
            return "$head … $tail"
        }
        fun sha256(b: ByteArray): String {
            val d = MessageDigest.getInstance("SHA-256").digest(b)
            return d.joinToString("") { "%02x".format(it) }
        }
    }
}
