package compass

import java.security.MessageDigest

class DwarfException(message: String) : Exception(message)

/** Bounds-checked little/big-endian byte cursor. Every read is range-checked;
 *  any overrun raises DwarfException so callers can isolate the bad unit. */
class Cursor(
    val buf: ByteArray,
    var pos: Int = 0,
    val limit: Int = buf.size,
    val littleEndian: Boolean = true
) {
    fun remaining(): Int = limit - pos

    fun need(n: Int) {
        if (n < 0 || pos < 0 || pos + n > limit) {
            throw DwarfException("读取越界 pos=$pos need=$n limit=$limit")
        }
    }

    fun u8(): Int {
        need(1)
        return buf[pos++].toInt() and 0xff
    }

    fun u16(): Int {
        need(2)
        val b0 = buf[pos].toInt() and 0xff
        val b1 = buf[pos + 1].toInt() and 0xff
        pos += 2
        return if (littleEndian) b0 or (b1 shl 8) else (b0 shl 8) or b1
    }

    fun u32(): Long {
        need(4)
        var v = 0L
        if (littleEndian) {
            for (i in 0 until 4) v = v or ((buf[pos + i].toLong() and 0xff) shl (8 * i))
        } else {
            for (i in 0 until 4) v = (v shl 8) or (buf[pos + i].toLong() and 0xff)
        }
        pos += 4
        return v
    }

    fun u64(): Long {
        need(8)
        var v = 0L
        if (littleEndian) {
            for (i in 0 until 8) v = v or ((buf[pos + i].toLong() and 0xff) shl (8 * i))
        } else {
            for (i in 0 until 8) v = (v shl 8) or (buf[pos + i].toLong() and 0xff)
        }
        pos += 8
        return v
    }

    fun uint(n: Int): Long = when (n) {
        1 -> u8().toLong()
        2 -> u16().toLong()
        4 -> u32()
        8 -> u64()
        else -> throw DwarfException("不支持的整数宽度 $n")
    }

    fun uleb(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 63) throw DwarfException("ULEB128 过长")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L
        var shift = 0
        var b: Int
        do {
            b = u8()
            result = result or ((b and 0x7f).toLong() shl shift)
            shift += 7
            if (shift > 70) throw DwarfException("SLEB128 过长")
        } while (b and 0x80 != 0)
        if (shift < 64 && b and 0x40 != 0) result = result or (-1L shl shift)
        return result
    }

    fun bytes(n: Int): ByteArray {
        need(n)
        val out = buf.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun cstr(): String {
        val start = pos
        while (pos < limit && buf[pos] != 0.toByte()) pos++
        if (pos >= limit) throw DwarfException("字符串缺少终止符 pos=$start")
        val s = String(buf, start, pos - start, Charsets.UTF_8)
        pos++
        return s
    }
}

fun sha256Hex(b: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

fun hex(v: Long): String = "0x" + v.toString(16)

fun parseAddress(text: String): Long? {
    val t = text.trim()
    if (t.isEmpty()) return null
    return try {
        if (t.startsWith("0x") || t.startsWith("0X")) t.substring(2).toULong(16).toLong()
        else t.toULong(16).toLong()
    } catch (e: NumberFormatException) {
        try { t.toLong() } catch (e2: NumberFormatException) { null }
    }
}

fun jsonEscape(s: String): String = buildString {
    for (ch in s) {
        when (ch) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (ch < ' ') append(String.format("\\u%04x", ch.code)) else append(ch)
        }
    }
}

fun toJson(v: Any?): String = when (v) {
    null -> "null"
    is String -> "\"${jsonEscape(v)}\""
    is Number, is Boolean -> v.toString()
    is Map<*, *> -> v.entries.joinToString(",", "{", "}") {
        "\"${jsonEscape(it.key.toString())}\":${toJson(it.value)}"
    }
    is List<*> -> v.joinToString(",", "[", "]") { toJson(it) }
    else -> toJson(v.toString())
}
