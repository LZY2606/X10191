package com.linecompass.io

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class ParseException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Bounded, endian-aware cursor over a debug section blob.
 * Every read is bounds-checked, so a truncated or corrupt section fails
 * loudly instead of drifting the cursor and producing phantom results.
 */
class ByteReader(
    val data: ByteArray,
    private val littleEndian: Boolean = true,
    private val sectionName: String = "section",
    private var pos: Int = 0
) {
    val size: Int get() = data.size
    val offset: Int get() = pos
    val remaining: Int get() = data.size - pos
    val endian: Boolean get() = littleEndian

    fun seek(newPos: Int): ByteReader {
        if (newPos < 0 || newPos > data.size) {
            throw ParseException("$sectionName: seek to $newPos outside [0,${data.size}]")
        }
        pos = newPos
        return this
    }

    fun skip(n: Int): ByteReader {
        if (n < 0) throw ParseException("$sectionName: negative skip $n")
        return seek(pos + n)
    }

    fun slice(start: Int, length: Int): ByteReader {
        if (start < 0 || length < 0 || start.toLong() + length > data.size) {
            throw ParseException("$sectionName: slice [$start,+$length) outside [0,${data.size}]")
        }
        return ByteReader(data, littleEndian, sectionName, start).also { it.end = start + length }
    }

    private var end: Int = data.size

    fun atEnd(): Boolean = pos >= end

    fun u1(): Int {
        if (pos + 1 > data.size) throw ParseException("$sectionName: u1 at $pos OOB (size=${data.size})")
        return data[pos++].toInt() and 0xFF
    }

    fun s1(): Int = u1().let { v -> if (v and 0x80 != 0) v - 0x100 else v }

    fun bytes(n: Int): ByteArray {
        if (n < 0 || pos + n > data.size) throw ParseException("$sectionName: bytes($n) at $pos OOB")
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun u2(): Int {
        if (pos + 2 > data.size) throw ParseException("$sectionName: u2 at $pos OOB")
        val a = data[pos].toInt() and 0xFF
        val b = data[pos + 1].toInt() and 0xFF
        pos += 2
        return if (littleEndian) (b shl 8) or a else (a shl 8) or b
    }

    fun u4(): Long {
        if (pos + 4 > data.size) throw ParseException("$sectionName: u4 at $pos OOB")
        var v = 0L
        for (i in 0 until 4) {
            val b = data[pos + i].toInt() and 0xFF
            val idx = if (littleEndian) i else 3 - i
            v = v or (b.toLong() shl (idx * 8))
        }
        pos += 4
        return v
    }

    fun s4(): Int = u4().toInt()

    fun u8(): Long {
        if (pos + 8 > data.size) throw ParseException("$sectionName: u8 at $pos OOB")
        var v = 0L
        for (i in 0 until 8) {
            val b = data[pos + i].toInt() and 0xFF
            val idx = if (littleEndian) i else 7 - i
            v = v or (b.toLong() shl (idx * 8))
        }
        pos += 8
        return v
    }

    fun u(widthBytes: Int): Long = when (widthBytes) {
        1 -> u1().toLong()
        2 -> u2().toLong()
        4 -> u4()
        8 -> u8()
        else -> throw ParseException("$sectionName: unsupported address width $widthBytes")
    }

    fun uleb128(maxBytes: Int = 10): Long {
        var result = 0L
        var shift = 0
        var read = 0
        while (true) {
            if (read >= maxBytes) throw ParseException("$sectionName: ULEB128 too long at $pos (limit $maxBytes)")
            if (pos >= data.size) throw ParseException("$sectionName: ULEB128 truncated at $pos")
            val b = data[pos++].toInt() and 0xFF
            read++
            result = result or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            if (shift >= 64) throw ParseException("$sectionName: ULEB128 overflow at $pos")
        }
    }

    fun sleb128(maxBytes: Int = 10): Long {
        var result = 0L
        var shift = 0
        var read = 0
        var last = 0
        while (true) {
            if (read >= maxBytes) throw ParseException("$sectionName: SLEB128 too long at $pos (limit $maxBytes)")
            if (pos >= data.size) throw ParseException("$sectionName: SLEB128 truncated at $pos")
            val b = data[pos++].toInt() and 0xFF
            read++
            last = b
            result = result or ((b and 0x7F).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                return result
            }
            if (shift >= 64) throw ParseException("$sectionName: SLEB128 overflow at $pos")
        }
    }

    /** NUL terminated string; throws on truncation. */
    fun cString(): String {
        val start = pos
        while (pos < data.size && data[pos].toInt() != 0) pos++
        if (pos >= data.size) throw ParseException("$sectionName: string not NUL-terminated at $start")
        val s = String(data, start, pos - start, StandardCharsets.UTF_8)
        pos++
        return s
    }

    fun cStringAt(off: Int): String = seek(off).cString()
}

object Hashes {
    fun sha256(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(bytes).joinToString("") { "%02x".format(it) }
    }

    /** Stable "raw byte summary": hex prefix + sha256, used to fingerprint imported blobs. */
    fun rawSummary(bytes: ByteArray, prefix: Int = 16): String {
        val head = bytes.copyOfRange(0, minOf(prefix, bytes.size)).joinToString("") { "%02x".format(it) }
        return "sha256=${sha256(bytes)} head=$head size=${bytes.size}"
    }
}
