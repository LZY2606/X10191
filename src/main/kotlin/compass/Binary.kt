package compass

import java.security.MessageDigest

class DwarfException(message: String) : Exception(message)
class UnknownFormException(val form: Int) : DwarfException("unknown DWARF form 0x${form.toString(16)}")

/** Bounds-checked little/big-endian byte reader with LEB128 support. */
class Reader(val buf: ByteArray, start: Int, val limit: Int, val littleEndian: Boolean = true) {
    var pos: Int = start
        private set

    val remaining: Int get() = limit - pos
    fun exhausted() = pos >= limit

    private fun need(n: Int) {
        if (n < 0 || pos + n > limit) throw DwarfException("truncated section: need $n bytes at 0x${pos.toString(16)}, limit 0x${limit.toString(16)}")
    }

    fun seek(p: Int) {
        if (p < 0 || p > limit) throw DwarfException("seek out of bounds: 0x${p.toString(16)}")
        pos = p
    }

    fun skip(n: Int) { need(n); pos += n }

    fun u8(): Int { need(1); return buf[pos++].toInt() and 0xFF }

    fun u16(): Int {
        need(2)
        val b0 = buf[pos].toInt() and 0xFF; val b1 = buf[pos + 1].toInt() and 0xFF
        pos += 2
        return if (littleEndian) b0 or (b1 shl 8) else (b0 shl 8) or b1
    }

    fun u32(): Long {
        need(4)
        var v = 0L
        if (littleEndian) for (i in 3 downTo 0) v = (v shl 8) or (buf[pos + i].toLong() and 0xFF)
        else for (i in 0..3) v = (v shl 8) or (buf[pos + i].toLong() and 0xFF)
        pos += 4
        return v
    }

    fun u64(): Long {
        need(8)
        var v = 0L
        if (littleEndian) for (i in 7 downTo 0) v = (v shl 8) or (buf[pos + i].toLong() and 0xFF)
        else for (i in 0..7) v = (v shl 8) or (buf[pos + i].toLong() and 0xFF)
        pos += 8
        return v
    }

    fun uleb(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            if (shift < 64) result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 70) throw DwarfException("ULEB128 too long at 0x${pos.toString(16)}")
        }
        return result
    }

    fun sleb(): Long {
        var result = 0L; var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (shift < 64 && (b and 0x40) != 0) result = result or (-1L shl shift)
                break
            }
            if (shift > 70) throw DwarfException("SLEB128 too long at 0x${pos.toString(16)}")
        }
        return result
    }

    fun bytes(n: Int): ByteArray {
        if (n < 0) throw DwarfException("negative length $n")
        need(n)
        val out = buf.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun cstring(): String {
        var end = pos
        while (end < limit && buf[end].toInt() != 0) end++
        if (end >= limit) throw DwarfException("unterminated string at 0x${pos.toString(16)}")
        val s = String(buf, pos, end - pos, Charsets.UTF_8)
        pos = end + 1
        return s
    }
}

fun sha256Hex(data: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

data class ElfSection(
    val name: String, val type: Long, val flags: Long, val addr: Long,
    val offset: Long, val size: Long, val link: Long, val entsize: Long,
)

data class ElfFile(
    val is64: Boolean,
    val littleEndian: Boolean,
    val machine: Int,
    val sections: List<ElfSection>,
    val sha256: String,
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }
    fun sectionData(name: String, raw: ByteArray): ByteArray? {
        val s = section(name) ?: return null
        if (s.type == 8L) return null // SHT_NOBITS occupies no file bytes
        if (s.offset < 0 || s.size < 0 || s.offset + s.size > raw.size) return null
        return raw.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
    }
}

object ElfParser {
    fun parse(raw: ByteArray): ElfFile {
        if (raw.size < 16 || raw[0] != 0x7f.toByte() || raw[1] != 'E'.code.toByte()
            || raw[2] != 'L'.code.toByte() || raw[3] != 'F'.code.toByte()
        ) throw DwarfException("not an ELF file")
        val elfClass = raw[4].toInt()
        val is64 = when (elfClass) { 1 -> false; 2 -> true; else -> throw DwarfException("bad ELF class $elfClass") }
        val little = when (raw[5].toInt()) { 1 -> true; 2 -> false; else -> throw DwarfException("bad ELF endianness") }
        val r = Reader(raw, 0, raw.size, little)
        r.seek(16)
        r.skip(2) // e_type
        val machine = r.u16()
        r.skip(4) // e_version
        if (is64) r.skip(8) else r.skip(4) // e_entry
        val shoff = if (is64) r.u64() else r.u32()
        r.skip(if (is64) 4 + 4 else 4 + 4) // phoff + flags
        r.skip(2 + 2 + 2) // ehsize, phentsize, phnum
        val shentsize = r.u16()
        var shnum = r.u16()
        var shstrndx = r.u16()
        if (shoff == 0L) return ElfFile(is64, little, machine, emptyList(), sha256Hex(raw))
        if (shoff + shentsize > raw.size) throw DwarfException("section header table out of bounds")

        fun shdrAt(i: Int): Reader {
            val off = shoff + i.toLong() * shentsize
            if (off + shentsize > raw.size) throw DwarfException("section header $i out of bounds")
            return Reader(raw, off.toInt(), raw.size, little)
        }
        // Extended numbering: real counts live in section header 0.
        if (shnum == 0 || shstrndx == 0xFFFF) {
            val s0 = shdrAt(0)
            s0.skip(4)
            if (shnum == 0) shnum = (if (is64) s0.u64() else s0.u32()).toInt()
            if (shstrndx == 0xFFFF) shstrndx = (if (is64) { s0.skip(8 + 8 + 8); s0.u32().toInt() } else { s0.skip(4 + 4 + 4); s0.u32().toInt() })
        }
        if (shnum <= 0 || shnum > 1_000_000) throw DwarfException("implausible section count $shnum")
        if (shoff + shnum.toLong() * shentsize > raw.size) throw DwarfException("section header table truncated")

        data class Raw(val nameOff: Long, val type: Long, val flags: Long, val addr: Long, val off: Long, val size: Long, val link: Long, val entsize: Long)
        val raws = ArrayList<Raw>(shnum)
        for (i in 0 until shnum) {
            val s = shdrAt(i)
            val nameOff = s.u32()
            val type = s.u32()
            val flags = if (is64) s.u64() else s.u32()
            val addr = if (is64) s.u64() else s.u32()
            val off = if (is64) s.u64() else s.u32()
            val size = if (is64) s.u64() else s.u32()
            val link = s.u32()
            s.skip(4) // info
            s.skip(if (is64) 8 else 4) // addralign
            val entsize = if (is64) s.u64() else s.u32()
            raws.add(Raw(nameOff, type, flags, addr, off, size, link, entsize))
        }
        val strSec = raws.getOrNull(shstrndx)
        val sections = raws.map { rs ->
            val name = if (strSec != null && rs.nameOff < strSec.size && strSec.off + rs.nameOff < raw.size) {
                var end = (strSec.off + rs.nameOff).toInt()
                val maxEnd = minOf(raw.size, (strSec.off + strSec.size).toInt())
                while (end < maxEnd && raw[end].toInt() != 0) end++
                String(raw, (strSec.off + rs.nameOff).toInt(), end - (strSec.off + rs.nameOff).toInt(), Charsets.UTF_8)
            } else ""
            ElfSection(name, rs.type, rs.flags, rs.addr, rs.off, rs.size, rs.link, rs.entsize)
        }
        return ElfFile(is64, little, machine, sections, sha256Hex(raw))
    }
}
