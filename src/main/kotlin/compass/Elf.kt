package compass

import java.security.MessageDigest

class ElfException(message: String) : RuntimeException(message)

data class SectionDigest(
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val flags: Long,
    val link: Long,
    val sha256: String?,   // null for SHT_NOBITS (no bytes in file)
    val nobits: Boolean,
)

data class LoadSegment(val vaddr: Long, val offset: Long, val filesz: Long, val memsz: Long, val flags: Long)

data class ElfInfo(
    val is64: Boolean,
    val littleEndian: Boolean,
    val elfClass: Int,
    val machine: Int,
    val entry: Long,
    val buildId: String?,
    val sections: List<SectionDigest>,
    val loads: List<LoadSegment>,
) {
    fun section(name: String): SectionDigest? = sections.firstOrNull { it.name == name }

    /** Minimum PT_LOAD vaddr; default link-time base for relocatable images. */
    val minLoadVaddr: Long get() = loads.minOfOrNull { it.vaddr } ?: 0L
}

class ElfReader(private val bytes: ByteArray) {
    private var little = true
    private var is64 = true

    private fun u16(off: Int): Int {
        if (off < 0 || off + 2 > bytes.size) throw ElfException("ELF: truncated u16 at $off")
        val b0 = bytes[off].toInt() and 0xff
        val b1 = bytes[off + 1].toInt() and 0xff
        return if (little) b0 or (b1 shl 8) else (b0 shl 8) or b1
    }

    private fun u32(off: Int): Long {
        if (off < 0 || off + 4 > bytes.size) throw ElfException("ELF: truncated u32 at $off")
        var v = 0L
        if (little) for (i in 0..3) v = v or ((bytes[off + i].toLong() and 0xff) shl (i * 8))
        else for (i in 0..3) v = (v shl 8) or (bytes[off + i].toLong() and 0xff)
        return v
    }

    private fun u64(off: Int): Long {
        if (off < 0 || off + 8 > bytes.size) throw ElfException("ELF: truncated u64 at $off")
        var v = 0L
        if (little) for (i in 0..7) v = v or ((bytes[off + i].toLong() and 0xff) shl (i * 8))
        else for (i in 0..7) v = (v shl 8) or (bytes[off + i].toLong() and 0xff)
        return v
    }

    private fun addr(off: Int): Long = if (is64) u64(off) else u32(off)
    private fun xword(off: Int): Long = if (is64) u64(off) else u32(off)

    fun parse(): ElfInfo {
        if (bytes.size < 16) throw ElfException("ELF: file too small (${bytes.size} bytes)")
        if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte())
            throw ElfException("ELF: bad magic")
        val elfClass = bytes[4].toInt() and 0xff
        is64 = when (elfClass) { 1 -> false; 2 -> true; else -> throw ElfException("ELF: bad class $elfClass") }
        little = when (bytes[5].toInt() and 0xff) { 1 -> true; 2 -> false; else -> throw ElfException("ELF: bad data encoding") }
        val machine = u16(18)
        val entry = addr(24)
        val phoff = xword(if (is64) 32 else 28)
        val shoff = xword(if (is64) 40 else 32)
        val phentsize = u16(if (is64) 54 else 42)
        val phnum = u16(if (is64) 56 else 44)
        val shentsize = u16(if (is64) 58 else 46)
        val shnum = u16(if (is64) 60 else 48)
        val shstrndx = u16(if (is64) 62 else 50)

        if (phnum > 65535 || shnum > 1_000_000) throw ElfException("ELF: unreasonable counts phnum=$phnum shnum=$shnum")

        val loads = mutableListOf<LoadSegment>()
        var i = 0
        while (i < phnum) {
            val off = (phoff + i.toLong() * phentsize).toInt()
            if (off + phentsize > bytes.size) throw ElfException("ELF: program header out of bounds")
            val ptype = u32(off)
            if (ptype == 1L) { // PT_LOAD
                if (is64) {
                    loads.add(LoadSegment(vaddr = u64(off + 16), offset = u64(off + 8), filesz = u64(off + 32), memsz = u64(off + 40), flags = u32(off + 4)))
                } else {
                    loads.add(LoadSegment(vaddr = u32(off + 8), offset = u32(off + 4), filesz = u32(off + 16), memsz = u32(off + 20), flags = u32(off + 24)))
                }
            }
            i++
        }

        val sections = mutableListOf<SectionDigest>()
        if (shoff > 0 && shnum > 0) {
            // section name string table
            val shstrOff = (shoff + shstrndx.toLong() * shentsize).toInt()
            val shstrSecOff = xword(shstrOff + if (is64) 24 else 16)
            val shstrSize = xword(shstrOff + if (is64) 32 else 20)
            fun secName(nameOff: Long): String {
                val start = (shstrSecOff + nameOff).toInt()
                if (start < 0 || start >= bytes.size || shstrSecOff + shstrSize > bytes.size) return ""
                var end = start
                val limit = minOf(bytes.size, (shstrSecOff + shstrSize).toInt())
                while (end < limit && bytes[end].toInt() != 0) end++
                return String(bytes, start, end - start, Charsets.UTF_8)
            }
            var s = 0
            while (s < shnum) {
                val off = (shoff + s.toLong() * shentsize).toInt()
                if (off + shentsize > bytes.size) throw ElfException("ELF: section header out of bounds")
                val nameOff = u32(off)
                val type = u32(off + 4)
                val flags: Long; val addrV: Long; val secOff: Long; val size: Long; val link: Long
                if (is64) {
                    flags = u64(off + 8); addrV = u64(off + 16); secOff = u64(off + 24); size = u64(off + 32); link = u32(off + 40)
                } else {
                    flags = u32(off + 8); addrV = u32(off + 12); secOff = u32(off + 16); size = u32(off + 20); link = u32(off + 24)
                }
                val nobits = type == 8L // SHT_NOBITS
                val sha = if (!nobits && size > 0) {
                    if (secOff + size > bytes.size) throw ElfException("ELF: section data out of bounds for section $s")
                    sha256(bytes, secOff.toInt(), size.toInt())
                } else null
                sections.add(SectionDigest(secName(nameOff), type, addrV, secOff, size, flags, link, sha, nobits))
                s++
            }
        }

        val buildId = findBuildId(sections)
        return ElfInfo(is64, little, elfClass, machine, entry, buildId, sections, loads)
    }

    private fun findBuildId(sections: List<SectionDigest>): String? {
        val note = sections.firstOrNull { it.name == ".note.gnu.build-id" } ?: return null
        if (note.nobits || note.size <= 0 || note.offset + note.size > bytes.size) return null
        val c = ByteCursor(bytes, note.offset.toInt(), (note.offset + note.size).toInt(), ".note.gnu.build-id")
        return try {
            while (c.remaining >= 12) {
                val namesz = c.u32().toInt()
                val descsz = c.u32().toInt()
                val type = c.u32()
                if (namesz < 0 || descsz < 0 || c.remaining < namesz + descsz) break
                val nameBytes = c.bytes(namesz)
                val padN = (namesz + 3) and 3.inv()
                if (namesz < padN) c.skip(padN - namesz)
                val descStart = c.pos
                val padD = (descsz + 3) and 3.inv()
                c.skip(padD)
                val name = String(nameBytes).trim('\u0000')
                if (type == 3L && name == "GNU") {
                    val desc = bytes.copyOfRange(descStart, descStart + descsz)
                    return desc.joinToString("") { "%02x".format(it) }
                }
            }
            null
        } catch (e: Exception) { null }
    }

    fun sectionBytes(sec: SectionDigest): ByteArray {
        if (sec.nobits) return ByteArray(0)
        if (sec.size <= 0) return ByteArray(0)
        if (sec.offset + sec.size > bytes.size) throw ElfException("ELF: section ${sec.name} out of bounds")
        return bytes.copyOfRange(sec.offset.toInt(), (sec.offset + sec.size).toInt())
    }

    companion object {
        fun sha256(data: ByteArray, off: Int = 0, len: Int = data.size): String {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(data, off, len)
            return md.digest().joinToString("") { "%02x".format(it) }
        }
    }
}
