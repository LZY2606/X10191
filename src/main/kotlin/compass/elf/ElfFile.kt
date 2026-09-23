package compass.elf

import compass.binary.ByteReader
import compass.binary.DwarfCorruptException
import java.security.MessageDigest

data class SectionDigest(
    val offset: Long,
    val size: Long,
    val nobits: Boolean,
    val sha256: String,
    val previewHex: String
)

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int
) {
    val nobits: Boolean get() = type == 8 // SHT_NOBITS
}

data class ElfFile(
    val bytes: ByteArray,
    val elfClass: Int,
    val littleEndian: Boolean,
    val machine: Int,
    val sections: List<ElfSection>,
    val sectionDigests: Map<String, SectionDigest>,
    val buildId: String?
) {
    val addressSize: Int get() = if (elfClass == 2) 8 else 4

    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    fun sectionBytes(section: ElfSection): ByteArray? {
        if (section.nobits) return ByteArray(0)
        val off = section.offset
        val size = section.size
        if (off < 0 || size < 0 || off > bytes.size || off + size > bytes.size) return null
        return bytes.copyOfRange(off.toInt(), (off + size).toInt())
    }

    val fileSha256: String by lazy { sha256Hex(bytes) }
}

private fun sha256Hex(data: ByteArray): String {
    val d = MessageDigest.getInstance("SHA-256").digest(data)
    return d.joinToString("") { "%02x".format(it) }
}

class ElfParseException(message: String) : RuntimeException(message)

object ElfParser {
    private const val MAX_SECTIONS = 65536
    private const val PREVIEW_BYTES = 32

    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 16) throw ElfParseException("file smaller than ELF ident")
        if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            throw ElfParseException("bad ELF magic")
        }
        val elfClass = bytes[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw ElfParseException("unknown ELF class $elfClass")
        val dataEncoding = bytes[5].toInt()
        if (dataEncoding != 1 && dataEncoding != 2) throw ElfParseException("unknown ELF data encoding")
        val le = dataEncoding == 1
        val r = ByteReader(bytes, le)

        // ELF header
        r.seek(16)
        r.u16() // e_type
        val machine = r.u16()
        r.u32() // e_version
        r.word(if (elfClass == 2) 8 else 4) // e_entry
        r.word(if (elfClass == 2) 8 else 4) // e_phoff
        val shoff = r.word(if (elfClass == 2) 8 else 4) // e_shoff
        r.u32() // e_flags
        r.u16() // e_ehsize
        r.u16() // e_phentsize
        r.u16() // e_phnum
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()

        if (shoff == 0L || shnum == 0) throw ElfParseException("no section headers")
        if (shnum >= MAX_SECTIONS) throw ElfParseException("too many sections")
        if (shoff > bytes.size) throw ElfParseException("section header table out of bounds")

        val expectedEnt = if (elfClass == 2) 64 else 40
        if (shentsize < expectedEnt) throw ElfParseException("section header entry too small")

        data class Raw(val nameOff: Int, val type: Int, val flags: Long, val addr: Long,
                       val off: Long, val size: Long, val link: Int, val info: Int)

        val raws = ArrayList<Raw>(shnum)
        for (i in 0 until shnum) {
            val base = (shoff + i.toLong() * shentsize).toInt()
            if (base.toLong() + expectedEnt > bytes.size) throw ElfParseException("section header $i truncated")
            r.seek(base)
            val nameOff = r.u32().toInt()
            val type = if (elfClass == 2) r.u32().toInt() else r.u16()
            val flags = if (elfClass == 2) r.word(8) else r.u32()
            val addr = if (elfClass == 2) r.word(8) else r.u32()
            val off = if (elfClass == 2) r.word(8) else r.u32()
            val size = if (elfClass == 2) r.word(8) else r.u32()
            val link = if (elfClass == 2) r.u32().toInt() else r.u16()
            val info = if (elfClass == 2) r.u32().toInt() else r.u16()
            raws.add(Raw(nameOff, type, flags, addr, off, size, link, info))
        }

        // section name string table
        val shstr: ByteArray = if (shstrndx == 0xffff || shstrndx >= raws.size) {
            ByteArray(0)
        } else {
            val s = raws[shstrndx]
            if (s.off >= 0 && s.size >= 0 && s.off + s.size <= bytes.size && s.type != 8) {
                bytes.copyOfRange(s.off.toInt(), (s.off + s.size).toInt())
            } else ByteArray(0)
        }
        fun shName(noff: Int): String {
            if (shstr.isEmpty() || noff < 0 || noff >= shstr.size) return ""
            var end = noff
            while (end < shstr.size && shstr[end].toInt() != 0) end++
            return String(shstr, noff, end - noff, Charsets.UTF_8)
        }

        val sections = raws.mapIndexed { idx, s ->
            val name = shName(s.nameOff).ifEmpty { if (idx == 0) "" else "<section:$idx>" }
            ElfSection(name, s.type, s.flags, s.addr, s.off, s.size, s.link, s.info)
        }

        val digests = LinkedHashMap<String, SectionDigest>()
        for (s in sections) {
            if (s.name.isEmpty()) continue
            val payload = if (s.nobits || s.offset < 0 || s.offset + s.size > bytes.size || s.offset > bytes.size) {
                null
            } else {
                bytes.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
            }
            val sha = payload?.let { sha256Hex(it) } ?: "0".repeat(64)
            val preview = payload?.copyOfRange(0, minOf(PREVIEW_BYTES, payload.size)) ?: ByteArray(0)
            digests[s.name] = SectionDigest(
                s.offset, s.size, s.nobits, sha,
                preview.joinToString("") { "%02x".format(it) }
            )
        }

        val buildId = extractBuildId(bytes, sections)

        return ElfFile(bytes, elfClass, le, machine, sections, digests, buildId)
    }

    private fun extractBuildId(bytes: ByteArray, sections: List<ElfSection>): String? {
        val notes = sections.filter { it.type == 7 || it.name == ".note.gnu.build-id" }
        for (sec in notes) {
            if (sec.nobits || sec.offset + sec.size > bytes.size || sec.offset > bytes.size) continue
            val r = ByteReader(bytes, true, sec.offset.toInt())
            val limit = (sec.offset + sec.size).toInt()
            while (r.pos < limit) {
                if (r.pos + 12 > limit) break
                val namesz = r.u32().toInt()
                val descsz = r.u32().toInt()
                val type = r.u32().toInt()
                if (namesz < 0 || descsz < 0 || r.pos.toLong() + namesz.toLong() + descsz.toLong() > limit.toLong()) break
                val name = r.bytes(namesz)
                val desc = r.bytes(descsz)
                // align to 4
                while (r.pos % 4 != 0 && r.pos < limit) r.skip(1)
                val isGnuBuildId = type == 3 &&
                    String(name, 0, name.indexOf(0).let { if (it < 0) name.size else it }, Charsets.UTF_8) == "GNU"
                if (isGnuBuildId && desc.isNotEmpty()) {
                    return desc.joinToString("") { "%02x".format(it) }
                }
            }
        }
        return null
    }
}
