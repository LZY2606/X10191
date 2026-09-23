package compass.elf

import compass.dwarf.ByteReader
import java.security.MessageDigest

data class ElfSection(
    val name: String,
    val type: Long,
    val flags: Long,
    val address: Long,
    val fileOffset: Long,
    val size: Long,
    val link: Int,
    val info: Long,
    val addralign: Long,
) {
    /** Bytes from the backing file, null when the section occupies no bytes (SHT_NOBITS). */
    var bytes: ByteArray? = null
}

data class ProgramSegment(
    val type: Long,
    val flags: Long,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val fileSize: Long,
    val memorySize: Long,
    val align: Long,
)

data class ElfFile(
    val elfClass: Int,
    val littleEndian: Boolean,
    val machine: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val segments: List<ProgramSegment>,
    val raw: ByteArray,
    val fileSha256: String,
    val buildId: String?,
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    /** Reader positioned at the start of a section, or null if the section is absent. */
    fun reader(name: String): ByteReader? {
        val s = section(name) ?: return null
        val b = s.bytes ?: return null
        return ByteReader(
            b, 0, b.size, 0, littleEndian, false, if (elfClass == 2) 8 else 4
        )
    }

    /**
     * Map a virtual link-time address to a file offset using program headers
     * (needed for SHT_NOBITS-free raw section bytes of stripped ET_EXEC/ET_DYN that
     * rely on segment layout). Returns null when not mapped.
     */
    fun vaddrToOffset(vaddr: Long): Long? {
        for (seg in segments) {
            if (seg.type != 1L) continue // PT_LOAD
            if (vaddr in seg.vaddr until seg.vaddr + seg.fileSize) {
                return seg.offset + (vaddr - seg.vaddr)
            }
        }
        // Fall back to section headers.
        for (s in sections) {
            if (s.size > 0 && vaddr in s.address until s.address + s.size) {
                return s.fileOffset + (vaddr - s.address)
            }
        }
        return null
    }
}

object ElfParser {
    private const val SHT_NOBITS = 8L
    private const val PT_NOTE = 4L

    fun parse(raw: ByteArray): ElfFile {
        require(raw.size >= 16) { "file too small to be ELF" }
        require(raw[0] == 0x7f.toByte() && raw[1] == 'E'.code.toByte() &&
            raw[2] == 'L'.code.toByte() && raw[3] == 'F'.code.toByte()) { "bad ELF magic" }
        val elfClass = raw[4].toInt()
        require(elfClass == 1 || elfClass == 2) { "unsupported ELF class $elfClass" }
        val endianByte = raw[5].toInt()
        require(endianByte == 1 || endianByte == 2) { "bad EI_DATA" }
        val le = endianByte == 1

        val r = ByteReader(raw, 0, raw.size, 16, le, false, if (elfClass == 2) 8 else 4)
        return if (elfClass == 2) parse64(r, raw, le) else parse32(r, raw, le)
    }

    private fun parse64(r: ByteReader, raw: ByteArray, le: Boolean): ElfFile {
        val type = r.u16()
        val machine = r.u16()
        val version = r.u32()
        val entry = r.u64()
        val phoff = r.u64()
        val shoff = r.u64()
        r.u32(); r.u32()
        val ehsize = r.u16()
        val phentsize = r.u16()
        val phnum = r.u16()
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()

        val sections = readSections64(raw, le, shoff, shnum, shentsize, shstrndx)
        val segments = readProgram64(raw, le, phoff, phnum, phentsize)
        return ElfFile(2, le, machine, entry, sections, segments, raw, sha256(raw),
            extractBuildId(raw, le, segments))
    }

    private fun parse32(r: ByteReader, raw: ByteArray, le: Boolean): ElfFile {
        r.u16()
        val machine = r.u16()
        r.u32()
        val entry = r.u32()
        val phoff = r.u32()
        val shoff = r.u32()
        r.u32(); r.u32()
        r.u16()
        val phentsize = r.u16()
        val phnum = r.u16()
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()

        val sections = readSections32(raw, le, shoff, shnum, shentsize, shstrndx)
        val segments = readProgram32(raw, le, phoff, phnum, phentsize)
        return ElfFile(1, le, machine, entry, sections, segments, raw, sha256(raw),
            extractBuildId(raw, le, segments))
    }

    private fun readSections64(
        raw: ByteArray, le: Boolean, shoff: Long, shnum: Int, shentsize: Int, shstrndx: Int
    ): List<ElfSection> {
        if (shnum == 0 || shoff == 0L) return emptyList()
        val rawSections = ArrayList<ElfSection>(shnum)
        for (i in 0 until shnum) {
            val r = ByteReader(raw, 0, raw.size, (shoff + i * shentsize).toInt(), le)
            val nameOff = r.u32()
            val type = r.u32()
            val flags = r.u64()
            val addr = r.u64()
            val off = r.u64()
            val size = r.u64()
            val link = r.u32()
            val info = r.u32()
            val align = r.u64()
            r.u64()
            rawSections.add(mkSection("", type.toLong(), flags.toLong(), addr, off, size, link, info.toLong(), align, raw))
        }
        val shstr = rawSections.getOrNull(shstrndx)
        val shstrBase = shstr?.fileOffset?.toInt() ?: 0
        return rawSections.mapIndexed { idx, s ->
            if (shstr != null) {
                val nameOff = ByteReader(raw, 0, raw.size,
                    (shoff + idx * shentsize).toInt(), le).u32()
                s.copy(name = readName(raw, shstrBase, nameOff.toInt()))
            } else s
        }
    }

    private fun readSections32(
        raw: ByteArray, le: Boolean, shoff: Long, shnum: Int, shentsize: Int, shstrndx: Int
    ): List<ElfSection> {
        if (shnum == 0 || shoff == 0L) return emptyList()
        val rawSections = ArrayList<ElfSection>(shnum)
        for (i in 0 until shnum) {
            val r = ByteReader(raw, 0, raw.size, (shoff + i * shentsize).toInt(), le)
            val nameOff = r.u32()
            val type = r.u32()
            val flags = r.u32()
            val addr = r.u32()
            val off = r.u32()
            val size = r.u32()
            val link = r.u32()
            val info = r.u32()
            val align = r.u32()
            r.u32()
            rawSections.add(mkSection("", type.toLong(), flags.toLong(), addr.toLong(), off.toLong(),
                size.toLong(), link, info.toLong(), align.toLong(), raw))
        }
        val shstr = rawSections.getOrNull(shstrndx)
        val shstrBase = shstr?.fileOffset?.toInt() ?: 0
        return rawSections.mapIndexed { idx, s ->
            if (shstr != null) {
                val nameOff = ByteReader(raw, 0, raw.size,
                    (shoff + idx * shentsize).toInt(), le).u32()
                s.copy(name = readName(raw, shstrBase, nameOff.toInt()))
            } else s
        }
    }

    private fun mkSection(
        name: String, type: Long, flags: Long, addr: Long, off: Long, size: Long,
        link: Int, info: Long, align: Long, raw: ByteArray
    ): ElfSection {
        val s = ElfSection(name, type, flags, addr, off, size, link, info, align)
        if (type != SHT_NOBITS && size > 0 && off >= 0 && off + size <= raw.size) {
            s.bytes = raw.copyOfRange(off.toInt(), (off + size).toInt())
        }
        return s
    }

    private fun readName(raw: ByteArray, base: Int, off: Int): String {
        var end = base + off
        if (end < 0 || end >= raw.size) return ""
        while (end < raw.size && raw[end].toInt() != 0) end++
        return String(raw, base + off, end - (base + off), Charsets.UTF_8)
    }

    private fun readProgram64(raw: ByteArray, le: Boolean, phoff: Long, phnum: Int, ent: Int)
            : List<ProgramSegment> {
        val out = ArrayList<ProgramSegment>(phnum)
        for (i in 0 until phnum) {
            val r = ByteReader(raw, 0, raw.size, (phoff + i * ent).toInt(), le)
            val type = r.u32()
            val flags = r.u32()
            val off = r.u64()
            val vaddr = r.u64()
            val paddr = r.u64()
            val filesz = r.u64()
            val memsz = r.u64()
            val align = r.u64()
            out.add(ProgramSegment(type.toLong(), flags.toLong(), off, vaddr, paddr, filesz, memsz, align))
        }
        return out
    }

    private fun readProgram32(raw: ByteArray, le: Boolean, phoff: Long, phnum: Int, ent: Int)
            : List<ProgramSegment> {
        val out = ArrayList<ProgramSegment>(phnum)
        for (i in 0 until phnum) {
            val r = ByteReader(raw, 0, raw.size, (phoff + i * ent).toInt(), le)
            val type = r.u32()
            val off = r.u32()
            val vaddr = r.u32()
            val paddr = r.u32()
            val filesz = r.u32()
            val memsz = r.u32()
            val flags = r.u32()
            val align = r.u32()
            out.add(ProgramSegment(type.toLong(), flags.toLong(), off.toLong(), vaddr.toLong(),
                paddr.toLong(), filesz.toLong(), memsz.toLong(), align.toLong()))
        }
        return out
    }

    private fun extractBuildId(raw: ByteArray, le: Boolean, segments: List<ProgramSegment>): String? {
        for (seg in segments) {
            if (seg.type != PT_NOTE || seg.fileSize <= 0) continue
            try {
                var r = ByteReader(raw, 0, raw.size, seg.offset.toInt(), le)
                val end = (seg.offset + seg.fileSize).toInt()
                while (r.position < end) {
                    val namesz = r.u32().toInt()
                    val descsz = r.u32().toInt()
                    val ntype = r.u32()
                    if (namesz < 0 || descsz < 0) break
                    val name = r.readBytes((namesz + 3) and 3)
                    val descStart = r.position
                    val desc = r.readBytes((descsz + 3) and 3)
                    if (ntype == 3 && String(name, 0, namesz.coerceAtMost(name.size).let {
                            if (it > 0) it - 1 else 0
                        }) == "GNU") {
                        // name includes NUL; check the unpadded prefix.
                    }
                    if (ntype == 3 && String(name).trimEnd('\u0000') == "GNU" && descsz in 1..128) {
                        return desc.copyOfRange(0, descsz).joinToString("") { "%02x".format(it) }
                    }
                    if (descStart + ((descsz + 3) and 3) > end) break
                }
            } catch (_: Exception) {
                // corrupt note is non-fatal
            }
        }
        return null
    }

    private fun sha256(raw: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(raw)
        return d.joinToString("") { "%02x".format(it) }
    }
}
