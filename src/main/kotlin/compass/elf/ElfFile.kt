package compass.elf

import java.security.MessageDigest

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val bytes: ByteArray?
)

data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long
) {
    fun contains(vma: Long): Boolean = vma in vaddr until vaddr + memsz
    fun fileOffsetOf(vma: Long): Long? =
        if (vma in vaddr until vaddr + filesz) offset + (vma - vaddr) else null
}

private class RawShdr(
    val nameOff: Int,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val align: Long
)

class ElfFile(val raw: ByteArray, val fileName: String = "?") {
    val is64: Boolean
    val bigEndian: Boolean
    val machine: Int
    val type: Int
    val entry: Long
    val sections: List<ElfSection>
    val segments: List<ElfSegment>
    private val byName = HashMap<String, ElfSection>()
    val rawSha256: String

    init {
        if (raw.size < 16 || raw[0] != 0x7f.toByte() || raw[1] != 'E'.code.toByte() ||
            raw[2] != 'L'.code.toByte() || raw[3] != 'F'.code.toByte()
        ) throw DwarfParseException("$fileName: not an ELF file (bad magic)")
        val identClass = raw[4].toInt() and 0xff
        if (identClass != 1 && identClass != 2) throw DwarfParseException("$fileName: bad EI_CLASS")
        is64 = identClass == 2
        val enc = raw[5].toInt() and 0xff
        if (enc != 1 && enc != 2) throw DwarfParseException("$fileName: bad EI_DATA")
        bigEndian = enc == 2
        rawSha256 = sha256(raw)

        val r = ByteReader(raw, bigEndian, fileName)
        if (is64) {
            r.pos = 16
            type = r.u16(); machine = r.u16(); r.u32()
            entry = r.u64()
            val phoff = r.u64(); val shoff = r.u64()
            r.u32()
            r.u16()
            val phentsize = r.u16(); val phnum = r.u16()
            val shentsize = r.u16(); val shnum = r.u16(); val shstrndx = r.u16()
            if (shentsize < 64 && shnum > 0) throw DwarfParseException("$fileName: bad 64-bit shentsize")
            segments = readSegments64(r, phoff, phentsize, phnum)
            val headers = readHeaders64(r, shoff, shentsize, shnum)
            sections = attachNamesAndBytes(headers, shstrndx)
        } else {
            r.pos = 16
            type = r.u16(); machine = r.u16(); r.u32()
            entry = r.u32()
            val phoff = r.u32(); val shoff = r.u32()
            r.u32(); r.u16()
            val phentsize = r.u16(); val phnum = r.u16()
            val shentsize = r.u16(); val shnum = r.u16(); val shstrndx = r.u16()
            if (shentsize < 40 && shnum > 0) throw DwarfParseException("$fileName: bad 32-bit shentsize")
            segments = readSegments32(r, phoff, phentsize, phnum)
            val headers = readHeaders32(r, shoff, shentsize, shnum)
            sections = attachNamesAndBytes(headers, shstrndx)
        }
        sections.forEach { if (it.name.isNotEmpty()) byName.putIfAbsent(it.name, it) }
    }

    fun section(name: String): ElfSection? = byName[name]

    fun sectionDigest(name: String): String? = section(name)?.bytes?.let { sha256(it) }

    /** Lowest LOAD segment vaddr — best-effort static base for load bias computation. */
    fun imageBase(): Long? = segments
        .filter { it.type == 1 }
        .minByOrNull { it.vaddr }
        ?.vaddr

    private fun attachNamesAndBytes(headers: List<RawShdr>, strndx: Int): List<ElfSection> {
        val strtab = headers.getOrNull(strndx)
        return headers.mapIndexed { idx, h ->
            val name = if (strtab != null && strtab.type != 8 && strtab.offset >= 0) {
                val start = (strtab.offset + h.nameOff).toIntExact()
                var end = start
                if (start in 0 until raw.size) {
                    while (end < raw.size && raw[end].toInt() != 0) end++
                }
                if (end in start until raw.size) String(raw, start, end - start, Charsets.UTF_8) else ""
            } else if (idx == 0) "" else ""
            val payload = when {
                h.type == 8 -> null
                h.size <= 0 || h.offset < 0 || h.offset > raw.size -> null
                h.offset + h.size > raw.size -> null
                else -> raw.copyOfRange(h.offset.toIntExact(), (h.offset + h.size).toIntExact())
            }
            ElfSection(name, h.type, h.flags, h.addr, h.offset, h.size, h.link, h.info, h.align, payload)
        }
    }

    private fun readHeaders64(r: ByteReader, shoff: Long, entsize: Int, num: Int): List<RawShdr> {
        if (num == 0) return emptyList()
        if (num > 100_000 || shoff !in 0..raw.size) throw DwarfParseException("$fileName: bad shoff/shnum")
        val out = ArrayList<RawShdr>(num)
        for (i in 0 until num) {
            r.pos = (shoff + i.toLong() * entsize).toIntExact()
            val nameOff = r.u32().toInt()
            val stype = r.u32().toInt()
            val flags = r.u64()
            val addr = r.u64()
            val off = r.u64()
            val size = r.u64()
            val link = r.u32().toInt()
            val info = r.u32().toInt()
            val align = r.u64()
            r.u64()
            out.add(RawShdr(nameOff, stype, flags, addr, off, size, link, info, align))
        }
        return out
    }

    private fun readHeaders32(r: ByteReader, shoff: Long, entsize: Int, num: Int): List<RawShdr> {
        if (num == 0) return emptyList()
        if (num > 100_000 || shoff !in 0..raw.size) throw DwarfParseException("$fileName: bad shoff/shnum")
        val out = ArrayList<RawShdr>(num)
        for (i in 0 until num) {
            r.pos = (shoff + i.toLong() * entsize).toIntExact()
            val nameOff = r.u32().toInt()
            val stype = r.u32().toInt()
            val flags = r.u32()
            val addr = r.u32()
            val off = r.u32()
            val size = r.u32()
            val link = r.u32().toInt()
            val info = r.u32().toInt()
            val align = r.u32()
            r.u32()
            out.add(RawShdr(nameOff, stype, flags, addr, off, size, link, info, align))
        }
        return out
    }

    private fun readSegments64(r: ByteReader, phoff: Long, entsize: Int, num: Int): List<ElfSegment> {
        if (phoff <= 0 || num > 1000 || phoff > raw.size) return emptyList()
        val out = ArrayList<ElfSegment>(num)
        for (i in 0 until num) {
            r.pos = (phoff + i.toLong() * entsize).toIntExact()
            val ptype = r.u32().toInt(); val pflags = r.u32().toInt()
            val off = r.u64(); val vaddr = r.u64(); val paddr = r.u64()
            val filesz = r.u64(); val memsz = r.u64(); val align = r.u64()
            out.add(ElfSegment(ptype, pflags, off, vaddr, paddr, filesz, memsz, align))
        }
        return out
    }

    private fun readSegments32(r: ByteReader, phoff: Long, entsize: Int, num: Int): List<ElfSegment> {
        if (phoff <= 0 || num > 1000 || phoff > raw.size) return emptyList()
        val out = ArrayList<ElfSegment>(num)
        for (i in 0 until num) {
            r.pos = (phoff + i.toLong() * entsize).toIntExact()
            val ptype = r.u32().toInt()
            val off = r.u32(); val vaddr = r.u32(); val paddr = r.u32()
            val filesz = r.u32(); val memsz = r.u32()
            val pflags = r.u32().toInt(); val align = r.u32()
            out.add(ElfSegment(ptype, pflags, off, vaddr, paddr, filesz, memsz, align))
        }
        return out
    }

    private fun Long.toIntExact(): Int {
        if (this < 0 || this > Int.MAX_VALUE.toLong()) throw DwarfParseException("$fileName: offset too large: $this")
        return toInt()
    }

    companion object {
        fun sha256(b: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    }
}
