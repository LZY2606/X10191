package compass.elf

/**
 * Minimal ELF view: header, section headers and raw section bytes.
 * Supports 32/64-bit, LE/BE, and records section file offsets/addresses so
 * callers can map a runtime address back to a containing section.
 */
class ElfException(message: String) : RuntimeException(message)

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
)

data class ElfHeader(
    val elfClass: Int,          // 1 = 32 bit, 2 = 64 bit
    val endian: ByteReader.Endian,
    val type: Int,
    val machine: Int,
    val entry: Long,
    val phoff: Long,
    val shoff: Long,
    val phentsize: Int,
    val phnum: Int,
    val shentsize: Int,
    val shnum: Int,
    val shstrndx: Int,
)

class ElfFile(val data: ByteArray) {
    val header: ElfHeader
    val sections: List<ElfSection>
    private val byName: Map<String, ElfSection>

    init {
        if (data.size < 16 || data[0] != 0x7f.toByte() ||
            data[1] != 'E'.code.toByte() || data[2] != 'L'.code.toByte() || data[3] != 'F'.code.toByte()
        ) {
            throw ElfException("not an ELF file (bad magic)")
        }
        val elfClass = data[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw ElfException("bad EI_CLASS ${data[4]}")
        val endian = when (data[5].toInt()) {
            1 -> ByteReader.Endian.LITTLE
            2 -> ByteReader.Endian.BIG
            else -> throw ElfException("bad EI_DATA ${data[5]}")
        }
        val r = ByteReader(data, if (elfClass == 2) 16 else 16, endian)
        // e_type(2) e_machine(2) e_version(4)
        val type = r.u2()
        val machine = r.u2()
        r.u4() // version
        val entry: Long
        val phoff: Long
        val shoff: Long
        if (elfClass == 2) {
            entry = r.u8(); phoff = r.u8(); shoff = r.u8()
        } else {
            entry = r.u4(); phoff = r.u4(); shoff = r.u4()
        }
        r.u4() // e_flags
        r.u2() // e_ehsize
        val phentsize = r.u2()
        val phnum = r.u2()
        val shentsize = r.u2()
        val shnum = r.u2()
        val shstrndx = r.u2()
        header = ElfHeader(elfClass, endian, type, machine, entry, phoff, shoff,
            phentsize, phnum, shentsize, shnum, shstrndx)

        if (shoff <= 0L || shnum <= 0) throw ElfException("ELF has no section headers")
        if (shstrndx < 0 || shstrndx >= shnum) throw ElfException("bad e_shstrndx $shstrndx")

        // section header string table
        val shstr = readSectionHeader(shstrndx, shoff, shentsize, elfClass)
        val namesStart = shstr.offset.toInt()
        val namesEnd = (shstr.offset + shstr.size).toInt()
        if (namesStart < 0 || namesEnd > data.size) throw ElfException(".shstrtab out of file")

        val raw = ArrayList<ElfSection>(shnum)
        for (i in 0 until shnum) {
            val sh = readSectionHeader(i, shoff, shentsize, elfClass)
            val nm = if (sh.nameOffset == 0L) "" else readName(sh.nameOffset.toInt(), namesStart, namesEnd)
            raw += ElfSection(nm, sh.type, sh.flags, sh.addr, sh.offset, sh.size, sh.link, sh.info, sh.addralign)
        }
        sections = raw
        byName = raw.associateBy { it.name }
    }

    private data class RawShdr(
        val nameOffset: Long, val type: Int, val flags: Long, val addr: Long,
        val offset: Long, val size: Long, val link: Int, val info: Int, val addralign: Long,
    )

    private fun readSectionHeader(index: Int, shoff: Long, shentsize: Int, elfClass: Int): RawShdr {
        val off = (shoff + index.toLong() * shentsize).toInt()
        if (off < 0 || off + shentsize > data.size) throw ElfException("section header $index out of file")
        val r = ByteReader(data, off, header.endian)
        return if (elfClass == 2) {
            val name = r.u4().toLong()
            val type = r.u4().toInt()
            val flags = r.u8()
            val addr = r.u8()
            val offset = r.u8()
            val size = r.u8()
            val link = r.u4()
            val info = r.u4()
            val align = r.u8()
            r.u8() // entsize
            RawShdr(name, type, flags, addr, offset, size, link, info, align)
        } else {
            val name = r.u4().toLong()
            val type = r.u4().toInt()
            val flags = r.u4()
            val addr = r.u4()
            val offset = r.u4()
            val size = r.u4()
            val link = r.u4().toInt()
            val info = r.u4().toInt()
            val align = r.u4()
            r.u4() // entsize
            RawShdr(name, type, flags, addr, offset, size, link, info, align)
        }
    }

    private fun readName(off: Int, start: Int, end: Int): String {
        var p = start + off
        if (p < start || p >= end) throw ElfException("section name offset $off out of .shstrtab")
        val begin = p
        while (p < end && data[p].toInt() != 0) p++
        return String(data, begin, p - begin, Charsets.UTF_8)
    }

    fun section(name: String): ElfSection? = byName[name]

    /** Bytes of [section], or empty array if absent; rejects sections that run past EOF. */
    fun sectionBytes(section: ElfSection): ByteArray {
        val start = section.offset.toInt()
        val len = section.size.toInt()
        if (start < 0 || len < 0 || start.toLong() + len > data.size.toLong()) {
            throw ElfException("section ${section.name} file range out of bounds")
        }
        return data.copyOfRange(start, start + len)
    }

    fun sectionBytesOrNull(name: String): ByteArray? =
        section(name)?.let { runCatching { sectionBytes(it) }.getOrNull() }

    /** SHT_ALLOC sections that occupy a runtime address range. */
    fun allocSections(): List<ElfSection> =
        sections.filter { it.size > 0 && it.flags and 0x2L != 0L && it.addr != 0L }

    /**
     * Find the alloc section containing the given file-relative (unrelocated)
     * vaddr. Returns null when the address falls in a gap.
     */
    fun sectionForVaddr(vaddr: Long): ElfSection? =
        allocSections().firstOrNull { vaddr >= it.addr && vaddr < it.addr + it.size }
}
