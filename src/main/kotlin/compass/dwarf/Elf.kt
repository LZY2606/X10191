package compass.dwarf

data class ElfSection(
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val data: ByteArray,
)

data class ElfProgramHeader(val type: Long, val vaddr: Long, val filesz: Long, val memsz: Long)

data class ElfFile(
    val is64: Boolean,
    val bigEndian: Boolean,
    val machine: Int,
    val sections: List<ElfSection>,
    val programHeaders: List<ElfProgramHeader>,
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    /** Lowest p_vaddr among PT_LOAD segments: the link-time base used for load-bias math. */
    val linkTimeBase: Long
        get() = programHeaders.filter { it.type == 1L }.minOfOrNull { it.vaddr } ?: 0L
}

object ElfParser {
    fun parse(bytes: ByteArray): ElfFile {
        val r = Reader(bytes, "elf")
        if (bytes.size < 16 || bytes[0] != 0x7F.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw DwarfException("not an ELF file")
        val is64 = bytes[4] == 2.toByte()
        val bigEndian = bytes[5] == 2.toByte()
        val rr = Reader(bytes, "elf", 0, bigEndian)
        rr.seek(16)
        rr.u16() // e_type
        val machine = rr.u16()
        rr.u32() // e_version
        if (is64) { rr.u64() } else { rr.u32() } // e_entry
        val phoff = if (is64) rr.u64() else rr.u32()
        val shoff = if (is64) rr.u64() else rr.u32()
        rr.u32() // flags
        rr.u16() // ehsize
        val phentsize = rr.u16()
        val phnum = rr.u16()
        val shentsize = rr.u16()
        val shnum = rr.u16()
        val shstrndx = rr.u16()

        val phs = mutableListOf<ElfProgramHeader>()
        for (i in 0 until phnum) {
            val off = phoff + i.toLong() * phentsize
            if (off < 0 || off + phentsize > bytes.size) throw DwarfException("program header $i out of bounds")
            rr.seek(off.toInt())
            val ptype = rr.u32()
            if (is64) {
                rr.u32() // flags
                rr.u64(); val vaddr = rr.u64(); rr.u64(); val filesz = rr.u64(); val memsz = rr.u64()
                phs.add(ElfProgramHeader(ptype, vaddr, filesz, memsz))
            } else {
                rr.u32(); val vaddr = rr.u32(); rr.u32(); val filesz = rr.u32(); val memsz = rr.u32()
                phs.add(ElfProgramHeader(ptype, vaddr, filesz, memsz))
            }
        }

        data class RawSh(val nameOff: Long, val type: Long, val addr: Long, val offset: Long, val size: Long)
        val raw = mutableListOf<RawSh>()
        for (i in 0 until shnum) {
            val off = shoff + i.toLong() * shentsize
            if (off < 0 || off + shentsize > bytes.size) throw DwarfException("section header $i out of bounds")
            rr.seek(off.toInt())
            val nameOff = rr.u32()
            val type = rr.u32()
            if (is64) {
                rr.u64(); val addr = rr.u64(); val offset = rr.u64(); val size = rr.u64()
                raw.add(RawSh(nameOff, type, addr, offset, size))
            } else {
                rr.u32(); val addr = rr.u32(); val offset = rr.u32(); val size = rr.u32()
                raw.add(RawSh(nameOff, type, addr, offset, size))
            }
        }
        val sections = mutableListOf<ElfSection>()
        val strtab: ByteArray = if (shstrndx in raw.indices) {
            val s = raw[shstrndx]
            if (s.offset + s.size <= bytes.size) bytes.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt()) else ByteArray(0)
        } else ByteArray(0)
        for (s in raw) {
            val name = runCatching {
                if (s.nameOff < strtab.size) {
                    var end = s.nameOff.toInt()
                    while (end < strtab.size && strtab[end] != 0.toByte()) end++
                    String(strtab, s.nameOff.toInt(), end - s.nameOff.toInt(), Charsets.UTF_8)
                } else ""
            }.getOrDefault("")
            val data = if (s.type == 8L || s.size == 0L) ByteArray(0) // SHT_NOBITS
            else {
                if (s.offset < 0 || s.offset + s.size > bytes.size) throw DwarfException("section $name out of bounds")
                bytes.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
            }
            sections.add(ElfSection(name, s.type, s.addr, s.offset, s.size, data))
        }
        return ElfFile(is64, bigEndian, machine, sections, phs)
    }
}
