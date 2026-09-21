package compass.elf

/** Raw section header plus a view of the section bytes. */
class ElfSection(
    val name: String,
    val type: Long,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Long,
    val addralign: Long,
    val bytes: ByteSlice?
) {
    val isAllocated: Boolean get() = (flags and SHF_ALLOC) != 0L
}

class ElfFile(
    val elfClass: Int,       // 1 = ELF32, 2 = ELF64
    val littleEndian: Boolean,
    val type: Int,
    val machine: Int,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val entry: Long
) {
    val is64: Boolean get() = elfClass == 2

    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    /** All loadable segments, for translating a file/virtual address relationship. */
    fun allocatedSections(): List<ElfSection> = sections.filter { it.isAllocated && it.size > 0 }

    companion object
}

const val SHF_ALLOC = 0x2L
class ElfSegment(val type: Long, val offset: Long, val vaddr: Long, val filesz: Long, val memsz: Long, val flags: Int)

/**
 * Minimal, defensive ELF header/section/segment parser. Only what the compass needs:
 * section names (.shstrtab), section bytes and PT_LOAD segments.
 */
object ElfParser {
    fun parse(bytes: ByteArray): ElfFile {
        val r = ByteReader(bytes)
        if (r.size < 16) throw ParseException("文件过小, 不是 ELF")
        if (r.u8() != 0x7f || r.u8().toChar() != 'E' || r.u8().toChar() != 'L' || r.u8().toChar() != 'F') {
            throw ParseException("ELF magic 不匹配")
        }
        val elfClass = r.u8("EI_CLASS")
        if (elfClass != 1 && elfClass != 2) throw ParseException("未知 EI_CLASS=$elfClass")
        val data = r.u8("EI_DATA")
        val le = when (data) { 1 -> true; 2 -> false; else -> throw ParseException("未知 EI_DATA=$data") }
        r.seek(16)
        val type = r.u16(le, "e_type")
        val machine = r.u16(le, "e_machine")
        val entry = if (elfClass == 2) r.u64(le, "e_entry") else r.u32(le, "e_entry")
        val phoff: Long
        val shoff: Long
        val shentsize: Int; val shnum: Int; val shstrndx: Int
        val phentsize: Int; val phnum: Int
        if (elfClass == 2) {
            r.seek(0x20); phoff = r.u64(le, "e_phoff")
            shoff = r.u64(le, "e_shoff")     // 0x28
            r.seek(0x36); phentsize = r.u16(le); phnum = r.u16(le)
            r.seek(0x3a); shentsize = r.u16(le); shnum = r.u16(le); shstrndx = r.u16(le)
        } else {
            phoff = r.u32(le, "e_phoff")
            shoff = r.u32(le, "e_shoff")
            r.seek(42); phentsize = r.u16(le); phnum = r.u16(le)
            r.seek(46); shentsize = r.u16(le); shnum = r.u16(le); shstrndx = r.u16(le)
        }
        if (shnum == 0) throw ParseException("没有 section header table, 无法导入")

        val segments = parseSegments(bytes, le, elfClass, phoff, phentsize, phnum)
        val raw = parseSectionHeaders(bytes, le, elfClass, shoff, shentsize, shnum)
        val shstr = raw.getOrNull(shstrndx)
        val nameTable = if (shstr != null) ByteSlice(bytes, shstr.fileOffset.toInt(), shstr.fileSize.toInt()) else null

        val sections = raw.mapIndexed { idx, sh ->
            val nm = if (nameTable != null) readStringAt(nameTable, sh.nameOffset) else ""
            val slice = if (sh.fileSize in 1..Int.MAX_VALUE.toLong() && sh.fileOffset >= 0 &&
                sh.fileOffset + sh.fileSize <= bytes.size) {
                ByteSlice(bytes, sh.fileOffset.toInt(), sh.fileSize.toInt())
            } else null
            ElfSection(nm, sh.type, sh.flags, sh.addr, sh.fileOffset, sh.fileSize,
                sh.link, sh.info, sh.addralign, slice)
        }
        return ElfFile(elfClass, le, type, machine, sections, segments, entry)
    }

    private class RawSh(
        val nameOffset: Int, val type: Long, val flags: Long, val addr: Long,
        val fileOffset: Long, val fileSize: Long, val link: Int, val info: Long,
        val addralign: Long
    )

    private fun parseSectionHeaders(
        bytes: ByteArray, le: Boolean, elfClass: Int,
        shoff: Long, shentsize: Int, shnum: Int
    ): List<RawSh> {
        val out = ArrayList<RawSh>(shnum)
        // Shentsize may carry trailing padding; read fields at fixed offsets.
        for (i in 0 until shnum) {
            val base = (shoff + i.toLong() * shentsize).toInt()
            val r = ByteReader(bytes, base)
            if (base < 0 || base + (if (elfClass == 2) 64 else 40) > bytes.size) {
                throw ParseException("section header #$i 越界")
            }
            val name = r.u32(le, "sh_name").toInt()
            if (elfClass == 2) {
                val type = r.u32(le, "sh_type")
                val flags = r.u64(le, "sh_flags")
                val addr = r.u64(le, "sh_addr")
                val off = r.u64(le, "sh_offset")
                val size = r.u64(le, "sh_size")
                val link = r.u32(le, "sh_link").toInt()
                val info = r.u32(le, "sh_info")
                val align = r.u64(le, "sh_addralign")
                r.u64(le, "sh_entsize")
                out.add(RawSh(name, type, flags, addr, off, size, link, info, align))
            } else {
                val type = r.u32(le, "sh_type"); val flags = r.u32(le); val addr = r.u32(le)
                val off = r.u32(le); val size = r.u32(le); val link = r.u16(le); val info = r.u16(le).toLong()
                val align = r.u32(le)
                out.add(RawSh(name, type, flags, addr, off, size, link, info, align))
            }
        }
        return out
    }

    private fun parseSegments(
        bytes: ByteArray, le: Boolean, elfClass: Int,
        phoff: Long, phentsize: Int, phnum: Int
    ): List<ElfSegment> {
        val out = ArrayList<ElfSegment>()
        for (i in 0 until phnum) {
            val base = (phoff + i.toLong() * phentsize).toInt()
            if (base < 0 || base + (if (elfClass == 2) 56 else 32) > bytes.size) continue
            val r = ByteReader(bytes, base)
            if (elfClass == 2) {
                val type = r.u32(le); val flags = r.u32(le).toInt()
                val off = r.u64(le); val vaddr = r.u64(le)
                r.u64(le) // paddr
                val filesz = r.u64(le); val memsz = r.u64(le)
                out.add(ElfSegment(type, off, vaddr, filesz, memsz, flags))
            } else {
                val type = r.u32(le); val off = r.u32(le); val vaddr = r.u32(le)
                r.u32(le)
                val filesz = r.u32(le); val memsz = r.u32(le); val flags = r.u32(le).toInt()
                out.add(ElfSegment(type, off, vaddr, filesz, memsz, flags))
            }
        }
        return out
    }

    private fun readStringAt(table: ByteSlice, offset: Int): String {
        if (offset < 0 || offset >= table.length) return ""
        val end = run {
            var p = table.offset + offset
            val limit = table.offset + table.length
            while (p < limit && table.data[p] != 0.toByte()) p++
            p - table.offset
        }
        return String(table.data, table.offset + offset, end - offset, Charsets.UTF_8)
    }
}
