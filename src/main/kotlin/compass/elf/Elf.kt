package compass.elf

import compass.util.Cursor
import compass.util.DwarfException

data class ElfSection(
    val name: String,
    val type: Long,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Long,
    val entsize: Long
)

data class ElfPhdr(val type: Long, val vaddr: Long, val memsz: Long)

data class ElfImage(
    val bits: Int,
    val elfType: Int,
    val machine: Int,
    val sections: List<ElfSection>,
    val phdrs: List<ElfPhdr>,
    /** Link-time base: lowest PT_LOAD vaddr (page aligned), else lowest alloc section addr, else 0. */
    val linkBase: Long,
    /** Span of the loaded image from linkBase; used to decide whether a runtime address belongs to the module. */
    val imageSize: Long
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    fun sectionBytes(fileBytes: ByteArray, s: ElfSection): ByteArray {
        if (s.type == 8L) return ByteArray(0) // SHT_NOBITS
        val off = s.offset.toInt()
        val end = off + s.size.toInt()
        if (off < 0 || s.size < 0 || end < off || end > fileBytes.size) {
            throw DwarfException("section ${s.name} extends past end of file")
        }
        return fileBytes.copyOfRange(off, end)
    }
}

object ElfParser {
    private const val PT_LOAD = 1L
    private const val SHF_ALLOC = 0x2L

    fun parse(bytes: ByteArray): ElfImage {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte()
            || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw DwarfException("not an ELF file")
        val elfClass = bytes[4].toInt()
        val dataEnc = bytes[5].toInt()
        if (elfClass != 1 && elfClass != 2) throw DwarfException("bad ELF class $elfClass")
        if (dataEnc != 1) throw DwarfException("only little-endian ELF is supported (got encoding $dataEnc)")
        val is64 = elfClass == 2
        val c = Cursor(bytes, 0, bytes.size, "elf-header")
        c.pos = 16
        val elfType = c.u16()
        val machine = c.u16()
        c.u32() // e_version
        if (is64) {
            c.u64(); c.u32()
        } else {
            c.u32(); c.u16()
        }
        val phoff: Long
        val shoff: Long
        if (is64) {
            phoff = c.u64(); shoff = c.u64()
        } else {
            phoff = c.u32(); shoff = c.u32()
        }
        c.u32() // flags
        c.u16() // ehsize
        val phentsize = c.u16()
        val phnum = c.u16()
        val shentsize = c.u16()
        val shnum = c.u16()
        val shstrndx = c.u16()

        val phdrs = mutableListOf<ElfPhdr>()
        if (phoff > 0 && phnum > 0) {
            if (phoff + phentsize.toLong() * phnum > bytes.size) throw DwarfException("program headers out of bounds")
            for (i in 0 until phnum) {
                val pc = Cursor(bytes, (phoff + i.toLong() * phentsize).toInt(), bytes.size, "phdr")
                val type = pc.u32()
                if (is64) {
                    pc.u32(); val off = pc.u64(); val vaddr = pc.u64(); pc.u64(); pc.u64(); val memsz = pc.u64()
                    phdrs += ElfPhdr(type.toLong(), vaddr, memsz)
                } else {
                    val off = pc.u32(); val vaddr = pc.u32(); pc.u32(); pc.u32(); val memsz = pc.u32()
                    phdrs += ElfPhdr(type.toLong(), vaddr, memsz)
                }
            }
        }

        val rawSections = mutableListOf<ElfSection>()
        if (shoff > 0 && shnum > 0) {
            if (shoff + shentsize.toLong() * shnum > bytes.size) throw DwarfException("section headers out of bounds")
            for (i in 0 until shnum) {
                val sc = Cursor(bytes, (shoff + i.toLong() * shentsize).toInt(), bytes.size, "shdr")
                val nameOff = sc.u32()
                val type = sc.u32()
                if (is64) {
                    val flags = sc.u64(); val addr = sc.u64(); val off = sc.u64(); val size = sc.u64()
                    val link = sc.u32(); sc.u32(); sc.u64(); val entsize = sc.u64()
                    rawSections += ElfSection(nameOff.toString(16), type, flags, addr, off, size, link, entsize)
                } else {
                    val flags = sc.u32(); val addr = sc.u32(); val off = sc.u32(); val size = sc.u32()
                    val link = sc.u32(); sc.u32(); sc.u32(); val entsize = sc.u32()
                    rawSections += ElfSection(nameOff.toString(16), type, flags, addr, off, size, link, entsize)
                }
            }
        }
        // Resolve section names via shstrtab.
        var sections: List<ElfSection> = rawSections
        if (shstrndx in rawSections.indices) {
            val strtab = rawSections[shstrndx]
            val base = strtab.offset.toInt()
            val end = base + strtab.size.toInt()
            if (base in 0..bytes.size && end <= bytes.size) {
                sections = rawSections.map { s ->
                    val noff = s.name.toInt(16)
                    val start = base + noff
                    var e = start
                    while (e < end && bytes[e] != 0.toByte()) e++
                    val nm = if (start in base until end) String(bytes, start, e - start, Charsets.UTF_8) else ""
                    s.copy(name = nm)
                }
            }
        }

        val loads = phdrs.filter { it.type == PT_LOAD && it.memsz > 0 }
        val linkBase: Long
        val imageSize: Long
        if (loads.isNotEmpty()) {
            val minV = loads.minOf { it.vaddr } and -0x1000L
            val maxV = loads.maxOf { it.vaddr + it.memsz }
            linkBase = minV
            imageSize = maxV - minV
        } else {
            val alloc = sections.filter { it.flags and SHF_ALLOC != 0L && it.size > 0 }
            if (alloc.isNotEmpty()) {
                val minA = alloc.minOf { it.addr }
                val maxA = alloc.maxOf { it.addr + it.size }
                linkBase = minA
                imageSize = maxA - minA
            } else {
                linkBase = 0L
                imageSize = 0L
            }
        }
        return ElfImage(if (is64) 64 else 32, elfType, machine, sections, phdrs, linkBase, imageSize)
    }
}
