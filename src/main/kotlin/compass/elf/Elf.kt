package compass.elf

import compass.binary.ByteReader
import compass.binary.DwarfParseException
import java.security.MessageDigest

data class ElfSection(
    val nameIndex: Int,
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val entrySize: Long,
    val ordinal: Int,
)

data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
) {
    /** Translate a runtime-relative virtual address to a file offset, or null. */
    fun fileOffsetOf(vaddr: Long): Long? {
        if (vaddr < this.vaddr || vaddr >= this.vaddr + filesz) return null
        return offset + (vaddr - this.vaddr)
    }
    fun containsVaddr(vaddr: Long): Boolean = vaddr in this.vaddr until this.vaddr + filesz
}

/**
 * Minimal ELF view: identification, section header table and program headers.
 * Sufficient to locate DWARF sections and to reason about segmented addresses.
 */
class ElfFile(
    val bytes: ByteArray,
    val elfClass: Int,        // 1 = 32-bit, 2 = 64-bit
    val dataEncoding: Int,   // 1 = little, 2 = big
    val machine: Int,
    val type: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val sectionNameTable: ByteArray,
) {
    private val byName = sections.groupBy { it.name }

    fun section(name: String): ElfSection? = byName[name]?.firstOrNull()

    /** All sections with that name (DWARF can contain duplicates); stable by ordinal. */
    fun sectionsNamed(name: String): List<ElfSection> = byName[name].orEmpty().sortedBy { it.ordinal }

    fun sectionBytes(section: ElfSection): ByteArray {
        val off = section.offset
        val len = section.size
        if (off < 0 || len < 0 || off + len > bytes.size || off + len < off) {
            throw DwarfParseException("section '${section.name}' out of file bounds")
        }
        return bytes.copyOfRange(off.toInt(), (off + len).toInt())
    }

    fun sectionBytesOrNull(section: ElfSection?): ByteArray? = section?.let {
        runCatching { sectionBytes(it) }.getOrNull()
    }

    fun mapVaddrToFileOffset(vaddr: Long): Long? =
        segments.firstNotNullOfOrNull { it.fileOffsetOf(vaddr) }

    /** Base (lowest PT_LOAD vaddr), used as a reference for load bias. */
    val loadBiasReference: Long by lazy {
        segments.filter { it.type == PT_LOAD && it.filesz > 0 }.minOfOrNull { it.vaddr } ?: 0L
    }

    val sha256: String by lazy {
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }

    companion object {
        const val PT_LOAD = 1
        const val SHT_SYMTAB = 2
        const val SHT_STRTAB = 3
    }
}

object ElfParser {
    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            throw DwarfParseException("not an ELF file (bad magic)")
        }
        val cls = bytes[4].toInt()
        if (cls != 1 && cls != 2) throw DwarfParseException("unknown EI_CLASS=${bytes[4]}")
        val enc = bytes[5].toInt()
        if (enc != 1 && enc != 2) throw DwarfParseException("unknown EI_DATA=${bytes[5]}")
        val r = ByteReader(bytes)
        r.big = enc == 2

        val type: Int
        val machine: Int
        val entry: Long
        val phoff: Long
        val shoff: Long
        val phentsize: Int
        val phnum: Int
        val shentsize: Int
        val shnum: Int
        val shstrndx: Int
        if (cls == 2) {
            r.seek(16)
            type = r.u16(); machine = r.u16(); r.u32() // version
            entry = r.u64(); phoff = r.u64(); shoff = r.u64()
            r.u32() // flags
            r.u16() // ehsize
            phentsize = r.u16(); phnum = r.u16()
            shentsize = r.u16(); shnum = r.u16(); shstrndx = r.u16()
        } else {
            r.seek(16)
            type = r.u16(); machine = r.u16(); r.u32()
            entry = r.u32(); phoff = r.u32(); shoff = r.u32()
            r.u32()
            r.u16()
            phentsize = r.u16(); phnum = r.u16()
            shentsize = r.u16(); shnum = r.u16(); shstrndx = r.u16()
        }
        if (shnum == 0 || shentsize == 0) throw DwarfParseException("ELF has no section headers")

        val rawSections = ArrayList<ElfSection>(shnum)
        for (i in 0 until shnum) {
            val off = (shoff + i.toLong() * shentsize).toInt()
            if (off < 0 || off + shentsize > bytes.size) {
                throw DwarfParseException("section header $i out of bounds")
            }
            r.seek(off)
            if (cls == 2) {
                val nameIdx = r.u32().toInt()
                val stype = r.u32().toInt()
                val flags = r.u64()
                val addr = r.u64()
                val soff = r.u64()
                val size = r.u64()
                val link = r.u32().toInt()
                val info = r.u32().toInt()
                val align = r.u64()
                val entsize = r.u64()
                rawSections += ElfSection(nameIdx, "", stype, flags, addr, soff, size, link, info, align, entsize, i)
            } else {
                val nameIdx = r.u32().toInt()
                val stype = r.u32().toInt()
                val flags = r.u32()
                val addr = r.u32()
                val soff = r.u32()
                val size = r.u32()
                val link = r.u16()
                val info = r.u16()
                val align = r.u32()
                val entsize = r.u32()
                rawSections += ElfSection(nameIdx, "", stype, flags, addr, soff, size, link, info, align, entsize, i)
            }
        }

        val shstr = if (shstrndx in rawSections.indices) rawSections[shstrndx] else null
        val nameTable = if (shstr != null) {
            val o = shstr.offset
            if (o < 0 || o + shstr.size > bytes.size) ByteArray(0)
            else bytes.copyOfRange(o.toInt(), (o + shstr.size).toInt())
        } else ByteArray(0)

        fun strAt(idx: Int): String {
            if (idx <= 0 || idx >= nameTable.size) return ""
            var end = idx
            while (end < nameTable.size && nameTable[end].toInt() != 0) end++
            return String(nameTable, idx, end - idx, Charsets.UTF_8)
        }

        val sections = rawSections.map { it.copy(name = strAt(it.nameIndex)) }

        val segments = ArrayList<ElfSegment>(phnum)
        if (phentsize > 0) {
            for (i in 0 until phnum) {
                val off = (phoff + i.toLong() * phentsize).toInt()
                if (off < 0 || off + phentsize > bytes.size) continue
                r.seek(off)
                if (cls == 2) {
                    val ptype = r.u32().toInt()
                    val pflags = r.u32().toInt()
                    val poff = r.u64(); val pvaddr = r.u64(); val ppaddr = r.u64()
                    val pfilesz = r.u64(); val pmemsz = r.u64(); val palign = r.u64()
                    segments += ElfSegment(ptype, pflags, poff, pvaddr, ppaddr, pfilesz, pmemsz, palign)
                } else {
                    val ptype = r.u32().toInt()
                    val poff = r.u32(); val pvaddr = r.u32(); val ppaddr = r.u32()
                    val pfilesz = r.u32(); val pmemsz = r.u32()
                    val pflags = r.u32().toInt(); val palign = r.u32()
                    segments += ElfSegment(ptype, pflags, poff, pvaddr, ppaddr, pfilesz, pmemsz, palign)
                }
            }
        }

        return ElfFile(bytes, cls, enc, machine, type, entry, sections, segments, nameTable)
    }
}
