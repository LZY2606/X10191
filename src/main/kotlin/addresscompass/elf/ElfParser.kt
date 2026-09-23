package addresscompass.elf

import addresscompass.dwarf.ByteReader
import addresscompass.dwarf.OutOfBoundsReferenceException
import addresscompass.dwarf.SectionTruncatedException
import addresscompass.model.ElfSegment
import addresscompass.model.SectionSummary
import java.nio.ByteOrder

class ElfException(message: String) : RuntimeException(message)

data class RawSection(val summary: SectionSummary, val bytes: ByteArray?)

class ElfFile(
    val class32: Boolean,
    val endian: ByteOrder,
    val type: Int,
    val machine: Int,
    val entry: Long,
    val sections: List<RawSection>,
    val segments: List<ElfSegment>,
    val buildId: String?,
) {
    private val byName = sections.mapIndexedNotNull { i, s -> s.summary.name.takeIf { it.isNotEmpty() }?.let { it to i } }.toMap()

    fun sectionIndex(name: String): Int? = byName[name]
    fun section(name: String): RawSection? = byName[name]?.let { sections[it] }
    fun requireSection(name: String): ByteArray = section(name)?.bytes
        ?: throw ElfException("section $name not found")

    val isPic: Boolean get() = type == ET_DYN
    val isExec: Boolean get() = type == ET_EXEC

    val preferredLoadBase: Long
        get() = segments.filter { it.type == PT_LOAD }.minOfOrNull { it.vaddr } ?: 0L

    val endOfImage: Long
        get() = segments.filter { it.type == PT_LOAD }.maxOfOrNull { it.vaddr + it.memsz }
            ?: sections.maxOfOrNull { it.summary.addr + it.summary.size } ?: 0L

    companion object {
        const val ET_EXEC = 2
        const val ET_DYN = 3
        const val PT_LOAD = 1L
        const val SHT_NOBITS = 8L
        const val SHT_NOTE = 7L
    }
}

object ElfParser {
    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ElfException("not an ELF file (bad magic)")
        val classByte = bytes[4].toInt()
        if (classByte != 1 && classByte != 2) throw ElfException("invalid EI_CLASS ${bytes[4]}")
        val class32 = classByte == 1
        val endian = when (bytes[5].toInt()) {
            1 -> ByteOrder.LITTLE_ENDIAN
            2 -> ByteOrder.BIG_ENDIAN
            else -> throw ElfException("invalid EI_DATA ${bytes[5]}")
        }
        val r = ByteReader(bytes, endian = endian)
        return if (class32) parse32(r, bytes) else parse64(r, bytes)
    }

    private fun parse64(r: ByteReader, bytes: ByteArray): ElfFile {
        r.seek(16)
        val type = r.u16(); val machine = r.u16(); r.u32() // version
        val entry = r.u64()
        val phoff = r.u64(); val shoff = r.u64()
        r.u32() // flags
        val ehsize = r.u16(); val phentsize = r.u16(); val phnum = r.u16()
        val shentsize = r.u16(); val shnum = r.u16(); val shstrndx = r.u16()
        if (shoff == 0L || shnum == 0) throw ElfException("no section headers (stripped ELF)")

        val sections = readShdrs64(bytes, endian = r.endian, shoff, shnum, shentsize)
        val shstrtab = sections.getOrNull(shstrndx)
        if (shstrtab == null || shstrtab.bytes == null) throw ElfException("invalid e_shstrndx")
        val named = sections.map { raw ->
            val s = raw.summary
            val nm = readName(shstrtab.bytes, s.name.toInt(), r.endian)
            RawSection(s.copy(name = nm), raw.bytes)
        }
        val segs = readPhdrs64(bytes, r.endian, phoff, phnum, phentsize)
        val buildId = findBuildId(named, r.endian, is64 = true)
        return ElfFile(false, r.endian, type, machine, entry, named, segs, buildId)
    }

    private fun parse32(r: ByteReader, bytes: ByteArray): ElfFile {
        r.seek(16)
        val type = r.u16(); val machine = r.u16(); r.u32()
        val entry = r.u32()
        val phoff = r.u32(); val shoff = r.u32()
        r.u32()
        r.u16(); val phentsize = r.u16(); val phnum = r.u16()
        val shentsize = r.u16(); val shnum = r.u16(); val shstrndx = r.u16()
        if (shoff == 0L || shnum == 0) throw ElfException("no section headers (stripped ELF)")

        val sections = readShdrs32(bytes, r.endian, shoff, shnum, shentsize)
        val shstrtab = sections.getOrNull(shstrndx)
        if (shstrtab == null || shstrtab.bytes == null) throw ElfException("invalid e_shstrndx")
        val named = sections.map { raw ->
            val nm = readName(shstrtab.bytes, raw.summary.name.toInt(), r.endian)
            RawSection(raw.summary.copy(name = nm), raw.bytes)
        }
        val segs = readPhdrs32(bytes, r.endian, phoff, phnum, phentsize)
        val buildId = findBuildId(named, r.endian, is64 = false)
        return ElfFile(true, r.endian, type, machine, entry, named, segs, buildId)
    }

    private data class ShdrFields(
        val name: Long, val type: Long, val flags: Long, val addr: Long,
        val offset: Long, val size: Long, val link: Int, val info: Int,
        val addralign: Long, val entsize: Long, val nobits: Boolean,
    )

    private fun readShdrs64(bytes: ByteArray, endian: ByteOrder, shoff: Long, shnum: Int, shentsize: Int): List<RawSection> {
        if (shoff > Int.MAX_VALUE.toLong()) throw ElfException("shoff too large")
        val r = ByteReader(bytes, endian = endian)
        val out = ArrayList<RawSection>(shnum)
        for (i in 0 until shnum) {
            r.seek((shoff + i.toLong() * shentsize).toInt())
            val f = ShdrFields(
                name = r.u32().toLong(), type = r.u32(), flags = r.u64(), addr = r.u64(),
                offset = r.u64(), size = r.u64(), link = r.u32().toInt(), info = r.u32().toInt(),
                addralign = r.u64(), entsize = r.u64(), nobits = false,
            )
            out += materialize(bytes, f)
        }
        return out
    }

    private fun readShdrs32(bytes: ByteArray, endian: ByteOrder, shoff: Long, shnum: Int, shentsize: Int): List<RawSection> {
        val r = ByteReader(bytes, endian = endian)
        val out = ArrayList<RawSection>(shnum)
        for (i in 0 until shnum) {
            r.seek((shoff + i.toLong() * shentsize).toInt())
            val f = ShdrFields(
                name = r.u32(), type = r.u32(), flags = r.u32(), addr = r.u32(),
                offset = r.u32(), size = r.u32(), link = r.u32().toInt(), info = r.u32().toInt(),
                addralign = r.u32(), entsize = r.u32(), nobits = false,
            )
            out += materialize(bytes, f)
        }
        return out
    }

    private fun materialize(bytes: ByteArray, f: ShdrFields): RawSection {
        val nobits = f.type == ElfFile.SHT_NOBITS
        val sum = SectionSummary(
            name = "", type = f.type, flags = f.flags, addr = f.addr, fileOffset = f.offset,
            size = f.size, link = f.link, info = f.info, entsize = f.entsize, nobits = nobits, sha256 = null,
        )
        val data = if (nobits) null else try {
            if (f.offset < 0 || f.size < 0 || f.offset + f.size > bytes.size) {
                null // corrupt section header; do not fabricate bytes
            } else {
                bytes.copyOfRange(f.offset.toInt(), (f.offset + f.size).toInt())
            }
        } catch (e: Exception) { null }
        return RawSection(sum, data)
    }

    private fun readPhdrs64(bytes: ByteArray, endian: ByteOrder, phoff: Long, phnum: Int, phentsize: Int): List<ElfSegment> {
        if (phoff == 0L) return emptyList()
        val r = ByteReader(bytes, endian = endian)
        val out = ArrayList<ElfSegment>(phnum)
        for (i in 0 until phnum) {
            r.seek((phoff + i.toLong() * phentsize).toInt())
            val type = r.u32(); val flags = r.u32()
            val offset = r.u64(); val vaddr = r.u64(); r.u64() // paddr
            val filesz = r.u64(); val memsz = r.u64()
            out += ElfSegment(type, flags, offset, vaddr, filesz, memsz)
        }
        return out
    }

    private fun readPhdrs32(bytes: ByteArray, endian: ByteOrder, phoff: Long, phnum: Int, phentsize: Int): List<ElfSegment> {
        if (phoff == 0L) return emptyList()
        val r = ByteReader(bytes, endian = endian)
        val out = ArrayList<ElfSegment>(phnum)
        for (i in 0 until phnum) {
            r.seek((phoff + i.toLong() * phentsize).toInt())
            val type = r.u32(); val offset = r.u32(); val vaddr = r.u32(); r.u32()
            val filesz = r.u32(); val memsz = r.u32(); val flags = r.u32()
            out += ElfSegment(type, flags.toLong(), offset, vaddr, filesz, memsz)
        }
        return out
    }

    private fun readName(strtab: ByteArray, off: Int, endian: ByteOrder): String {
        if (off < 0 || off >= strtab.size) return ""
        var end = off
        while (end < strtab.size && strtab[end].toInt() != 0) end++
        return String(strtab, off, end - off, Charsets.UTF_8)
    }

    private fun findBuildId(sections: List<RawSection>, endian: ByteOrder, is64: Boolean): String? {
        val note = sections.firstOrNull { it.summary.name == ".note.gnu.build-id" }
            ?: sections.firstOrNull { it.summary.name == ".note.gnu.build-id".replace("-", "-") && it.summary.type == ElfFile.SHT_NOTE }
        val bytes = note?.bytes ?: return null
        return try {
            val r = ByteReader(bytes, endian = endian)
            while (r.remaining > 12) {
                val namesz = r.u32().toInt(); val descsz = r.u32().toInt(); val type = r.u32().toInt()
                val nameStart = r.pos
                r.seek(nameStart + ((namesz + 3) and 3))
                val descStart = r.pos
                if (type == 3 && descsz in 4..64) {
                    val desc = bytes.copyOfRange(descStart, descStart + descsz)
                    return desc.joinToString("") { "%02x".format(it) }
                }
                r.seek(descStart + ((descsz + 3) and 3))
            }
            null
        } catch (e: Exception) { null }
    }
}
