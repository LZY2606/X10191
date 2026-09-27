package compass.elf

import compass.dwarf.ByteReader
import compass.model.*
import java.security.MessageDigest

const val SHT_NOBITS = 8
const val PT_LOAD = 1

private data class RawSection(
    val nameOff: Long, val type: Int, val flags: Long, val addr: Long,
    val fileOffset: Long, val size: Long, val link: Int, val info: Int,
    val addralign: Long, val entsize: Long, val noBits: Boolean
)

class ElfFile(val bytes: ByteArray, val fileName: String) {
    lateinit var endian: Endian
        private set
    var elfClass: Int = 0
        private set
    var machine: Int = 0
        private set
    var entry: Long = 0
        private set
    val sections = mutableListOf<ElfSectionInfo>()
    val segments = mutableListOf<ElfSegmentInfo>()

    private val sectionData = HashMap<String, ByteArray>()

    init { parse() }

    private fun parse() {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte())
            throw IllegalArgumentException("$fileName: not an ELF file")
        elfClass = bytes[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw IllegalArgumentException("$fileName: bad EI_CLASS")
        endian = when (bytes[5].toInt()) { 1 -> Endian.LITTLE; 2 -> Endian.BIG; else -> throw IllegalArgumentException("bad EI_DATA") }
        val r = ByteReader(bytes)
        when (elfClass) { 2 -> parse64(r); 1 -> parse32(r) }
    }

    private fun parse64(r: ByteReader) {
        r.seek(16)
        r.readU16(endian); machine = r.readU16(endian); r.readU32(endian)
        entry = r.readU64(endian)
        val phoff = r.readU64(endian); val shoff = r.readU64(endian)
        r.readU32(endian); r.readU16(endian)
        val phentsize = r.readU16(endian); val phnum = r.readU16(endian)
        val shentsize = r.readU16(endian); val shnum = r.readU16(endian); val shstrndx = r.readU16(endian)
        finishSections(readSections64(r, shoff, shnum, shentsize), shstrndx)
        parseSegments64(r, phoff, phnum, phentsize)
    }

    private fun parse32(r: ByteReader) {
        r.seek(16)
        r.readU16(endian); machine = r.readU16(endian); r.readU32(endian)
        entry = r.readU32(endian)
        val phoff = r.readU32(endian); val shoff = r.readU32(endian)
        r.readU32(endian)
        val phentsize = r.readU16(endian); val phnum = r.readU16(endian)
        val shentsize = r.readU16(endian); val shnum = r.readU16(endian); val shstrndx = r.readU16(endian)
        finishSections(readSections32(r, shoff, shnum, shentsize), shstrndx)
        parseSegments32(r, phoff, phnum, phentsize)
    }

    private fun readSections64(r: ByteReader, shoff: Long, shnum: Int, entsize: Int): List<RawSection> {
        val raw = ArrayList<RawSection>(shnum)
        for (i in 0 until shnum) {
            r.seek((shoff + i.toLong() * entsize).toInt())
            val nameOff = r.readU32(endian); val type = r.readU32(endian).toInt()
            val flags = r.readU64(endian); val addr = r.readU64(endian)
            val off = r.readU64(endian); val size = r.readU64(endian)
            val link = r.readU32(endian).toInt(); val info = r.readU32(endian).toInt()
            val align = r.readU64(endian); val entsz = r.readU64(endian)
            raw += RawSection(nameOff, type, flags, addr, off, size, link, info, align, entsz, type == SHT_NOBITS)
        }
        return raw
    }

    private fun readSections32(r: ByteReader, shoff: Long, shnum: Int, entsize: Int): List<RawSection> {
        val raw = ArrayList<RawSection>(shnum)
        for (i in 0 until shnum) {
            r.seek((shoff + i.toLong() * entsize).toInt())
            val nameOff = r.readU32(endian); val type = r.readU32(endian).toInt()
            val flags = r.readU32(endian); val addr = r.readU32(endian)
            val off = r.readU32(endian); val size = r.readU32(endian)
            val link = r.readU32(endian).toInt(); val info = r.readU32(endian).toInt()
            val align = r.readU32(endian); val entsz = r.readU32(endian)
            raw += RawSection(nameOff, type, flags, addr, off, size, link, info, align, entsz, type == SHT_NOBITS)
        }
        return raw
    }

    private fun sectionNameTable(raw: List<RawSection>, shstrndx: Int): ByteArray {
        if (shstrndx !in raw.indices) return ByteArray(0)
        val s = raw[shstrndx]
        if (s.noBits) return ByteArray(0)
        val off = s.fileOffset.toInt(); val size = s.size.toInt()
        if (off < 0 || off + size > bytes.size) return ByteArray(0)
        return bytes.copyOfRange(off, off + size)
    }

    private fun elfName(table: ByteArray, off: Long): String {
        val o = off.toInt()
        if (o < 0 || o >= table.size) return ""
        var e = o
        while (e < table.size && table[e].toInt() != 0) e++
        return String(table, o, e - o, Charsets.UTF_8)
    }

    private fun finishSections(raw: List<RawSection>, shstrndx: Int) {
        val names = sectionNameTable(raw, shstrndx)
        raw.forEach { s ->
            sections += ElfSectionInfo(
                elfName(names, s.nameOff), s.type, s.flags.toInt(), s.addr, s.fileOffset,
                s.size, s.link, s.info, s.addralign, s.entsize, s.noBits
            )
        }
    }

    private fun parseSegments64(r: ByteReader, phoff: Long, phnum: Int, entsize: Int) {
        for (i in 0 until phnum) {
            r.seek((phoff + i.toLong() * entsize).toInt())
            val type = r.readU32(endian).toInt(); val flags = r.readU32(endian).toInt()
            val off = r.readU64(endian); val vaddr = r.readU64(endian)
            r.readU64(endian)
            val filesz = r.readU64(endian); val memsz = r.readU64(endian)
            segments += ElfSegmentInfo(type, flags, off, vaddr, filesz, memsz)
        }
    }

    private fun parseSegments32(r: ByteReader, phoff: Long, phnum: Int, entsize: Int) {
        for (i in 0 until phnum) {
            r.seek((phoff + i.toLong() * entsize).toInt())
            val type = r.readU32(endian).toInt()
            val off = r.readU32(endian); val vaddr = r.readU32(endian)
            r.readU32(endian)
            val filesz = r.readU32(endian); val memsz = r.readU32(endian)
            val flags = r.readU32(endian).toInt()
            segments += ElfSegmentInfo(type, flags, off, vaddr, filesz, memsz)
        }
    }

    fun sectionByName(name: String): ElfSectionInfo? = sections.firstOrNull { it.name == name }

    private fun sectionBytesInternal(s: ElfSectionInfo): ByteArray {
        val off = s.fileOffset.toInt(); val size = s.size.toInt()
        if (s.noBits || size == 0) return ByteArray(0)
        if (off < 0 || off > bytes.size || off + size > bytes.size)
            throw BoundsException("section ${s.name} bytes [$off,+$size) outside file of ${bytes.size}")
        return bytes.copyOfRange(off, off + size)
    }

    fun sectionBytes(name: String): ByteArray? {
        val s = sectionByName(name) ?: return null
        return sectionData.getOrPut(name) { sectionBytesInternal(s) }
    }

    fun vaddrToOffset(vaddr: Long): Long? {
        for (seg in segments) {
            if (seg.type != PT_LOAD) continue
            if (vaddr in seg.vaddr until seg.vaddr + seg.filesz)
                return seg.fileOffset + (vaddr - seg.vaddr)
        }
        for (s in sections) {
            if (s.noBits || s.size == 0L || s.addr == 0L) continue
            if (vaddr in s.addr until s.addr + s.size)
                return s.fileOffset + (vaddr - s.addr)
        }
        return null
    }

    fun isLoadable(vaddr: Long): Boolean =
        segments.any { it.type == PT_LOAD && vaddr in it.vaddr until it.vaddr + it.memsz }

    fun byteSummary(): ByteSummary {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        val sectionSums = sections.filter { !it.noBits && it.size > 0 }.mapNotNull { s ->
            val b = runCatching { sectionBytesInternal(s) }.getOrNull() ?: return@mapNotNull null
            val d = MessageDigest.getInstance("SHA-256").digest(b)
            s.name to SectionSummary(d.joinToString("") { "%02x".format(it) }, s.size)
        }.toMap()
        return ByteSummary(
            sha, bytes.size.toLong(),
            bytes.hexView(16),
            bytes.copyOfRange(maxOf(0, bytes.size - 16), bytes.size).hexView(16),
            sectionSums
        )
    }
}
