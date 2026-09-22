package compass.elf

import compass.util.ByteReader
import compass.util.ParseException
import java.security.MessageDigest

data class ElfSection(
    val index: Int,
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val align: Long,
    val entsize: Long
) {
    val isAllocated: Boolean get() = flags and 0x2L != 0L
}

data class ProgramHeader(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long
) {
    val isLoad: Boolean get() = type == PT_LOAD
    companion object { const val PT_LOAD = 1; const val PT_NOTE = 4 }
}

class ElfFile(
    val fileName: String,
    val bytes: ByteArray,
    val classBits: Int,
    val littleEndian: Boolean,
    val osabi: Int,
    val type: Int,
    val machine: Int,
    val entry: Long,
    val flags: Long,
    val sections: List<ElfSection>,
    val programHeaders: List<ProgramHeader>
) {
    private val byName = sections.associateBy { it.name }
    fun section(name: String): ElfSection? = byName[name]

    fun sectionBytes(name: String): ByteArray? {
        val s = byName[name] ?: return null
        return readSectionBytes(s)
    }

    fun readSectionBytes(s: ElfSection): ByteArray {
        val off = s.offset
        val size = s.size
        if (size == 0L) return ByteArray(0)
        if (off < 0 || size < 0 || off > bytes.size || off + size > bytes.size) {
            throw ParseException("section '${s.name}' bytes out of file bounds (off=$off size=$size filesz=${bytes.size})")
        }
        return bytes.copyOfRange(off.toInt(), (off + size).toInt())
    }

    fun sectionReader(name: String): ByteReader? {
        val s = byName[name] ?: return null
        val data = readSectionBytes(s)
        return ByteReader(data, 0, data.size)
    }

    /** Lowest p_vaddr of a PT_LOAD segment; a conservative static link base. */
    fun staticLoadBase(): Long =
        programHeaders.filter { it.isLoad }.minOfOrNull { it.vaddr } ?: 0L

    /** File range that maps [vaddr] (for allocated sections/segments), else null. */
    fun fileOffsetForVaddr(vaddr: Long): Long? {
        for (p in programHeaders) {
            if (p.isLoad && vaddr >= p.vaddr && vaddr < p.vaddr + p.filesz) {
                return p.offset + (vaddr - p.vaddr)
            }
        }
        val sec = sections.firstOrNull { it.isAllocated && it.size > 0 && vaddr >= it.addr && vaddr < it.addr + it.size }
        return sec?.let { it.offset + (vaddr - it.addr) }
    }

    val sha256: String by lazy {
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }

    /** GNU build-id from any PT_NOTE / SHT_NOTE, hex encoded; null when absent. */
    val buildId: String? by lazy { readBuildId() }

    private fun readBuildId(): String? {
        for (p in programHeaders) {
            if (p.type == ProgramHeader.PT_NOTE && p.filesz > 0) {
                parseNote(p.offset, p.filesz)?.let { return it }
            }
        }
        for (s in sections) {
            if (s.type == 7 /* SHT_NOTE */ && s.size > 0) {
                parseNote(s.offset, s.size)?.let { return it }
            }
        }
        return null
    }

    private fun parseNote(offset: Long, size: Long): String? {
        return try {
            val start = offset.toInt()
            val r = ByteReader(bytes, start, size.toInt())
            val end = r.sectionEnd
            while (r.remaining() >= 12) {
                val namesz = r.u32(littleEndian).toInt()
                val descsz = r.u32(littleEndian).toInt()
                val ntype = r.u32(littleEndian).toInt()
                if (namesz > r.remaining() || descsz > r.remaining()) break
                val nameBytes = r.bytes(namesz)
                val name = String(nameBytes.takeWhile { it.toInt() != 0 }.toByteArray())
                r.position = start + ((r.position - start + 3) and 3.inv())
                val desc = r.bytes(descsz)
                r.position = start + ((r.position - start + 3) and 3.inv())
                if (ntype == 3 && name == "GNU") {
                    return desc.joinToString("") { "%02x".format(it) }
                }
                if (r.position >= end) break
            }
            null
        } catch (_: Exception) { null }
    }
}

object ElfParser {
    private val MAGIC = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())

    fun parse(bytes: ByteArray, fileName: String = "<memory>"): ElfFile {
        if (bytes.size < 16) throw ParseException("file too small to be ELF")
        for (i in MAGIC.indices) if (bytes[i] != MAGIC[i]) throw ParseException("bad ELF magic")
        val classByte = bytes[4].toInt()
        val classBits = when (classByte) { 1 -> 32; 2 -> 64; else -> throw ParseException("unknown EI_CLASS=$classByte") }
        val endianByte = bytes[5].toInt()
        val littleEndian = when (endianByte) { 1 -> true; 2 -> false; else -> throw ParseException("unknown EI_DATA=$endianByte") }
        val osabi = bytes[7].toInt()

        val r = ByteReader(bytes)
        r.position = 16
        val type = r.u16(littleEndian)
        val machine = r.u16(littleEndian)
        val version = r.u32(littleEndian)
        if (version != 1L) throw ParseException("unexpected ELF version $version")

        if (classBits == 64) {
            val entry = r.u64(littleEndian)
            val phoff = r.u64(littleEndian)
            val shoff = r.u64(littleEndian)
            val flags = r.u32(littleEndian)
            val ehsize = r.u16(littleEndian)
            val phentsize = r.u16(littleEndian)
            val phnum = r.u16(littleEndian)
            val shentsize = r.u16(littleEndian)
            val shnum = r.u16(littleEndian)
            val shstrndx = r.u16(littleEndian)
            val phdrs = parseProgramHeaders64(r, phoff, phentsize, phnum, littleEndian)
            val sections = parseSections64(r, shoff, shentsize, shnum, shstrndx, littleEndian)
            return ElfFile(fileName, bytes, classBits, littleEndian, osabi, type, machine, entry, flags, sections, phdrs)
        } else {
            val entry = r.u32(littleEndian)
            val phoff = r.u32(littleEndian)
            val shoff = r.u32(littleEndian)
            val flags = r.u32(littleEndian)
            val ehsize = r.u16(littleEndian)
            val phentsize = r.u16(littleEndian)
            val phnum = r.u16(littleEndian)
            val shentsize = r.u16(littleEndian)
            val shnum = r.u16(littleEndian)
            val shstrndx = r.u16(littleEndian)
            val phdrs = parseProgramHeaders32(r, phoff, phentsize, phnum, littleEndian)
            val sections = parseSections32(r, shoff, shentsize, shnum, shstrndx, littleEndian)
            return ElfFile(fileName, bytes, classBits, littleEndian, osabi, type, machine, entry, flags, sections, phdrs)
        }
    }

    private fun parseProgramHeaders64(r: ByteReader, off: Long, entsz: Int, num: Int, le: Boolean): List<ProgramHeader> {
        if (off == 0L || num == 0) return emptyList()
        val out = ArrayList<ProgramHeader>(num)
        for (i in 0 until num) {
            r.position = (off + i * entsz).toInt()
            val ptype = r.u32(le).toInt()
            val flags = r.u32(le).toInt()
            val poff = r.u64(le); val vaddr = r.u64(le); val paddr = r.u64(le)
            val filesz = r.u64(le); val memsz = r.u64(le); val align = r.u64(le)
            out.add(ProgramHeader(ptype, flags, poff, vaddr, paddr, filesz, memsz, align))
        }
        return out
    }

    private fun parseProgramHeaders32(r: ByteReader, off: Long, entsz: Int, num: Int, le: Boolean): List<ProgramHeader> {
        if (off == 0L || num == 0) return emptyList()
        val out = ArrayList<ProgramHeader>(num)
        for (i in 0 until num) {
            r.position = (off + i * entsz).toInt()
            val ptype = r.u32(le).toInt()
            val poff = r.u32(le); val vaddr = r.u32(le); val paddr = r.u32(le)
            val filesz = r.u32(le); val memsz = r.u32(le); val flags = r.u32(le).toInt(); val align = r.u32(le)
            out.add(ProgramHeader(ptype, flags, poff, vaddr, paddr, filesz, memsz, align))
        }
        return out
    }

    private data class RawSection(
        val index: Int, val type: Int, val flags: Long, val addr: Long,
        val offset: Long, val size: Long, val link: Int, val info: Int,
        val align: Long, val entsize: Long, val nameOff: Int
    )

    private fun parseSections64(r: ByteReader, shoff: Long, shentsize: Int, shnum: Int, shstrndx: Int, le: Boolean): List<ElfSection> {
        if (shoff == 0L || shnum == 0) return listOf(emptySection())
        val raws = ArrayList<RawSection>(shnum)
        for (i in 0 until shnum) {
            r.position = (shoff + i * shentsize).toInt()
            val nameOff = r.u32(le).toInt()
            val type = r.u32(le).toInt()
            val flags = r.u64(le)
            val addr = r.u64(le); val offset = r.u64(le); val size = r.u64(le)
            val link = r.u32(le).toInt(); val info = r.u32(le).toInt()
            val align = r.u64(le); val entsize = r.u64(le)
            raws.add(RawSection(i, type, flags, addr, offset, size, link, info, align, entsize, nameOff))
        }
        return nameSections(r, raws, shstrndx)
    }

    private fun parseSections32(r: ByteReader, shoff: Long, shentsize: Int, shnum: Int, shstrndx: Int, le: Boolean): List<ElfSection> {
        if (shoff == 0L || shnum == 0) return listOf(emptySection())
        val raws = ArrayList<RawSection>(shnum)
        for (i in 0 until shnum) {
            r.position = (shoff + i * shentsize).toInt()
            val nameOff = r.u32(le).toInt()
            val type = r.u32(le).toInt()
            val flags = r.u32(le)
            val addr = r.u32(le); val offset = r.u32(le); val size = r.u32(le)
            val link = r.u32(le).toInt(); val info = r.u32(le).toInt()
            val align = r.u32(le); val entsize = r.u32(le)
            raws.add(RawSection(i, type, flags, addr, offset, size, link, info, align, entsize, nameOff))
        }
        return nameSections(r, raws, shstrndx)
    }

    private fun nameSections(r: ByteReader, raws: List<RawSection>, shstrndx: Int): List<ElfSection> {
        val str = raws.getOrNull(shstrndx)
        return raws.map { raw ->
            var name = ""
            if (str != null && raw.index > 0 && raw.nameOff < str.size) {
                name = try {
                    r.position = (str.offset + raw.nameOff).toInt()
                    r.readNTString()
                } catch (_: Exception) { "" }
            }
            ElfSection(raw.index, name, raw.type, raw.flags, raw.addr, raw.offset, raw.size,
                raw.link, raw.info, raw.align, raw.entsize)
        }
    }

    private fun emptySection() = ElfSection(0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0)
}
