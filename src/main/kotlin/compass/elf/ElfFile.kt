package compass.elf

import compass.ByteReader
import compass.DwarfTruncationException
import java.security.MessageDigest

/** Section number SHN_XINDEX: real section count lives in section 0's sh_link field. */
private const val SHN_UNDEF = 0
private const val SHN_XINDEX = 0xffff
private const val SHT_NOBITS = 8
private const val SHT_SYMTAB = 2
private const val SHT_STRTAB = 3
private const val PT_LOAD = 1

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val data: ByteArray?,
) {
    val isAllocated: Boolean get() = flags and 0x2L != 0L // SHF_ALLOC
}

data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val fileSize: Long,
    val memSize: Long,
) {
    /** Translate a file offset that belongs to a PT_LOAD segment to its link-time vaddr. */
    fun fileOffsetToVaddr(fileOffset: Long): Long? =
        if (fileOffset in offset until offset + fileSize) vaddr + (fileOffset - offset) else null
}

data class ElfFile(
    val elfClass: Int,
    val littleEndian: Boolean,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val fileBytes: ByteArray,
    val sectionNameTable: Map<String, ElfSection>,
    val elfType: Int,
    val machine: Int,
) {
    fun section(name: String): ElfSection? = sectionNameTable[name]

    /**
     * File-relative virtual address of the first allocated byte: for ET_DYN this is what a
     * runtime load bias is added against. We compute the lowest PT_LOAD vaddr.
     */
    val preferredImageBase: Long by lazy {
        segments.filter { it.type == PT_LOAD && it.fileSize > 0 }.minOfOrNull { it.vaddr } ?: 0L
    }
}

data class ByteSummary(
    val sha256: String,
    val sizeBytes: Long,
    val first16Hex: String,
)

fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

object ElfParser {

    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() ||
            bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            throw IllegalArgumentException("not an ELF file (bad magic)")
        }
        val elfClass = bytes[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw IllegalArgumentException("unknown EI_CLASS=${bytes[4]}")
        val dataEncoding = bytes[5].toInt()
        val littleEndian = when (dataEncoding) {
            1 -> true
            2 -> false
            else -> throw IllegalArgumentException("unknown EI_DATA=$dataEncoding")
        }
        val r = ByteReader(bytes, 0, bytes.size, littleEndian)
        r.seek(16)
        val elfType = r.u16()
        val machine = r.u16()
        r.u32() // e_version
        if (elfClass == 2) {
            r.u64() // e_entry
        } else {
            r.u32() // e_entry
        }
        val ePhoff = if (elfClass == 2) r.u64() else r.u32()
        val eShoff = if (elfClass == 2) r.u64() else r.u32()
        r.u32() // e_flags
        r.u16() // e_ehsize
        val ePhentsize = r.u16()
        val ePhnum = r.u16()
        val eShentsize = r.u16()
        var eShnum = r.u16()
        var eShstrndx = r.u16()

        // Extended numbering: real values come from section header 0.
        var shstrSectionLink = -1
        if (eShnum == 0 && eShoff != 0L) {
            val zr = readerAt(bytes, eShoff, elfClass, littleEndian)
            if (elfClass == 2) {
                zr.u32(); zr.u32(); zr.u64(); zr.u64(); zr.u64(); zr.u64(); zr.u64()
                eShnum = zr.u32().toInt(); shstrSectionLink = zr.u32().toInt()
            } else {
                zr.u32(); zr.u32(); zr.u32(); zr.u32(); zr.u32(); zr.u32()
                eShnum = zr.u32().toInt(); shstrSectionLink = zr.u32().toInt()
            }
        }

        val rawHeaders = ArrayList<LongArray>(eShnum)
        for (i in 0 until eShnum) {
            val off = eShoff + i.toLong() * eShentsize
            val hr = readerAt(bytes, off, elfClass, littleEndian)
            if (elfClass == 2) {
                val name = hr.u32().toInt()
                val type = hr.u32().toInt()
                val flags = hr.u64()
                val addr = hr.u64()
                val offset = hr.u64()
                val size = hr.u64()
                val link = hr.u32().toInt()
                rawHeaders += longArrayOf(name.toLong(), type.toLong(), flags, addr, offset, size, link.toLong())
            } else {
                val name = hr.u32().toInt()
                val type = hr.u32().toInt()
                val flags = hr.u32()
                val addr = hr.u32()
                val offset = hr.u32()
                val size = hr.u32()
                val link = hr.u32()
                rawHeaders += longArrayOf(name.toLong(), type.toLong(), flags.toLong(), addr.toLong(), offset.toLong(), size.toLong(), link.toLong())
            }
        }

        if (eShstrndx == SHN_XINDEX) eShstrndx = shstrSectionLink

        val shstr = rawHeaders.getOrNull(eShstrndx)?.let { decodeHeader(it) }
        val shstrBytes = shstr?.let { readSectionBytes(bytes, it) }

        val sections = rawHeaders.mapIndexed { idx, packed ->
            val h = decodeHeader(packed)
            val name = if (shstrBytes != null && idx != SHN_UNDEF) readName(shstrBytes, h.nameOffset, littleEndian) else ""
            val data = if (h.type == SHT_NOBITS) null else readSectionBytes(bytes, h)
            ElfSection(name, h.type, h.flags, h.addr, h.offset, h.size, h.link, data)
        }

        val segments = (0 until ePhnum).map { i ->
            val pr = readerAt(bytes, ePhoff + i.toLong() * ePhentsize, elfClass, littleEndian)
            if (elfClass == 2) {
                val type = pr.u32().toInt(); val flags = pr.u32().toInt()
                val offset = pr.u64(); val vaddr = pr.u64()
                pr.u64() // paddr
                val filesz = pr.u64(); val memsz = pr.u64()
                ElfSegment(type, flags, offset, vaddr, filesz, memsz)
            } else {
                val type = pr.u32().toInt(); val offset = pr.u32(); val vaddr = pr.u32()
                pr.u32()
                val filesz = pr.u32(); val memsz = pr.u32(); val flags = pr.u32().toInt()
                pr.u32()
                ElfSegment(type, flags, offset.toLong(), vaddr.toLong(), filesz.toLong(), memsz.toLong())
            }
        }

        val byName = sections.filter { it.name.isNotEmpty() }.associateBy { it.name }
        return ElfFile(elfClass, littleEndian, sections, segments, bytes, byName, elfType, machine)
    }

    private fun readerAt(bytes: ByteArray, off: Long, elfClass: Int, le: Boolean): ByteReader {
        if (off < 0 || off >= bytes.size) throw DwarfTruncationException("ELF header offset $off out of file")
        return ByteReader(bytes, off.toInt(), bytes.size, le)
    }

    private fun readSectionBytes(bytes: ByteArray, h: DecodedHeader): ByteArray {
        if (h.offset < 0 || h.size < 0 || h.offset + h.size > bytes.size.toLong()) {
            throw DwarfTruncationException("section ${h.nameOffset} [$h.offset,+$h.size] out of file")
        }
        return bytes.copyOfRange(h.offset.toInt(), (h.offset + h.size).toInt())
    }

    private fun readName(table: ByteArray, offset: Int, le: Boolean): String {
        if (offset < 0 || offset >= table.size) return ""
        val end = (offset until table.size).firstOrNull { table[it].toInt() == 0 } ?: table.size
        return String(table, offset, end - offset, Charsets.UTF_8)
    }
}

internal data class DecodedHeader(
    val nameOffset: Int, val type: Int, val flags: Long,
    val addr: Long, val offset: Long, val size: Long, val link: Int,
)

private fun decodeHeader(packed: RawHeader) = DecodedHeader(
    packed[0].toInt(), packed[1].toInt(), packed[2], packed[3], packed[4], packed[5], packed[6].toInt(),
)
