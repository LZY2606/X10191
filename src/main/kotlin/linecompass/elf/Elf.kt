package linecompass.elf

import linecompass.dwarf.BoundedReader
import linecompass.dwarf.DwarfFormatException
import java.nio.ByteOrder

/**
 * Minimal local ELF reader: file header, section headers (+ names) and
 * program headers. No system debugger is involved. Supports ELF32/ELF64
 * and little/big endian encodings; byte data is retained verbatim so the
 * importer can persist original-byte summaries.
 */
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
    val entsize: Long,
    val data: ByteArray,
) {
    val isAllocated: Boolean get() = flags and 0x2L != 0L // SHF_ALLOC
    override fun equals(other: Any?): Boolean = other is ElfSection && other.name == name && other.offset == offset
    override fun hashCode(): Int = 31 * name.hashCode() + offset.hashCode()
}

data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
)

data class ElfFile(
    val path: String,
    val elfClass: Int,       // 1 = 32-bit, 2 = 64-bit
    val dataEncoding: Int,   // 1 = LSB, 2 = MSB
    val machine: Int,
    val fileType: Int,       // ET_EXEC=2, ET_DYN=3, ...
    val entry: Long,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val raw: ByteArray,
) {
    private val byName = sections.associateBy { it.name }
    fun section(name: String): ElfSection? = byName[name]

    /** True when the file is a position-independent object (PIE/shared object). */
    val isDynamic: Boolean get() = fileType == 3 // ET_DYN

    /**
     * Load bias for a runtime base: for ET_DYN the lowest PT_LOAD vaddr is
     * subtracted; for ET_EXEC vaddrs are absolute and the bias is 0.
     */
    fun loadBias(runtimeBase: Long): Long {
        if (!isDynamic) return 0L
        val firstLoad = segments.filter { it.type == 1 /* PT_LOAD */ }.minByOrNull { it.vaddr }
        return if (firstLoad != null) runtimeBase - firstLoad.vaddr else runtimeBase
    }
}

object ElfParser {
    private const val EI_CLASS = 4
    private const val EI_DATA = 5

    fun parse(bytes: ByteArray, path: String = "<memory>"): ElfFile {
        if (bytes.size < 16) throw DwarfFormatException("file too small to be ELF: ${bytes.size} bytes")
        if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            throw DwarfFormatException("bad ELF magic")
        }
        val elfClass = bytes[EI_CLASS].toInt()
        val encoding = bytes[EI_DATA].toInt()
        if (elfClass != 1 && elfClass != 2) throw DwarfFormatException("unknown ELF class $elfClass")
        if (encoding != 1 && encoding != 2) throw DwarfFormatException("unknown ELF data encoding $encoding")
        val order = if (encoding == 1) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val r = BoundedReader(bytes, 0, bytes.size, "elf")

        fun u16(): Int {
            val p = r.pos
            r.skip(2)
            return readShort(bytes, p, order).toInt() and 0xffff
        }
        fun u32(): Long {
            val p = r.pos
            r.skip(4)
            return readInt(bytes, p, order).toLong() and 0xffffffffL
        }
        fun u64(): Long {
            val p = r.pos
            r.skip(8)
            return readLong(bytes, p, order)
        }

        r.seek(16, counted = false)
        val fileType = u16()
        val machine = u16()
        r.skip(4) // e_version
        if (elfClass == 2) {
            val entry = u64()
            val phoff = u64()
            val shoff = u64()
            r.skip(4) // flags
            val ehsize = u16()
            val phentsize = u16()
            val phnum = u16()
            val shentsize = u16()
            val shnum = u16()
            val shstrndx = u16()
            val segments = if (elfClass == 2) {
                readSegments64(bytes, phoff, phentsize, phnum, order)
            } else emptyList()
            val sections = readSections64(bytes, shoff, shentsize, shnum, shstrndx, order)
            return ElfFile(path, elfClass, encoding, machine, fileType, entry, sections, segments, bytes)
        } else {
            val entry = u32()
            val phoff = u32()
            val shoff = u32()
            r.skip(4)
            val ehsize = u16()
            val phentsize = u16()
            val phnum = u16()
            val shentsize = u16()
            val shnum = u16()
            val shstrndx = u16()
            val segments = readSegments32(bytes, phoff, phentsize, phnum, order)
            val sections = readSections32(bytes, shoff, shentsize, shnum, shstrndx, order)
            return ElfFile(path, elfClass, encoding, machine, fileType, entry, sections, segments, bytes)
        }
    }

    private fun readSections64(
        bytes: ByteArray, shoff: Long, shentsize: Int, shnum: Int, shstrndx: Int, order: ByteOrder
    ): List<ElfSection> {
        if (shoff <= 0 || shnum == 0) return emptyList()
        val headers = ArrayList<RawSection>(shnum)
        for (i in 0 until shnum) {
            val o = (shoff + i.toLong() * shentsize).toInt()
            if (o + 64 > bytes.size) throw DwarfFormatException("section header $i past EOF")
            headers.add(
                RawSection(
                    nameOff = readInt(bytes, o, order).toLong() and 0xffffffffL,
                    type = readInt(bytes, o + 4, order),
                    flags = readLong(bytes, o + 8, order),
                    addr = readLong(bytes, o + 16, order),
                    offset = readLong(bytes, o + 24, order),
                    size = readLong(bytes, o + 32, order),
                    link = readInt(bytes, o + 40, order),
                    info = readInt(bytes, o + 44, order),
                    addralign = readLong(bytes, o + 48, order),
                    entsize = readLong(bytes, o + 56, order),
                )
            )
        }
        return materialize(bytes, headers, shstrndx)
    }

    private fun readSections32(
        bytes: ByteArray, shoff: Long, shentsize: Int, shnum: Int, shstrndx: Int, order: ByteOrder
    ): List<ElfSection> {
        if (shoff <= 0 || shnum == 0) return emptyList()
        val headers = ArrayList<RawSection>(shnum)
        for (i in 0 until shnum) {
            val o = (shoff + i.toLong() * shentsize).toInt()
            if (o + 40 > bytes.size) throw DwarfFormatException("section header $i past EOF")
            headers.add(
                RawSection(
                    nameOff = readInt(bytes, o, order).toLong() and 0xffffffffL,
                    type = readInt(bytes, o + 4, order),
                    flags = readInt(bytes, o + 8, order).toLong() and 0xffffffffL,
                    addr = readInt(bytes, o + 12, order).toLong() and 0xffffffffL,
                    offset = readInt(bytes, o + 16, order).toLong() and 0xffffffffL,
                    size = readInt(bytes, o + 20, order).toLong() and 0xffffffffL,
                    link = readInt(bytes, o + 24, order),
                    info = readInt(bytes, o + 28, order),
                    addralign = readInt(bytes, o + 32, order).toLong() and 0xffffffffL,
                    entsize = readInt(bytes, o + 36, order).toLong() and 0xffffffffL,
                )
            )
        }
        return materialize(bytes, headers, shstrndx)
    }

    private data class RawSection(
        val nameOff: Long, val type: Int, val flags: Long, val addr: Long, val offset: Long,
        val size: Long, val link: Int, val info: Int, val addralign: Long, val entsize: Long,
    )

    private fun materialize(bytes: ByteArray, headers: List<RawSection>, shstrndx: Int): List<ElfSection> {
        if (shstrndx !in headers.indices) {
            throw DwarfFormatException("invalid shstrndx $shstrndx for ${headers.size} sections")
        }
        val strtab = headers[shstrndx]
        fun nameAt(off: Long): String {
            val start = (strtab.offset + off).toInt()
            if (start < 0 || start >= bytes.size) throw DwarfFormatException("section name offset past EOF")
            var end = start
            while (end < bytes.size && bytes[end].toInt() != 0) end++
            return String(bytes, start, end - start, Charsets.UTF_8)
        }
        return headers.map { h ->
            val start = h.offset.toInt()
            val len = h.size.toInt()
            val data = when {
                h.type == 8 /* SHT_NOBITS */ -> ByteArray(0)
                len == 0 -> ByteArray(0)
                else -> {
                    if (start < 0 || start + len > bytes.size) {
                        throw DwarfFormatException("section data past EOF: off=${h.offset} size=${h.size}")
                    }
                    bytes.copyOfRange(start, start + len)
                }
            }
            ElfSection(
                name = if (h === headers[0]) "" else nameAt(h.nameOff),
                type = h.type, flags = h.flags, addr = h.addr, offset = h.offset, size = h.size,
                link = h.link, info = h.info, addralign = h.addralign, entsize = h.entsize, data = data,
            )
        }
    }

    private fun readSegments64(
        bytes: ByteArray, phoff: Long, entsize: Int, num: Int, order: ByteOrder
    ): List<ElfSegment> {
        if (phoff <= 0 || num == 0) return emptyList()
        val out = ArrayList<ElfSegment>(num)
        for (i in 0 until num) {
            val o = (phoff + i.toLong() * entsize).toInt()
            if (o + 56 > bytes.size) throw DwarfFormatException("program header $i past EOF")
            out.add(
                ElfSegment(
                    type = readInt(bytes, o, order),
                    flags = readInt(bytes, o + 4, order),
                    offset = readLong(bytes, o + 8, order),
                    vaddr = readLong(bytes, o + 16, order),
                    paddr = readLong(bytes, o + 24, order),
                    filesz = readLong(bytes, o + 32, order),
                    memsz = readLong(bytes, o + 40, order),
                    align = readLong(bytes, o + 48, order),
                )
            )
        }
        return out
    }

    private fun readSegments32(
        bytes: ByteArray, phoff: Long, entsize: Int, num: Int, order: ByteOrder
    ): List<ElfSegment> {
        if (phoff <= 0 || num == 0) return emptyList()
        val out = ArrayList<ElfSegment>(num)
        for (i in 0 until num) {
            val o = (phoff + i.toLong() * entsize).toInt()
            if (o + 32 > bytes.size) throw DwarfFormatException("program header $i past EOF")
            out.add(
                ElfSegment(
                    type = readInt(bytes, o, order),
                    offset = readInt(bytes, o + 4, order).toLong() and 0xffffffffL,
                    vaddr = readInt(bytes, o + 8, order).toLong() and 0xffffffffL,
                    paddr = readInt(bytes, o + 12, order).toLong() and 0xffffffffL,
                    filesz = readInt(bytes, o + 16, order).toLong() and 0xffffffffL,
                    memsz = readInt(bytes, o + 20, order).toLong() and 0xffffffffL,
                    flags = readInt(bytes, o + 24, order),
                    align = readInt(bytes, o + 28, order).toLong() and 0xffffffffL,
                )
            )
        }
        return out
    }
}

private fun readShort(b: ByteArray, o: Int, order: ByteOrder): Short =
    if (order == ByteOrder.LITTLE_ENDIAN)
        ((b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)).toShort()
    else (((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)).toShort()

private fun readInt(b: ByteArray, o: Int, order: ByteOrder): Int =
    if (order == ByteOrder.LITTLE_ENDIAN)
        (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or
            ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt()) shl 24)
    else
        ((b[o].toInt() and 0xff) shl 24) or ((b[o + 1].toInt() and 0xff) shl 16) or
            ((b[o + 2].toInt() and 0xff) shl 8) or (b[o + 3].toInt() and 0xff)

private fun readLong(b: ByteArray, o: Int, order: ByteOrder): Long =
    if (order == ByteOrder.LITTLE_ENDIAN) {
        var v = 0L
        for (i in 0 until 8) v = v or ((b[o + i].toLong() and 0xff) shl (i * 8))
        v
    } else {
        var v = 0L
        for (i in 0 until 8) v = v or ((b[o + i].toLong() and 0xff) shl ((7 - i) * 8))
        v
    }
