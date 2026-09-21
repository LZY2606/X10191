package compass.elf

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: ULong,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Long,
    val addralign: ULong,
    val bytes: ByteArray,
) {
    val isAllocated: Boolean get() = flags and 0x2L != 0L
}

data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: ULong,
    val vaddr: ULong,
    val filesz: ULong,
    val memsz: ULong,
)

class ElfFormatException(message: String) : RuntimeException(message)

class ElfFile private constructor(
    val elf64: Boolean,
    val littleEndian: Boolean,
    val machine: Int,
    val entry: ULong,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val rawBytes: ByteArray,
) {
    private val byName = sections.groupBy { it.name }

    /** A section name can legally occur more than once (e.g. multiple groups). */
    fun sectionsNamed(name: String): List<ElfSection> = byName[name] ?: emptyList()

    fun section(name: String): ElfSection? = byName[name]?.let { if (it.size == 1) it[0] else it.maxByOrNull { s -> s.size } }

    fun cursor(section: ElfSection): Cursor =
        Cursor(section.bytes, 0, section.bytes.size, littleEndian)

    companion object {
        fun parse(input: ByteArray): ElfFile {
            if (input.size < 16) throw ElfFormatException("file too small for ELF magic")
            if (input[0].toInt() != 0x7F || input[1].toInt() != 'E'.code ||
                input[2].toInt() != 'L'.code || input[3].toInt() != 'F'.code
            ) {
                throw ElfFormatException("bad ELF magic")
            }
            val elfClass = input[4].toInt()
            val elf64 = when (elfClass) {
                1 -> false
                2 -> true
                else -> throw ElfFormatException("unknown EI_CLASS=$elfClass")
            }
            val endian = when (input[5].toInt()) {
                1 -> true
                2 -> false
                else -> throw ElfFormatException("unknown EI_DATA")
            }
            val hdr = Cursor(input, 0, input.size, endian)
            return if (elf64) parse64(hdr, endian, input) else parse32(hdr, endian, input)
        }

        private fun parse64(h: Cursor, le: Boolean, raw: ByteArray): ElfFile {
            h.seek(16)
            val type = h.u16()
            val machine = h.u16()
            h.u32() // e_version
            val entry = h.u64()
            val phoff = h.u64()
            val shoff = h.u64()
            h.u32() // flags
            h.u16() // ehsize
            val phentsize = h.u16()
            val phnum = h.u16()
            val shentsize = h.u16()
            val shnum = h.u16()
            val shstrndx = h.u16()

            val sections = readSections64(raw, le, shoff.toLong(), shentsize, shnum, shstrndx)
            val segments = readSegments64(raw, le, phoff.toLong(), phentsize, phnum)
            return ElfFile(true, le, machine, entry, sections, segments, raw)
        }

        private fun parse32(h: Cursor, le: Boolean, raw: ByteArray): ElfFile {
            h.seek(16)
            h.u16() // e_type
            val machine = h.u16()
            h.u32() // e_version
            val entry = h.u32()
            val phoff = h.u32()
            val shoff = h.u32()
            h.u32() // flags
            h.u16() // ehsize
            val phentsize = h.u16()
            val phnum = h.u16()
            val shentsize = h.u16()
            val shnum = h.u16()
            val shstrndx = h.u16()

            val sections = readSections32(raw, le, shoff, shentsize, shnum, shstrndx)
            val segments = readSegments32(raw, le, phoff, phentsize, phnum, entry.toULong())
            return ElfFile(false, le, machine, entry.toULong(), sections, segments, raw)
        }

        private fun readSections64(raw: ByteArray, le: Boolean, off: Long, entsize: Int, num: Int, strndx: Int): List<ElfSection> {
            if (num == 0) return emptyList()
            if (off <= 0 || off >= raw.size.toLong()) throw ElfFormatException("bad e_shoff")
            if (entsize < 64) throw ElfFormatException("bad e_shentsize64")
            val headers = ArrayList<RawSection>(num)
            for (i in 0 until num) {
                val so = off + i.toLong() * entsize
                if (so + entsize > raw.size) throw ElfFormatException("section header $i past EOF")
                val c = Cursor(raw, so.toInt(), entsize, le)
                val nameOff = c.u32().toInt()
                val type = c.u32().toInt()
                val flags = c.u64().toLong()
                val addr = c.u64()
                val offset = c.u64().toLong()
                val size = c.u64().toLong()
                val link = c.u32().toInt()
                val info = c.u32().toLong()
                val align = c.u64()
                c.u64() // entsize
                headers.add(RawSection(nameOff, type, flags, addr, offset, size, link, info, align))
            }
            val strtab = if (strndx in headers.indices) headers[strndx] else null
            return headers.mapIndexed { idx, rs ->
                val name = if (strtab != null && rs.nameOff >= 0) {
                    readName(raw, strtab.offset, strtab.size, rs.nameOff.toLong()) ?: ""
                } else ""
                ElfSection(name, rs.type, rs.flags, rs.addr, rs.offset, rs.size, rs.link, rs.info, rs.addralign,
                    safeSlice(raw, rs.offset, rs.size, idx == 0))
            }
        }

        private fun readSections32(raw: ByteArray, le: Boolean, off: Long, entsize: Int, num: Int, strndx: Int): List<ElfSection> {
            if (num == 0) return emptyList()
            if (off <= 0 || off >= raw.size.toLong()) throw ElfFormatException("bad e_shoff")
            if (entsize < 40) throw ElfFormatException("bad e_shentsize32")
            val headers = ArrayList<RawSection>(num)
            for (i in 0 until num) {
                val so = off + i.toLong() * entsize
                if (so + entsize > raw.size) throw ElfFormatException("section header $i past EOF")
                val c = Cursor(raw, so.toInt(), entsize, le)
                val nameOff = c.u32().toInt()
                val type = c.u32().toInt()
                val flags = c.u32()
                val addr = c.u32().toULong()
                val offset = c.u32()
                val size = c.u32()
                val link = c.u32().toInt()
                val info = c.u32()
                val align = c.u32().toULong()
                c.u32() // entsize
                headers.add(RawSection(nameOff, type, flags.toLong(), addr, offset, size, link, info.toLong(), align))
            }
            val strtab = if (strndx in headers.indices) headers[strndx] else null
            return headers.mapIndexed { idx, rs ->
                val name = if (strtab != null) readName(raw, strtab.offset, strtab.size, rs.nameOff.toLong()) ?: "" else ""
                ElfSection(name, rs.type, rs.flags, rs.addr, rs.offset, rs.size, rs.link, rs.info, rs.addralign,
                    safeSlice(raw, rs.offset, rs.size, idx == 0))
            }
        }

        private fun readSegments64(raw: ByteArray, le: Boolean, off: Long, entsize: Int, num: Int): List<ElfSegment> {
            val out = ArrayList<ElfSegment>()
            if (off <= 0L || num == 0) return out
            for (i in 0 until num) {
                val so = off + i.toLong() * entsize
                if (so + 56 > raw.size) break
                val c = Cursor(raw, so.toInt(), minOf(entsize, raw.size - so.toInt()), le)
                val type = c.u32().toInt()
                val flags = c.u32().toInt()
                val offset = c.u64()
                val vaddr = c.u64()
                val paddr = c.u64()
                val filesz = c.u64()
                val memsz = c.u64()
                out.add(ElfSegment(type, flags, offset, vaddr, filesz, memsz))
            }
            return out
        }

        private fun readSegments32(raw: ByteArray, le: Boolean, off: Long, entsize: Int, num: Int, @Suppress("UNUSED_PARAMETER") dummy: ULong): List<ElfSegment> {
            val out = ArrayList<ElfSegment>()
            if (off <= 0L || num == 0) return out
            for (i in 0 until num) {
                val so = off + i.toLong() * entsize
                if (so + 32 > raw.size) break
                val c = Cursor(raw, so.toInt(), minOf(entsize, raw.size - so.toInt()), le)
                val type = c.u32().toInt()
                val offset = c.u32().toULong()
                val vaddr = c.u32().toULong()
                c.u32()
                val filesz = c.u32().toULong()
                val memsz = c.u32().toULong()
                val flags = c.u32().toInt()
                out.add(ElfSegment(type, flags, offset, vaddr, filesz, memsz))
            }
            return out
        }

        private fun safeSlice(raw: ByteArray, off: Long, size: Long, isNull: Boolean): ByteArray {
            if (off == 0L && size == 0L) return EMPTY
            if (off < 0 || size < 0 || off + size > raw.size.toLong()) {
                if (isNull) return EMPTY
                throw ElfFormatException("section body [off=$off size=$size] past EOF")
            }
            return raw.copyOfRange(off.toInt(), (off + size).toInt())
        }

        private fun readName(raw: ByteArray, tabOff: Long, tabSize: Long, strOff: Long): String? {
            if (strOff < 0 || tabOff + strOff >= raw.size.toLong()) return null
            val start = (tabOff + strOff).toInt()
            val end = minOf((tabOff + tabSize).toInt(), raw.size)
            var p = start
            while (p < end && raw[p].toInt() != 0) p++
            return String(raw, start, p - start, Charsets.UTF_8)
        }

        private val EMPTY = ByteArray(0)
    }

    private data class RawSection(
        val nameOff: Int, val type: Int, val flags: Long, val addr: ULong,
        val offset: Long, val size: Long, val link: Int, val info: Long, val addralign: ULong,
    )
}
