package compass

object ElfParser {
    private const val PT_NULL = 0
    private const val SHT_STRTAB = 3
    private const val SHT_NOBITS = 8

    fun parse(bytes: ByteArray): ElfFile {
        val warnings = mutableListOf<Warning>()
        val r = ByteReader(bytes)
        if (r.remaining() < 16 || r.u8() != 0x7f || r.u8() != 'E'.code || r.u8() != 'L'.code || r.u8() != 'F'.code) {
            throw CursorException("not an ELF file")
        }
        val elfClass = r.u8()
        if (elfClass != 1 && elfClass != 2) throw CursorException("unknown ELF class $elfClass")
        val endian = r.u8()
        if (endian != 1 && endian != 2) throw CursorException("unknown ELF endianness")
        r.pos = if (elfClass == 1) 24 else 32
        val eMachine = if (elfClass == 1) {
            r.pos = 18; r.u16(endian)
        } else {
            r.pos = 18; r.u16(endian)
        }
        val entry = if (elfClass == 1) {
            r.pos = 24; r.u32(endian)
        } else {
            r.pos = 24; r.u64(endian)
        }
        val (sectionHeaderOffset, sectionHeaderEntrySize, sectionCount, sectionNameIndex) = if (elfClass == 1) {
            r.pos = 28
            val shoff = r.u32(endian); val shentsize = r.u16(endian); val shnum = r.u16(endian); val shstrndx = r.u16(endian)
            listOf(shoff, shentsize.toLong(), shnum.toLong(), shstrndx.toLong())
        } else {
            r.pos = 40
            val shoff = r.u64(endian); val shentsize = r.u16(endian); val shnum = r.u16(endian); val shstrndx = r.u16(endian)
            listOf(shoff, shentsize.toLong(), shnum.toLong(), shstrndx.toLong())
        }
        if (sectionCount > 100_000 || sectionHeaderEntrySize > 4096) throw CursorException("implausible ELF section table")
        val raw = mutableListOf<SectionInfo>()
        val nameOffsets = mutableListOf<Long>()
        val minEntry = if (elfClass == 1) 40 else 64
        for (index in 0 until sectionCount.toInt()) {
            val start = sectionHeaderOffset + index * sectionHeaderEntrySize
            if (start < 0 || start + minEntry > bytes.size) {
                warnings += Warning("elf", "section header $index out of bounds", start, "error")
                break
            }
            r.pos = start.toInt()
            val nameOffset = r.u32(endian); val type = r.u32(endian)
            val flags = if (elfClass == 1) r.u32(endian) else r.u64(endian)
            val addr = if (elfClass == 1) r.u32(endian) else r.u64(endian)
            val offset = if (elfClass == 1) r.u32(endian) else r.u64(endian)
            val size = if (elfClass == 1) r.u32(endian) else r.u64(endian)
            val link = r.u32(endian); val info = r.u32(endian)
            val addralign = if (elfClass == 1) r.u32(endian) else r.u64(endian)
            val entsize = if (elfClass == 1) r.u32(endian) else r.u64(endian)
            val sectionBytes = if (type != SHT_NOBITS.toLong() && offset >= 0 && size >= 0 && offset + size <= bytes.size && offset + size >= offset) {
                bytes.copyOfRange(offset.toInt(), (offset + size).toInt())
            } else ByteArray(0)
            nameOffsets += nameOffset
            raw += SectionInfo(index, "<pending>", type, flags, addr, offset, size, link, info, addralign, entsize, sha256Hex(sectionBytes))
        }
        val names = raw.getOrNull(sectionNameIndex.toInt())?.takeIf { it.type == SHT_STRTAB.toLong() && it.offset + it.size <= bytes.size }?.let {
            bytes.copyOfRange(it.offset.toInt(), (it.offset + it.size).toInt())
        } ?: ByteArray(1)
        val sections = raw.map { sec ->
            val name = when {
                sec.ordinal == 0 || sectionNameIndex == 0L -> ""
                else -> runCatching { ByteReader(names).stringAt(nameOffsets[sec.ordinal]) }.getOrDefault("<invalid>")
            }
            sec.copy(name = name)
        }
        return ElfFile(elfClass, endian, eMachine, entry, sections, bytes)
    }

}

