package compass.elf

import java.nio.ByteOrder

/**
 * Parses ELF container files. A blob without the ELF magic is accepted as a
 * single anonymous section blob so tests can feed minimal synthetic fixtures
 * without constructing a full ELF file.
 */
object ElfParser {

    fun parse(bytes: ByteArray, path: String? = null): ElfFile {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            throw ParseError("not an ELF file (bad magic)")
        }
        val elfClass = bytes[4].toInt() and 0xff
        if (elfClass != 1 && elfClass != 2) throw ParseError("unknown ELF class $elfClass")
        val endian = when (bytes[5].toInt() and 0xff) {
            1 -> ByteOrder.LITTLE_ENDIAN
            2 -> ByteOrder.BIG_ENDIAN
            else -> throw ParseError("unknown ELF data encoding")
        }
        val r = Reader(bytes, endian, "elf")
        r.seek(16)
        return if (elfClass == ElfFile.ELFCLASS64) parse64(r, path, endian, bytes)
        else parse32(r, path, endian, bytes)
    }

    private fun parse64(r: Reader, path: String?, endian: ByteOrder, raw: ByteArray): ElfFile {
        val type = r.u16()
        val machine = r.u16()
        r.u32() // version
        val entry = r.u64()
        val phoff = r.u64()
        val shoff = r.u64()
        r.u32() // flags
        r.u16() // ehsize
        val phentsize = r.u16()
        val phnum = r.u16()
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()

        val segments = (0 until phnum).map { i ->
            r.seek((phoff + i.toLong() * phentsize).toIntExact())
            ElfSegment(
                type = r.u32().toInt(), flags = r.u32().toInt(),
                offset = r.u64(), vaddr = r.u64(), paddr = r.u64(),
                filesz = r.u64(), memsz = r.u64(), align = r.u64(),
            )
        }

        val rawSections = (0 until shnum).map { i ->
            r.seek((shoff + i.toLong() * shentsize).toIntExact())
            RawSection(
                nameOff = r.u32().toInt(), type = r.u32().toInt(), flags = r.u64(),
                addr = r.u64(), offset = r.u64(), size = r.u64(),
                link = r.u32(), info = r.u32(), addralign = r.u64(), entsize = r.u64(),
            )
        }
        val names = resolveNames(raw, shstrndx, raw)
        val sections = rawSections.mapIndexed { idx, s ->
            val data = extractSection(raw, s, idx)
            ElfSection(names[idx], s.type, s.flags, s.addr, s.offset, s.size, s.link, s.info, s.addralign, data)
        }
        return ElfFile(path, ElfFile.ELFCLASS64, endian, machine, entry, type, sections, segments, raw)
    }

    private fun parse32(r: Reader, path: String?, endian: ByteOrder, raw: ByteArray): ElfFile {
        val type = r.u16()
        val machine = r.u16()
        r.u32()
        val entry = r.u32()
        val phoff = r.u32()
        val shoff = r.u32()
        r.u32()
        r.u16()
        val phentsize = r.u16()
        val phnum = r.u16()
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()

        val segments = (0 until phnum).map { i ->
            r.seek((phoff + i.toLong() * shentsize).toIntExact())
            ElfSegment(
                type = r.u32().toInt(), offset = r.u32(), vaddr = r.u32(), paddr = r.u32(),
                filesz = r.u32(), memsz = r.u32(), flags = r.u32().toInt(), align = r.u32(),
            )
        }
        val rawSections = (0 until shnum).map { i ->
            r.seek((shoff + i.toLong() * shentsize).toIntExact())
            RawSection(
                nameOff = r.u32().toInt(), type = r.u32().toInt(), flags = r.u32(),
                addr = r.u32(), offset = r.u32(), size = r.u32(),
                link = r.u32(), info = r.u32(), addralign = r.u32(), entsize = r.u32(),
            )
        }
        val names = resolveNames(rawSections, shstrndx, raw)
        val sections = rawSections.mapIndexed { idx, s ->
            ElfSection(names[idx], s.type, s.flags, s.addr, s.offset, s.size, s.link, s.info, s.addralign, extractSection(raw, s, idx))
        }
        return ElfFile(path, ElfFile.ELFCLASS32, endian, machine, entry, type, sections, segments, raw)
    }

    private data class RawSection(
        val nameOff: Int, val type: Int, val flags: Long, val addr: Long,
        val offset: Long, val size: Long, val link: Int, val info: Int,
        val addralign: Long, val entsize: Long,
    )

    /** SHT_NOBITS sections have no bytes; everything else is copied bounded. */
    private fun extractSection(raw: ByteArray, s: RawSection, idx: Int): ByteArray {
        if (s.type == 8) return ByteArray(0) // SHT_NOBITS
        val off = s.offset
        val len = s.size
        if (off == 0L && len == 0L) return ByteArray(0)
        if (off < 0 || off > raw.size || len < 0 || off + len > raw.size) {
            // Truncated section table: isolate the damage, return empty bytes.
            return ByteArray(0)
        }
        return raw.copyOfRange(off.toIntExact(), (off + len).toIntExact())
    }

    private fun resolveNames(raw: List<RawSection>, shstrndx: Int, file: ByteArray): List<String> {
        if (shstrndx == 0 || shstrndx >= raw.size) return List(raw.size) { if (it == 0) "" else ".unknown$it" }
        val str = raw[shstrndx]
        if (str.offset + str.size > file.size) return List(raw.size) { ".badname$it" }
        return raw.map { s ->
            val start = str.offset.toIntExact() + s.nameOff
            if (s.nameOff < 0 || start >= file.size) return@map ""
            var end = start
            while (end < file.size && file[end] != 0.toByte()) end++
            String(file, start, end - start, Charsets.UTF_8)
        }
    }
}

private fun Long.toIntExact(): Int {
    if (this < 0 || this > Int.MAX_VALUE) throw ParseError("offset/address does not fit in this JVM array index: $this")
    return toInt()
}
