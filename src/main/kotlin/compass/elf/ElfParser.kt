@file:Suppress("ArrayInDataClass")
package compass.elf

import compass.util.ByteReader
import compass.util.Hex
import compass.util.ParseException
import compass.util.U64

private const val SHT_SYMTAB = 2
private const val SHT_STRTAB = 3
private const val SHT_NOBITS = 8
private const val SHT_DYNSYM = 11
private const val PT_NOTE = 4
private const val SHT_NOTE = 7

private val DEBUG_SECTIONS = setOf(
    ".debug_info", ".debug_abbrev", ".debug_str", ".debug_str_offsets",
    ".debug_addr", ".debug_ranges", ".debug_rnglists", ".debug_line",
    ".debug_line_str", ".debug_cu_index", ".debug_tu_index",
    ".debug_loclists", ".debug_loclists.dwo", ".debug_rnglists.dwo",
    ".debug_info.dwo", ".debug_abbrev.dwo", ".debug_str.dwo",
    ".debug_str_offsets.dwo", ".debug_line.dwo", ".debug_line_str.dwo",
    ".debug_addr.dwo", ".zdebug_info", ".zdebug_abbrev", ".zdebug_line",
    ".symtab", ".dynsym", ".strtab", ".dynstr"
)

object ElfParser {

    fun parse(bytes: ByteArray): ParsedElf {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() ||
            bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            throw ParseException("not an ELF file (bad magic)")
        }
        val elfClass = bytes[4].toInt() and 0xff
        if (elfClass != 1 && elfClass != 2) throw ParseException("unknown ELF class $elfClass")
        val endianByte = bytes[5].toInt() and 0xff
        if (endianByte != 1 && endianByte != 2) throw ParseException("unknown ELF data encoding $endianByte")
        val big = endianByte == 2

        val r = ByteReader(bytes)
        r.seek(16)
        val eType = r.u16b(big)
        val machine = r.u16b(big)
        r.seek(if (elfClass == 2) 0x18 else 0x14)
        val entry = if (elfClass == 2) r.u64b(big) else U64(r.u32b(big))
        val phoff = if (elfClass == 2) r.u64b(big) else U64(r.u32b(big))
        val shoff = if (elfClass == 2) r.u64b(big) else U64(r.u32b(big))
        r.seek(if (elfClass == 2) 0x36 else 0x28)
        val phentsize = r.u16b(big)
        val phnum = r.u16b(big)
        val shentsize = r.u16b(big)
        val shnum = r.u16b(big)
        val shstrndx = r.u16b(big)

        val rawSections = readSections(bytes, elfClass, big, shoff, shentsize, shnum)
        if (shstrndx >= rawSections.size) throw ParseException("e_shstrndx out of bounds")
        val shstr = rawSections[shstrndx]
        val sectionNames = parseStrtab(slice(bytes, shstr.offset, shstr.size))

        val sections = rawSections.mapIndexed { idx, rs ->
            SectionInfo(
                name = sectionNames[rs.nameOff] ?: ("<section $idx>"),
                type = rs.type,
                flags = rs.flags,
                addr = rs.addr,
                fileOffset = rs.offset,
                size = rs.size,
                link = rs.link,
                info = rs.info,
                addralign = rs.addralign,
                entsize = rs.entsize
            )
        }

        val segments = readSegments(bytes, elfClass, big, phoff, phentsize, phnum)

        val sectionBytes = LinkedHashMap<String, ByteArray>()
        for (s in sections) {
            if (s.name in DEBUG_SECTIONS && s.type != SHT_NOBITS) {
                sectionBytes[s.name] = slice(bytes, s.fileOffset, s.size)
            }
        }

        val symbols = mutableListOf<SymbolInfo>()
        for ((idx, s) in sections.withIndex()) {
            if (s.type == SHT_SYMTAB || s.type == SHT_DYNSYM) {
                val strSec = sections.getOrNull(s.link)
                val strBytes = strSec?.let { sectionBytes[it.name] ?: slice(bytes, it.fileOffset, it.size) }
                if (strBytes != null) {
                    val origin = if (s.type == SHT_SYMTAB) "symtab" else "dynsym"
                    symbols += parseSymbols(slice(bytes, s.fileOffset, s.size), strBytes, elfClass, big, s.entsize.v.toInt(), origin)
                }
            }
        }

        val buildId = findBuildId(bytes, sections, segments, sectionBytes)

        return ParsedElf(
            ElfSummary(
                elfClass = elfClass,
                endian = if (big) "big" else "little",
                machine = machine,
                entry = entry,
                buildId = buildId,
                sections = sections,
                segments = segments,
                symbols = symbols
            ),
            sectionBytes
        )
    }

    private data class RawSection(
        val nameOff: Long, val type: Int, val flags: U64, val addr: U64,
        val offset: U64, val size: U64, val link: Int, val info: Int,
        val addralign: U64, val entsize: U64
    )

    private fun readSections(
        bytes: ByteArray, elfClass: Int, big: Boolean,
        shoff: U64, shentsize: Int, shnum: Int
    ): List<RawSection> {
        if (shnum == 0 || shoff.v.toULong() == 0UL) return emptyList()
        val out = ArrayList<RawSection>(shnum)
        val need = if (elfClass == 2) 64 else 40
        if (shentsize < need) throw ParseException("shentsize too small: $shentsize")
        var off = shoff.v.toLong()
        repeat(shnum) {
            if (off < 0 || off > bytes.size - need) throw ParseException("section header $it out of file")
            val r = ByteReader(bytes, off.toInt())
            if (elfClass == 2) {
                val nameOff = r.u32b(big)
                val type = r.u32b(big).toInt()
                val flags = r.u64b(big)
                val addr = r.u64b(big)
                val foff = r.u64b(big)
                val size = r.u64b(big)
                val link = r.u32b(big).toInt()
                val info = r.u32b(big).toInt()
                val addralign = r.u64b(big)
                val entsize = r.u64b(big)
                out += RawSection(nameOff, type, flags, addr, foff, size, link, info, addralign, entsize)
            } else {
                val nameOff = r.u32b(big)
                val type = r.u32b(big).toInt()
                val flags = U64(r.u32b(big))
                val addr = U64(r.u32b(big))
                val foff = U64(r.u32b(big))
                val size = U64(r.u32b(big))
                val link = r.u32b(big).toInt()
                val info = r.u32b(big).toInt()
                val addralign = U64(r.u32b(big))
                val entsize = U64(r.u32b(big))
                out += RawSection(nameOff, type, flags, addr, foff, size, link, info, addralign, entsize)
            }
            off += shentsize
        }
        return out
    }

    private fun readSegments(
        bytes: ByteArray, elfClass: Int, big: Boolean,
        phoff: U64, phentsize: Int, phnum: Int
    ): List<SegmentInfo> {
        if (phnum == 0 || phoff.v.toULong() == 0UL) return emptyList()
        val need = if (elfClass == 2) 56 else 32
        if (phentsize < need) throw ParseException("phentsize too small: $phentsize")
        val out = ArrayList<SegmentInfo>(phnum)
        var off = phoff.v.toLong()
        repeat(phnum) {
            if (off < 0 || off > bytes.size - need) throw ParseException("program header $it out of file")
            val r = ByteReader(bytes, off.toInt())
            if (elfClass == 2) {
                val type = r.u32b(big).toInt()
                val flags = r.u32b(big).toInt()
                val offset = r.u64b(big)
                val vaddr = r.u64b(big)
                val paddr = r.u64b(big)
                val filesz = r.u64b(big)
                val memsz = r.u64b(big)
                val align = r.u64b(big)
                out += SegmentInfo(type, flags, offset, vaddr, paddr, filesz, memsz, align)
            } else {
                val type = r.u32b(big).toInt()
                val offset = U64(r.u32b(big))
                val vaddr = U64(r.u32b(big))
                val paddr = U64(r.u32b(big))
                val filesz = U64(r.u32b(big))
                val memsz = U64(r.u32b(big))
                val flags = r.u32b(big).toInt()
                val align = U64(r.u32b(big))
                out += SegmentInfo(type, flags, offset, vaddr, paddr, filesz, memsz, align)
            }
            off += phentsize
        }
        return out
    }

    private fun parseSymbols(symBytes: ByteArray, strBytes: ByteArray, elfClass: Int, big: Boolean, entsizeIn: Int, origin: String): List<SymbolInfo> {
        val entsize = if (entsizeIn > 0) entsizeIn else if (elfClass == 2) 24 else 16
        val names = parseStrtab(strBytes)
        val count = symBytes.size / entsize
        val out = ArrayList<SymbolInfo>(count)
        for (i in 0 until count) {
            val r = ByteReader(symBytes, i * entsize)
            val nameOff: Long
            var value: U64
            var size: U64
            var info: Int
            var shndx: Int
            if (elfClass == 2) {
                nameOff = r.u32b(big)
                info = r.u8()
                r.u8() // other
                shndx = r.u16b(big)
                value = r.u64b(big)
                size = r.u64b(big)
            } else {
                nameOff = r.u32b(big)
                value = U64(r.u32b(big))
                size = U64(r.u32b(big))
                info = r.u8()
                r.u8()
                shndx = r.u16b(big)
            }
            val name = names[nameOff] ?: continue
            if (name.isEmpty()) continue
            out += SymbolInfo(
                name = name,
                value = value,
                size = size,
                type = info and 0x0f,
                bind = info ushr 4,
                sectionIndex = shndx,
                source = origin
            )
        }
        return out
    }

    private fun findBuildId(
        bytes: ByteArray,
        sections: List<SectionInfo>,
        segments: List<SegmentInfo>,
        sectionBytes: Map<String, ByteArray>
    ): String? {
        for (s in sections) {
            if (s.type == SHT_NOTE && s.name == ".note.gnu.build-id") {
                val data = sectionBytes[s.name] ?: slice(bytes, s.fileOffset, s.size)
                readGnuBuildId(data, false)?.let { return it }
            }
        }
        for (seg in segments) {
            if (seg.type == PT_NOTE) {
                val data = slice(bytes, seg.offset, seg.filesz)
                readGnuBuildId(data, false)?.let { return it }
            }
        }
        return null
    }

    /** Reads the first NT_GNU_BUILD_ID (namesz 4, name "GNU\0", type 3). */
    fun readGnuBuildId(data: ByteArray, big: Boolean): String? {
        val r = ByteReader(data)
        while (r.remaining() >= 12) {
            val namesz = r.u32b(big).toInt()
            val descsz = r.u32b(big).toInt()
            val type = r.u32b(big).toInt()
            if (namesz > 64 || descsz > 64 || namesz <= 0) return null
            if (r.remaining() < namesz + descsz) return null
            val name = r.bytes(namesz)
            while (r.pos % 4 != 0) r.u8()
            val desc = r.bytes(descsz)
            while (r.pos % 4 != 0 && r.remaining() > 0) r.u8()
            if (type == 3 && String(name).trimEnd('\u0000') == "GNU") {
                return Hex.encode(desc)
            }
        }
        return null
    }

    private fun parseStrtab(data: ByteArray): Map<Long, String> {
        val out = LinkedHashMap<Long, String>()
        var i = 0
        while (i < data.size) {
            var j = i
            while (j < data.size && data[j].toInt() != 0) j++
            if (j < data.size) out[i.toLong()] = String(data, i, j - i, Charsets.UTF_8)
            i = j + 1
        }
        return out
    }

    private fun slice(bytes: ByteArray, offset: U64, size: U64): ByteArray {
        val o = offset.v.toLong()
        val n = size.v.toLong()
        if (o < 0 || n < 0 || o > bytes.size - n) throw ParseException("section slice out of bounds: off=$o size=$n")
        return bytes.copyOfRange(o.toInt(), (o + n).toInt())
    }
}

// --- endian-aware primitives ---
private fun ByteReader.u16b(big: Boolean): Int {
    require(2)
    val a = data[pos].toInt() and 0xff
    val b = data[pos + 1].toInt() and 0xff
    pos += 2
    return if (big) (a shl 8) or b else a or (b shl 8)
}

private fun ByteReader.u32b(big: Boolean): Long {
    require(4)
    var v = 0L
    for (i in 0..3) {
        // byte at the lowest file offset holds the most-significant byte when big-endian
        val shift = if (big) (3 - i) * 8 else i * 8
        v = v or ((data[pos + i].toLong() and 0xff) shl shift)
    }
    pos += 4
    return v
}

private fun ByteReader.u64b(big: Boolean): U64 {
    require(8)
    var v = 0L
    for (i in 0..7) {
        val shift = if (big) (7 - i) * 8 else i * 8
        v = v or ((data[pos + i].toLong() and 0xff) shl shift)
    }
    pos += 8
    return U64(v)
}
