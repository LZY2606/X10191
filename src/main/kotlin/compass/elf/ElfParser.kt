package compass.elf

import compass.model.BoundsException
import compass.model.ElfClass
import compass.model.ElfFile
import compass.model.ElfParseException
import compass.model.LoadSegment
import compass.model.SectionInfo
import java.nio.ByteOrder
import java.security.MessageDigest

object SectionTypes {
    const val SHT_NOBITS = 8
    const val SHT_SYMTAB = 2
    const val SHT_STRTAB = 3
}

object ProgramTypes {
    const val PT_LOAD = 1
    const val PT_NOTE = 4
}

class ElfParser(private val bytes: ByteArray, private val pathHint: String = "<memory>") {

    fun parse(): ElfFile {
        if (bytes.size < 16) throw ElfParseException("file too small for ELF header")
        if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ElfParseException("bad ELF magic")
        val elfClass = ElfClass.from(bytes[4].toInt())
        val endianByte = bytes[5].toInt()
        if (endianByte !in 1..2) throw ElfParseException("bad EI_DATA=$endianByte")
        val littleEndian = endianByte == 1
        val order = if (littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val r = BoundedReader(bytes, 0, bytes.size, order)

        return if (elfClass == ElfClass.ELF64) parse64(r, order, littleEndian)
        else parse32(r, order, littleEndian)
    }

    private fun parse64(r: BoundedReader, order: java.nio.ByteOrder, littleEndian: Boolean): ElfFile {
        r.seek(16)
        val type = r.u16()
        val machine = r.u16()
        val version = r.u32()
        if (version != 1L) throw ElfParseException("unexpected ELF version $version")
        val entry = r.u64()
        val phoff = r.u64()
        val shoff = r.u64()
        r.u32(); r.u32() // flags, ehsize
        val phentsize = r.u16()
        val phnum = r.u16()
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()

        val segments = parseProgramHeaders64(r, phoff, phentsize, phnum)
        val sections = parseSectionHeaders64(r, shoff, shentsize, shnum, shstrndx)
        return ElfFile(
            pathHint = pathHint, elfClass = ElfClass.ELF64, littleEndian = littleEndian,
            machine = machine, entry = entry, type = type,
            sections = sections, segments = segments, rawBytes = bytes,
            buildId = readBuildId64(segments, r),
        )
    }

    private fun parse32(r: BoundedReader, order: java.nio.ByteOrder, littleEndian: Boolean): ElfFile {
        r.seek(16)
        val type = r.u16()
        val machine = r.u16()
        val version = r.u32()
        if (version != 1L) throw ElfParseException("unexpected ELF version $version")
        val entry = r.u32()
        val phoff = r.u32()
        val shoff = r.u32()
        r.u32(); r.u32()
        val phentsize = r.u16()
        val phnum = r.u16()
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()

        val segments = parseProgramHeaders32(r, phoff, phentsize, phnum)
        val sections = parseSectionHeaders32(r, shoff, shentsize, shnum, shstrndx)
        return ElfFile(
            pathHint = pathHint, elfClass = ElfClass.ELF32, littleEndian = littleEndian,
            machine = machine, entry = entry, type = type,
            sections = sections, segments = segments, rawBytes = bytes, buildId = null,
        )
    }

    private fun parseProgramHeaders64(r: BoundedReader, off: Long, entsz: Int, num: Int): List<LoadSegment> {
        if (num == 0 || off == 0L) return emptyList()
        if (entsz < 56) throw ElfParseException("phentsize $entsz < 56")
        val out = ArrayList<LoadSegment>(num)
        for (i in 0 until num) {
            val base = Math.addExact(off, Math.multiplyExact(i.toLong(), entsz.toLong()))
            if (base < 0 || base + 56 > bytes.size) throw BoundsException("phdr $i oob")
            r.seek(base.toInt())
            val ptype = r.u32().toInt()
            val flags = r.u32().toInt()
            val poff = r.u64(); val vaddr = r.u64(); val paddr = r.u64()
            val filesz = r.u64(); val memsz = r.u64(); val align = r.u64()
            out += LoadSegment(ptype, flags, poff, vaddr, paddr, filesz, memsz, align)
        }
        return out
    }

    private fun parseProgramHeaders32(r: BoundedReader, off: Long, entsz: Int, num: Int): List<LoadSegment> {
        if (num == 0 || off == 0L) return emptyList()
        if (entsz < 32) throw ElfParseException("phentsize $entsz < 32")
        val out = ArrayList<LoadSegment>(num)
        for (i in 0 until num) {
            val base = Math.addExact(off, Math.multiplyExact(i.toLong(), entsz.toLong())).toInt()
            if (base < 0 || base + 32 > bytes.size) throw BoundsException("phdr32 $i oob")
            r.seek(base)
            val ptype = r.u32().toInt()
            val poff = r.u32(); val vaddr = r.u32(); val paddr = r.u32()
            val filesz = r.u32(); val memsz = r.u32()
            val flags = r.u32().toInt(); val align = r.u32()
            out += LoadSegment(ptype, flags, poff, vaddr, paddr, filesz, memsz, align)
        }
        return out
    }

    private fun parseSectionHeaders64(r: BoundedReader, shoff: Long, entsz: Int, num: Int, shstrndx: Int): List<SectionInfo> {
        if (num == 0 || shoff == 0L) return emptyList()
        if (entsz < 64) throw ElfParseException("shentsize $entsz < 64")
        if (shstrndx >= num) throw ElfParseException("shstrndx $shstrndx >= shnum $num")
        val raw = ArrayList<SectionInfo>(num)
        for (i in 0 until num) {
            val base = Math.addExact(shoff, Math.multiplyExact(i.toLong(), entsz.toLong())).toInt()
            if (base + 64 > bytes.size) throw BoundsException("shdr $i oob")
            r.seek(base)
            val nameOff = r.u32().toInt()
            val stype = r.u32().toInt()
            val flags = r.u64()
            val addr = r.u64()
            val offset = r.u64()
            val size = r.u64()
            val link = r.u32().toInt()
            val info = r.u32().toInt()
            val addralign = r.u64()
            r.u64() // entsize
            raw += SectionInfo("", nameOff, stype, flags, addr, offset, size, link, info, addralign, ByteArray(0))
        }
        val strtab = raw[shstrndx]
        val strBytes = readSectionBytes(strtab)
        return raw.map { s -> s.copy(name = readCString(strBytes, s.nameOffset), data = readSectionBytes(s)) }
    }

    private fun parseSectionHeaders32(r: BoundedReader, shoff: Long, entsz: Int, num: Int, shstrndx: Int): List<SectionInfo> {
        if (num == 0 || shoff == 0L) return emptyList()
        if (entsz < 40) throw ElfParseException("shentsize $entsz < 40")
        if (shstrndx >= num) throw ElfParseException("shstrndx $shstrndx >= shnum $num")
        val raw = ArrayList<Pair<Int, SectionInfo>>(num)
        for (i in 0 until num) {
            val base = Math.addExact(shoff, Math.multiplyExact(i.toLong(), entsz.toLong())).toInt()
            if (base + 40 > bytes.size) throw BoundsException("shdr32 $i oob")
            r.seek(base)
            val nameOff = r.u32().toInt()
            val stype = r.u32().toInt()
            val flags = r.u32()
            val addr = r.u32()
            val offset = r.u32()
            val size = r.u32()
            val link = r.u32().toInt()
            val info = r.u32().toInt()
            val addralign = r.u32()
            r.u32()
            raw += nameOff to SectionInfo("", nameOff, stype, flags.toLong(), addr, offset, size, link, info, addralign.toLong(), ByteArray(0))
        }
        val (strNameOff, strtab) = raw[shstrndx]
        val strBytes = readSectionBytes(strtab)
        return raw.map { (nameOff, s) ->
            s.copy(name = readCString(strBytes, nameOff), data = readSectionBytes(s))
        }
    }

    private fun readSectionBytes(s: SectionInfo): ByteArray {
        if (s.type == SectionTypes.SHT_NOBITS) return ByteArray(0)
        val off = s.fileOffset
        val size = s.size
        if (off < 0 || size < 0) throw ElfParseException("negative section offset/size")
        if (Math.addExact(off, size) > bytes.size.toLong()) {
            throw BoundsException("section bytes ${off}..${off + size} past file size ${bytes.size}")
        }
        return bytes.copyOfRange(off.toInt(), (off + size).toInt())
    }

    private fun readCString(data: ByteArray, off: Int): String {
        if (off < 0 || off >= data.size) return "<invalid:$off>"
        var p = off
        while (p < data.size && data[p] != 0.toByte()) p++
        return String(data, off, p - off, Charsets.UTF_8)
    }

    private fun readBuildId64(segments: List<LoadSegment>, r: BoundedReader): String? {
        val note = segments.firstOrNull { it.type == ProgramTypes.PT_NOTE } ?: return null
        return try {
            r.seek(note.fileOffset.toInt())
            val end = note.fileOffset + note.filesz
            while (r.pos + 12 <= end) {
                val namesz = r.u32().toInt()
                val descsz = r.u32().toInt()
                val ntype = r.u32().toInt()
                val nameStart = r.pos
                val name = r.bytes(namesz).toString(Charsets.UTF_8).trimEnd(0.toChar())
                r.seek(nameStart + align4(namesz))
                val desc = r.bytes(descsz)
                r.seek(nameStart + align4(namesz) + align4(descsz))
                // NT_GNU_BUILD_ID == 3
                if (ntype == 3 && name == "GNU") {
                    return desc.joinToString("") { "%02x".format(it) }
                }
            }
            null
        } catch (_: Exception) { null }
    }

    private fun align4(n: Int) = (n + 3) and 3.inv()

    companion object {
        fun parse(bytes: ByteArray, pathHint: String = "<memory>"): ElfFile = ElfParser(bytes, pathHint).parse()
        fun sha256(data: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
    }
}

typealias BoundedReader = compass.model.BoundedReader
