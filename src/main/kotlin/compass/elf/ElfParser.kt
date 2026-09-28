package compass.elf

import compass.dwarf.ByteReader
import compass.dwarf.ElfSegments
import compass.dwarf.MemorySegment
import compass.dwarf.SectionInfo
import java.nio.ByteOrder
import java.security.MessageDigest

class ElfException(message: String) : RuntimeException(message)

object ElfParser {
    fun parse(bytes: ByteArray): ElfSegments {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 0x45 || bytes[2] != 0x4c || bytes[3] != 0x46)
            throw ElfException("not an ELF file")
        val elfClass = bytes[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw ElfException("unsupported ELF class $elfClass")
        val order = when (bytes[5].toInt()) { 1 -> ByteOrder.LITTLE_ENDIAN; 2 -> ByteOrder.BIG_ENDIAN; else -> throw ElfException("bad endian") }
        val reader = ByteReader(bytes, order)
        reader.seek(0x20)
        val ePhoff = if (elfClass == 2) reader.u64() else reader.u32()
        reader.seek(if (elfClass == 2) 0x36 else 0x28)
        val eShoff = if (elfClass == 2) reader.u64() else reader.u32()
        reader.seek(if (elfClass == 2) 0x3a else 0x2e)
        val eShentsize = reader.u16()
        val eShnum = reader.u16()
        val eShstrndx = reader.u16()

        val loads = parseProgramHeaders(bytes, order, elfClass, ePhoff, reader)
        val sections = parseSections(bytes, order, elfClass, eShoff, eShentsize, eShnum, eShnum, eShstrndx)
        return ElfSegments(sections, loads, elfClass, order)
    }

    private fun parseProgramHeaders(bytes: ByteArray, order: ByteOrder, elfClass: Int, phoff: Long, shared: ByteReader): List<MemorySegment> {
        if (phoff <= 0) return emptyList()
        val reader = ByteReader(bytes, order)
        reader.seek(0x2a); val phentsize = reader.u16(); val phnum = reader.u16()
        if (phoff >= bytes.size) return emptyList()
        val result = mutableListOf<MemorySegment>()
        for (i in 0 until phnum) {
            val start = phoff + i.toLong() * phentsize
            if (start < 0 || start + phentsize > bytes.size) continue
            reader.seek(start.toInt())
            if (elfClass == 2) {
                val type = reader.u32(); val flags = reader.u32(); val offset = reader.u64()
                val vaddr = reader.u64(); reader.u64(); val filesz = reader.u64(); val memsz = reader.u64()
                if (type == 1L) result += MemorySegment(offset, vaddr, filesz, memsz, flags)
            } else {
                val type = reader.u32(); val offset = reader.u32(); val vaddr = reader.u32()
                reader.u32(); val filesz = reader.u32(); val memsz = reader.u32(); val flags = reader.u32()
                if (type == 1L) result += MemorySegment(offset.toLong(), vaddr.toLong(), filesz.toLong(), memsz.toLong(), flags)
            }
        }
        return result
    }

    private fun parseSections(bytes: ByteArray, order: ByteOrder, elfClass: Int, shoff: Long, shentsize: Int, shnumInput: Int, shnum: Int, shstrndx: Int): List<SectionInfo> {
        if (shoff <= 0 || shentsize <= 0 || shoff > bytes.size) return emptyList()
        val reader = ByteReader(bytes, order)
        var count = shnum
        var namesIndex = shstrndx
        if (count == 0) {
            reader.seek(shoff.toInt() + if (elfClass == 2) 60 else 32)
            count = if (elfClass == 2) reader.u64().toInt() else reader.u32().toInt()
            if (namesIndex == 0xffff.toShort().toInt() || namesIndex == 0xffff) {
                reader.seek(shoff.toInt() + if (elfClass == 2) 62 else 48)
                namesIndex = if (elfClass == 2) reader.u64().toInt() else reader.u32().toInt()
            }
        }
        fun shEntry(index: Int, field: Int): Int = (shoff + index.toLong() * shentsize + field).toInt()
        reader.seek(shEntry(namesIndex, if (elfClass == 2) 24 else 16))
        val nameOffset = if (elfClass == 2) reader.u64() else reader.u32()
        if (nameOffset >= bytes.size) return emptyList()
        val digest = MessageDigest.getInstance("SHA-256")
        return (0 until count).mapNotNull { index ->
            val start = shoff + index.toLong() * shentsize
            if (start < 0 || start + shentsize > bytes.size) return@mapNotNull null
            reader.seek(start.toInt())
            val nameIdx = reader.u32()
            val type = reader.u32()
            val flags = if (elfClass == 2) reader.u64() else reader.u32()
            val address = if (elfClass == 2) reader.u64() else reader.u32()
            val offset = if (elfClass == 2) reader.u64() else reader.u32()
            val size = if (elfClass == 2) reader.u64() else reader.u32()
            val link = if (elfClass == 2) { reader.seek(start.toInt() + 40); reader.u32() } else { reader.seek(start.toInt() + 24); reader.u32() }
            val info = if (elfClass == 2) { reader.seek(start.toInt() + 44); reader.u32() } else { reader.seek(start.toInt() + 28); reader.u32() }
            val addralign = if (elfClass == 2) { reader.seek(start.toInt() + 48); reader.u64() } else { reader.seek(start.toInt() + 32); reader.u32() }
            if (offset > bytes.size || offset + size > bytes.size) null else {
                val endIndex = minOf((nameOffset + nameIdx).toInt(), bytes.size)
                val end = bytes.indexOf(0, endIndex).let { if (it < 0) endIndex else it }
                val name = bytes.copyOfRange(endIndex, end).toString(Charsets.UTF_8)
                val sectionBytes = bytes.copyOfRange(offset.toInt(), (offset + size).toInt())
                val hash = digest.digest(sectionBytes).joinToString("") { "%02x".format(it) }
                SectionInfo(name, type, flags, address, offset, size, link, info, addralign, hash)
            }
        }
    }
}
