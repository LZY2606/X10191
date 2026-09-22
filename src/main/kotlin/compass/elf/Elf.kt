package compass.elf

import compass.dwarf.Cursor
import compass.dwarf.DwarfParseException

data class ElfSection(
    val index: Int,
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
)

data class ElfFile(
    val is64: Boolean,
    val littleEndian: Boolean,
    val elfType: Int,
    val machine: Int,
    val sections: List<ElfSection>,
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }
    fun sectionBytes(data: ByteArray, name: String): ByteArray? {
        val s = section(name) ?: return null
        if (s.type == 8L) return null // SHT_NOBITS occupies no file bytes
        if (s.offset < 0 || s.offset + s.size > data.size) return null
        return data.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
    }
}

fun parseElf(data: ByteArray): ElfFile {
    if (data.size < 16 || data[0] != 0x7f.toByte() || data[1] != 'E'.code.toByte()
        || data[2] != 'L'.code.toByte() || data[3] != 'F'.code.toByte()
    ) throw DwarfParseException("not an ELF file")
    val is64 = when (data[4].toInt()) { 1 -> false; 2 -> true; else -> throw DwarfParseException("bad ELF class") }
    val littleEndian = when (data[5].toInt()) { 1 -> true; 2 -> false; else -> throw DwarfParseException("bad ELF endianness") }
    val c = Cursor(data, 0, data.size, littleEndian)
    c.pos = 16
    val elfType = c.u16()
    val machine = c.u16()
    c.u32() // e_version
    if (is64) { c.u64(); c.u64() } else { c.u32(); c.u32() } // entry, phoff
    val shoff = if (is64) c.u64() else c.u32()
    c.u32() // flags
    c.u16() // ehsize
    c.u16() // phentsize
    c.u16() // phnum
    val shentsize = c.u16()
    var shnum = c.u16().toLong()
    var shstrndx = c.u16().toLong()
    if (shoff == 0L) return ElfFile(is64, littleEndian, elfType, machine, emptyList())

    fun shdr(index: Long): LongArray {
        val at = shoff + index * shentsize
        if (at < 0 || at + shentsize > data.size) throw DwarfParseException("section header out of bounds")
        val s = Cursor(data, at.toInt(), data.size, littleEndian)
        return if (is64)
            longArrayOf(s.u32(), s.u32(), s.u64(), s.u64(), s.u64(), s.u64(), s.u32(), s.u32(), s.u64(), s.u64())
        else
            longArrayOf(s.u32(), s.u32(), s.u32(), s.u32(), s.u32(), s.u32(), s.u32(), s.u32(), s.u32(), s.u32())
    }
    if (shnum == 0L) shnum = shdr(0)[5]          // extended numbering
    if (shstrndx == 0xFFFFL) shstrndx = shdr(0)[6]
    if (shnum > 100_000) throw DwarfParseException("unreasonable section count $shnum")
    if (shnum == 0L) return ElfFile(is64, littleEndian, elfType, machine, emptyList())

    val strHdr = shdr(shstrndx)
    val strOff = strHdr[4]
    val strSize = strHdr[5]
    fun shName(nameOff: Long): String {
        val at = strOff + nameOff
        val limit = minOf(strOff + strSize, data.size.toLong())
        if (at < 0 || at >= limit) return ""
        var p = at
        while (p < limit && data[p.toInt()].toInt() != 0) p++
        return String(data, at.toInt(), (p - at).toInt(), Charsets.UTF_8)
    }
    val sections = (0 until shnum).map { i ->
        val h = shdr(i)
        ElfSection(i.toInt(), shName(h[0]), h[1], h[3], h[4], h[5])
    }
    return ElfFile(is64, littleEndian, elfType, machine, sections)
}
