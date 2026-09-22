package compass.elf

import java.security.MessageDigest

class ElfFormat(msg: String) : Exception(msg)

data class ElfSection(
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val data: ByteArray,
    val sha256: String,
)

data class ElfFile(
    val is64: Boolean,
    val bigEndian: Boolean,
    val machine: Int,
    val sections: List<ElfSection>,
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }
}

object ElfParser {
    private fun sha256(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 16 || bytes[0] != 0x7F.toByte() || bytes[1] != 'E'.code.toByte()
            || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ElfFormat("not an ELF file")
        val is64 = when (bytes[4].toInt()) { 1 -> false; 2 -> true; else -> throw ElfFormat("bad ELF class") }
        val bigEndian = when (bytes[5].toInt()) { 1 -> false; 2 -> true; else -> throw ElfFormat("bad ELF endianness") }
        val r = Reader(bytes, bigEndian = bigEndian)
        r.pos = 16
        r.u16() // e_type
        val machine = r.u16()
        r.u32() // e_version
        if (is64) r.u64() else r.u32() // e_entry
        val phoff = if (is64) r.u64() else r.u32()
        val shoff = if (is64) r.u64() else r.u32()
        r.u32() // flags
        r.u16() // ehsize
        r.u16(); r.u16() // phentsize, phnum
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()
        if (shoff == 0L || shnum == 0) return ElfFile(is64, bigEndian, machine, emptyList())
        if (shoff + shentsize.toLong() * shnum > bytes.size) throw ElfFormat("section header table out of bounds")

        data class Shdr(val nameOff: Long, val type: Long, val addr: Long, val off: Long, val size: Long)
        val shdrs = ArrayList<Shdr>(shnum)
        for (i in 0 until shnum) {
            val sr = Reader(bytes, (shoff + i.toLong() * shentsize).toInt(), bytes.size, bigEndian)
            val nameOff = sr.u32()
            val type = sr.u32()
            if (is64) {
                sr.u64() // flags
                val addr = sr.u64(); val off = sr.u64(); val size = sr.u64()
                shdrs.add(Shdr(nameOff, type, addr, off, size))
            } else {
                sr.u32()
                val addr = sr.u32(); val off = sr.u32(); val size = sr.u32()
                shdrs.add(Shdr(nameOff, type, addr, off, size))
            }
        }
        if (shstrndx >= shdrs.size) throw ElfFormat("bad shstrndx")
        val strTab = shdrs[shstrndx]
        if (strTab.off + strTab.size > bytes.size) throw ElfFormat("shstrtab out of bounds")
        fun strAt(off: Long): String {
            var p = (strTab.off + off).toInt()
            val end = (strTab.off + strTab.size).toInt()
            val start = p
            while (p < end && bytes[p].toInt() != 0) p++
            return String(bytes, start, p - start, Charsets.UTF_8)
        }
        val sections = shdrs.map { h ->
            val name = strAt(h.nameOff)
            val data = if (h.type == 8L /* SHT_NOBITS */ || h.size == 0L) ByteArray(0)
            else {
                if (h.off + h.size > bytes.size) throw ElfFormat("section $name out of bounds")
                bytes.copyOfRange(h.off.toInt(), (h.off + h.size).toInt())
            }
            ElfSection(name, h.type, h.addr, h.off, h.size, data, sha256(data))
        }
        return ElfFile(is64, bigEndian, machine, sections)
    }
}
