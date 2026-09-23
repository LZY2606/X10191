package compass.elf

import compass.dwarf.ByteReader
import compass.dwarf.DwarfParseException
import java.security.MessageDigest

data class ElfSection(
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val data: ByteArray
) {
    val sha256: String = sha256Hex(data)
}

data class ElfSegment(val type: Long, val vaddr: Long, val memSize: Long)

data class ElfFile(
    val is64: Boolean,
    val bigEndian: Boolean,
    val elfType: Int,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val fileSha256: String
) {
    /** Lowest PT_LOAD virtual address: the link-time base used for load-bias math. */
    val linkBase: Long = segments.filter { it.type == PT_LOAD }
        .minOfOrNull { it.vaddr } ?: 0L

    val isDynamic: Boolean get() = elfType == ET_DYN

    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    fun debugSection(name: String): ByteArray? = section(name)?.data

    companion object {
        const val ET_EXEC = 2
        const val ET_DYN = 3
        const val PT_LOAD = 1L

        fun parse(bytes: ByteArray): ElfFile {
            if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte()
                || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
            ) throw DwarfParseException("not an ELF file")
            val is64 = bytes[4].toInt() == 2
            val bigEndian = bytes[5].toInt() == 2
            val r = ByteReader(bytes, 0, bytes.size, bigEndian)
            r.pos = 16
            val elfType = r.u2()
            r.u2() // machine
            r.u4() // version
            if (is64) r.u8() else r.u4() // entry
            val phoff = if (is64) r.u8() else r.u4()
            val shoff = if (is64) r.u8() else r.u4()
            r.u4() // flags
            r.u2() // ehsize
            val phentsize = r.u2()
            val phnum = r.u2()
            val shentsize = r.u2()
            val shnum = r.u2()
            val shstrndx = r.u2()

            val segments = mutableListOf<ElfSegment>()
            for (i in 0 until phnum) {
                val off = phoff + i.toLong() * phentsize
                if (off < 0 || off + phentsize > bytes.size) break
                r.pos = off.toInt()
                val pType = if (is64) r.u4() else r.u4()
                if (is64) r.u4() // flags
                if (is64) r.u8() else r.u4() // offset
                val vaddr = if (is64) r.u8() else r.u4()
                if (is64) r.u8() else r.u4() // paddr
                if (is64) r.u8() else r.u4() // filesz
                val memsz = if (is64) r.u8() else r.u4()
                segments.add(ElfSegment(pType, vaddr, memsz))
            }

            data class Shdr(val nameOff: Long, val type: Long, val addr: Long, val offset: Long, val size: Long)
            val shdrs = mutableListOf<Shdr>()
            for (i in 0 until shnum) {
                val off = shoff + i.toLong() * shentsize
                if (off < 0 || off + shentsize > bytes.size) break
                r.pos = off.toInt()
                val nameOff = r.u4()
                val type = r.u4()
                if (is64) r.u8() else r.u4() // flags
                val addr = if (is64) r.u8() else r.u4()
                val secOff = if (is64) r.u8() else r.u4()
                val size = if (is64) r.u8() else r.u4()
                shdrs.add(Shdr(nameOff, type, addr, secOff, size))
            }

            fun shStr(off: Long): String {
                if (shstrndx >= shdrs.size) return ""
                val strTab = shdrs[shstrndx]
                val start = strTab.offset + off
                if (start < 0 || start >= bytes.size) return ""
                var end = start.toInt()
                while (end < bytes.size && bytes[end].toInt() != 0) end++
                return String(bytes, start.toInt(), end, Charsets.UTF_8)
            }

            val sections = shdrs.map { s ->
                val end = (s.offset + s.size).coerceAtMost(bytes.size.toLong()).toInt()
                val start = s.offset.coerceAtMost(bytes.size.toLong()).toInt()
                val data = if (s.type == 8L || end <= start) ByteArray(0) else bytes.copyOfRange(start, end)
                ElfSection(shStr(s.nameOff), s.type, s.addr, s.offset, s.size, data)
            }
            return ElfFile(is64, bigEndian, elfType, sections, segments, sha256Hex(bytes))
        }
    }
}

fun sha256Hex(data: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
