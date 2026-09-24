package compass.elf

import compass.dwarf.DwarfParseException
import compass.dwarf.Reader
import java.security.MessageDigest

data class ElfSection(
    val name: String,
    val type: Long,
    val offset: Long,
    val size: Long,
    val addr: Long,
    val sha256: String
)

data class ElfFile(
    val is64Bit: Boolean,
    val littleEndian: Boolean,
    val machine: Int,
    val sections: List<ElfSection>,
    val sha256: String
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    /** Raw bytes of a named section, or null when absent. */
    fun sectionBytes(whole: ByteArray, name: String): ByteArray? {
        val s = section(name) ?: return null
        if (s.offset < 0 || s.offset + s.size > whole.size) return null
        return whole.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
    }

    companion object {
        fun sha256(bytes: ByteArray): String {
            val md = MessageDigest.getInstance("SHA-256")
            return md.digest(bytes).joinToString("") { "%02x".format(it) }
        }

        fun parse(bytes: ByteArray): ElfFile {
            if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte()
                || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
            ) {
                throw DwarfParseException("not an ELF file")
            }
            val is64 = when (bytes[4].toInt()) {
                1 -> false
                2 -> true
                else -> throw DwarfParseException("bad ELF class ${bytes[4]}")
            }
            val le = when (bytes[5].toInt()) {
                1 -> true
                2 -> false
                else -> throw DwarfParseException("bad ELF endianness ${bytes[5]}")
            }
            val r = Reader(bytes, 0, bytes.size, le)
            r.pos = 16
            r.u16() // e_type
            val machine = r.u16()
            r.u32() // e_version
            if (is64) r.u64() else r.u32() // e_entry
            val phoff = if (is64) r.u64() else r.u32()
            val shoff = if (is64) r.u64() else r.u32()
            r.u32() // flags
            r.u16() // ehsize
            r.u16() // phentsize
            r.u16() // phnum
            val shentsize = r.u16()
            val shnum = r.u16()
            val shstrndx = r.u16()
            if (shoff == 0L || shnum == 0) {
                return ElfFile(is64, le, machine, emptyList(), sha256(bytes))
            }
            if (shoff + shentsize.toLong() * shnum > bytes.size) {
                throw DwarfParseException("section header table out of bounds")
            }
            data class RawSh(val nameOff: Long, val type: Long, val addr: Long, val off: Long, val size: Long)
            val raw = ArrayList<RawSh>()
            for (i in 0 until shnum) {
                r.pos = (shoff + i.toLong() * shentsize).toInt()
                val nameOff = r.u32()
                val type = r.u32()
                if (is64) {
                    r.u64() // flags
                    val addr = r.u64()
                    val off = r.u64()
                    val size = r.u64()
                    raw.add(RawSh(nameOff, type, addr, off, size))
                } else {
                    r.u32() // flags
                    val addr = r.u32()
                    val off = r.u32()
                    val size = r.u32()
                    raw.add(RawSh(nameOff, type, addr, off, size))
                }
            }
            val strSec = raw.getOrNull(shstrndx)
                ?: throw DwarfParseException("bad shstrndx $shstrndx")
            if (strSec.off + strSec.size > bytes.size) {
                throw DwarfParseException("shstrtab out of bounds")
            }
            fun strAt(off: Long): String {
                var p = (strSec.off + off).toInt()
                val end = (strSec.off + strSec.size).toInt()
                if (p >= end) return ""
                val start = p
                while (p < end && bytes[p].toInt() != 0) p++
                return String(bytes, start, p - start, Charsets.UTF_8)
            }
            val sections = raw.map { sh ->
                val safeSize = if (sh.off + sh.size <= bytes.size) sh.size else 0L
                val digest = if (safeSize > 0) {
                    sha256(bytes.copyOfRange(sh.off.toInt(), (sh.off + safeSize).toInt()))
                } else {
                    sha256(ByteArray(0))
                }
                ElfSection(strAt(sh.nameOff), sh.type, sh.off, sh.size, sh.addr, digest)
            }
            return ElfFile(is64, le, machine, sections, sha256(bytes))
        }
    }
}
