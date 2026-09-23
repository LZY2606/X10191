package compass

import java.security.MessageDigest

/** A single ELF section with its raw bytes preserved. */
data class ElfSection(
    val name: String,
    val type: Long,
    val offset: Long,
    val size: Long,
    val addr: Long,
    val data: ByteArray,
) {
    val sha256: String get() = sha256Of(data)
}

data class ElfFile(
    val is64: Boolean,
    val littleEndian: Boolean,
    val machine: Int,
    val sections: List<ElfSection>,
)

fun sha256Of(data: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

class ElfParseException(msg: String) : Exception(msg)

object ElfParser {
    const val MAX_SECTIONS = 4096
    const val MAX_SECTION_SIZE = 512L * 1024 * 1024

    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 16) throw ElfParseException("file too small for ELF header")
        if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ElfParseException("not an ELF file (bad magic)")
        val is64 = when (bytes[4].toInt()) {
            1 -> false; 2 -> true
            else -> throw ElfParseException("unknown ELF class ${bytes[4]}")
        }
        val little = when (bytes[5].toInt()) {
            1 -> true; 2 -> false
            else -> throw ElfParseException("unknown ELF data encoding ${bytes[5]}")
        }
        val r = Cursor(bytes, 0, bytes.size, little)
        r.pos = 16
        r.u16() // e_type
        val machine = r.u16()
        r.u32() // e_version
        if (is64) r.u64() else r.u32() // e_entry
        r.u32Or64(is64) // e_phoff
        val shoff = r.u32Or64(is64)
        r.u32() // e_flags
        r.u16() // e_ehsize
        r.u16(); r.u16() // phentsize, phnum
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()
        if (shoff == 0L || shnum == 0) return ElfFile(is64, little, machine, emptyList())
        if (shnum > MAX_SECTIONS) throw ElfParseException("too many sections: $shnum")
        if (shoff + shnum.toLong() * shentsize > bytes.size)
            throw ElfParseException("section header table out of bounds")

        data class Sh(val nameOff: Long, val type: Long, val addr: Long, val off: Long, val size: Long)
        val headers = ArrayList<Sh>(shnum)
        for (i in 0 until shnum) {
            r.pos = (shoff + i.toLong() * shentsize).toInt()
            val nameOff = r.u32()
            val type = r.u32()
            r.u32Or64(is64) // flags
            val addr = r.u32Or64(is64)
            val off = r.u32Or64(is64)
            val size = r.u32Or64(is64)
            headers += Sh(nameOff, type, addr, off, size)
        }
        val strSh = headers.getOrNull(shstrndx)
            ?: return ElfFile(is64, little, machine, emptyList())
        if (strSh.off + strSh.size > bytes.size) throw ElfParseException("shstrtab out of bounds")

        val sections = ArrayList<ElfSection>()
        for (h in headers) {
            val name = cstrAt(bytes, strSh.off.toInt(), h.nameOff.toInt())
            if (h.type == 8L /* SHT_NOBITS */ || h.size == 0L) {
                sections += ElfSection(name, h.type, h.off, h.size, h.addr, ByteArray(0))
                continue
            }
            if (h.size > MAX_SECTION_SIZE) throw ElfParseException("section $name too large: ${h.size}")
            if (h.off + h.size > bytes.size) throw ElfParseException("section $name out of bounds")
            val data = bytes.copyOfRange(h.off.toInt(), (h.off + h.size).toInt())
            sections += ElfSection(name, h.type, h.off, h.size, h.addr, data)
        }
        return ElfFile(is64, little, machine, sections)
    }

    private fun cstrAt(buf: ByteArray, base: Int, off: Int): String {
        var i = base + off
        if (i < 0 || i >= buf.size) return ""
        val start = i
        while (i < buf.size && buf[i] != 0.toByte()) i++
        return String(buf, start, i - start, Charsets.UTF_8)
    }
}
