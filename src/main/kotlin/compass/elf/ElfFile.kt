package compass.elf

import java.security.MessageDigest

fun sha256Hex(data: ByteArray): String {
    val md = MessageDigest.getInstance("SHA-256")
    return md.digest(data).joinToString("") { "%02x".format(it) }
}

class ElfException(msg: String) : Exception(msg)

data class ElfSection(
    val index: Int,
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val data: ByteArray,
) {
    val digest: String get() = sha256Hex(data)
}

/** Minimal self-contained ELF section reader (32/64-bit, LE/BE). No external tools. */
class ElfFile(val bytes: ByteArray) {
    val is64: Boolean
    val littleEndian: Boolean
    val sections: List<ElfSection>
    val digest: String get() = sha256Hex(bytes)

    init {
        if (bytes.size < 0x34) throw ElfException("file too small for ELF header")
        if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ElfException("not an ELF file")
        is64 = when (bytes[4].toInt()) {
            1 -> false
            2 -> true
            else -> throw ElfException("bad EI_CLASS ${bytes[4]}")
        }
        littleEndian = when (bytes[5].toInt()) {
            1 -> true
            2 -> false
            else -> throw ElfException("bad EI_DATA ${bytes[5]}")
        }
        sections = parseSections()
    }

    private fun u16(off: Int): Int {
        require(off + 2 <= bytes.size) { "header overrun" }
        val b0 = bytes[off].toInt() and 0xFF
        val b1 = bytes[off + 1].toInt() and 0xFF
        return if (littleEndian) b0 or (b1 shl 8) else (b0 shl 8) or b1
    }

    private fun u32(off: Int): Long {
        require(off + 4 <= bytes.size) { "header overrun" }
        var v = 0L
        if (littleEndian) for (i in 3 downTo 0) v = (v shl 8) or (bytes[off + i].toLong() and 0xFF)
        else for (i in 0..3) v = (v shl 8) or (bytes[off + i].toLong() and 0xFF)
        return v
    }

    private fun u64(off: Int): Long {
        require(off + 8 <= bytes.size) { "header overrun" }
        var v = 0L
        if (littleEndian) for (i in 7 downTo 0) v = (v shl 8) or (bytes[off + i].toLong() and 0xFF)
        else for (i in 0..7) v = (v shl 8) or (bytes[off + i].toLong() and 0xFF)
        return v
    }

    private fun parseSections(): List<ElfSection> {
        val shoff: Long
        val shentsize: Int
        var shnum: Int
        var shstrndx: Int
        if (is64) {
            shoff = u64(0x28); shentsize = u16(0x3A); shnum = u16(0x3C); shstrndx = u16(0x3E)
        } else {
            shoff = u32(0x20); shentsize = u16(0x2E); shnum = u32(0x30).toInt(); shstrndx = u32(0x32).toInt()
        }
        if (shoff == 0L) return emptyList()
        require(shoff + shentsize.toLong() * shnum <= bytes.size) { "section header table out of bounds" }
        data class RawSh(val nameOff: Long, val type: Long, val addr: Long, val off: Long, val size: Long, val link: Int)
        val raw = ArrayList<RawSh>()
        for (i in 0 until shnum) {
            val base = (shoff + i.toLong() * shentsize).toInt()
            if (is64) {
                raw.add(RawSh(u32(base), u32(base + 4), u64(base + 16), u64(base + 24), u64(base + 32), u32(base + 40).toInt()))
            } else {
                raw.add(RawSh(u32(base), u32(base + 4), u32(base + 12), u32(base + 16), u32(base + 20), u32(base + 24).toInt()))
            }
        }
        if (shnum == 0 && raw.isNotEmpty()) shnum = raw[0].size.toInt() // extended numbering
        if (shstrndx == 0xFFFF && raw.isNotEmpty()) shstrndx = raw[0].link
        val strtab: ByteArray = if (shstrndx in raw.indices) {
            val s = raw[shstrndx]
            require(s.off + s.size <= bytes.size) { "shstrtab out of bounds" }
            bytes.copyOfRange(s.off.toInt(), (s.off + s.size).toInt())
        } else ByteArray(0)

        fun nameAt(no: Long): String {
            if (no >= strtab.size) return ""
            var end = no.toInt()
            while (end < strtab.size && strtab[end] != 0.toByte()) end++
            return String(strtab, no.toInt(), end - no.toInt(), Charsets.UTF_8)
        }

        return raw.mapIndexed { i, s ->
            val data = when {
                s.type == 8L -> ByteArray(0) // SHT_NOBITS
                s.off + s.size > bytes.size -> throw ElfException("section $i (${nameAt(s.nameOff)}) data out of bounds")
                else -> bytes.copyOfRange(s.off.toInt(), (s.off + s.size).toInt())
            }
            ElfSection(i, nameAt(s.nameOff), s.type, s.addr, s.off, s.size, s.link, data)
        }
    }

    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    fun dwarfSections(): Map<String, ByteArray> =
        sections.filter { it.name.startsWith(".debug") || it.name.startsWith(".zdebug") }
            .associate { it.name to it.data }
}
