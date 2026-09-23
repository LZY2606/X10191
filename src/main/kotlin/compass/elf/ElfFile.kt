package compass.elf

import compass.dwarf.ByteReader
import java.security.MessageDigest

/** One ELF section as found in the section header table. */
data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
)

class ElfException(message: String, cause: Throwable? = null) : Exception(message, cause)

private data class RawSection(
    val nameOff: Int,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
)

private data class Reloc(val offset: Long, val sym: Long, val type: Long, val addend: Long)

/**
 * Minimal ELF parser: identification, section header table (with sh_0
 * extended numbering), section bytes, and RELA relocations applied to
 * debug sections so address-bearing fields read as linked values.
 */
class ElfFile(val bytes: ByteArray) {
    var elfClass: Int = 2
        private set
    var littleEndian: Boolean = true
        private set
    var machine: Int = 0
        private set
    var etype: Int = 0
        private set
    var sections: List<ElfSection> = emptyList()
        private set
    val warnings = mutableListOf<String>()
    private val sectionData = HashMap<String, ByteArray>()

    init { parse() }

    private fun parse() {
        if (bytes.size < 52 || bytes[0] != 0x7F.toByte() ||
            bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() ||
            bytes[3] != 'F'.code.toByte()) throw ElfException("not an ELF file (bad magic)")
        elfClass = bytes[4].toInt() and 0xFF
        if (elfClass != 1 && elfClass != 2) throw ElfException("unknown ELF class $elfClass")
        littleEndian = (bytes[5].toInt() and 0xFF) == 1
        val r = ByteReader(bytes, 0, bytes.size, littleEndian)
        if (elfClass == 2) parse64(r) else parse32(r)
    }

    private fun parse32(r: ByteReader) {
        r.pos = 16
        etype = r.u16()
        machine = r.u16()
        r.pos = 32
        val shoff = r.u32()
        r.pos = 46
        val shentsize = r.u16()
        val shnum0 = r.u16()
        val shstrndx0 = r.u16()
        val raw = readRaw32(r, shoff.toInt(), shentsize, shnum0)
        finish(raw, shoff, shstrndx0, 4)
    }

    private fun parse64(r: ByteReader) {
        r.pos = 16
        etype = r.u16()
        machine = r.u16()
        r.pos = 40
        val shoff = r.u64()
        r.pos = 58
        val shentsize = r.u16()
        val shnum0 = r.u16()
        val shstrndx0 = r.u16()
        val raw = readRaw64(r, shoff, shentsize, shnum0)
        finish(raw, shoff, shstrndx0, 8)
    }

    private fun readRaw32(r: ByteReader, shoff: Int, entsize: Int, shnumIn: Int): List<RawSection> {
        var shnum = shnumIn
        if (shnum == 0 && shoff + 24 <= bytes.size) {
            r.pos = shoff + 20
            shnum = r.u32().toInt()
        }
        val out = ArrayList<RawSection>(shnum)
        for (i in 0 until shnum) {
            r.pos = shoff + i * entsize
            val nameOff = r.u32().toInt()
            val type = r.u32().toInt()
            val flags = r.u32()
            val addr = r.u32()
            val off = r.u32()
            val size = r.u32()
            val link = r.u32().toInt()
            val info = r.u32().toInt()
            val align = r.u32()
            out.add(RawSection(nameOff, type, flags, addr, off, size, link, info, align))
        }
        return out
    }

    private fun readRaw64(r: ByteReader, shoff: Long, entsize: Int, shnumIn: Int): List<RawSection> {
        var shnum = shnumIn
        if (shnum == 0 && shoff + 48 <= bytes.size.toLong()) {
            r.pos = (shoff + 32).toInt()
            shnum = r.u64().toInt()
        }
        val out = ArrayList<RawSection>(shnum)
        for (i in 0 until shnum) {
            r.pos = (shoff + i * entsize).toInt()
            val nameOff = r.u32().toInt()
            val type = r.u32().toInt()
            val flags = r.u64()
            val addr = r.u64()
            val off = r.u64()
            val size = r.u64()
            val link = r.u32().toInt()
            val info = r.u32().toInt()
            val align = r.u64()
            out.add(RawSection(nameOff, type, flags, addr, off, size, link, info, align))
        }
        return out
    }

    private fun finish(raw: List<RawSection>, shoff: Long, shstrndxIn: Int, addressSize: Int) {
        var shstrndx = shstrndxIn
        if (shstrndx == 0xFFFF && raw.isNotEmpty()) {
            shstrndx = if (elfClass == 2) {
                ByteReader(bytes, (shoff + 44).toInt(), bytes.size, littleEndian).u64().toInt()
            } else {
                ByteReader(bytes, (shoff + 24).toInt(), bytes.size, littleEndian).u32().toInt()
            }
        }
        val names = if (shstrndx in raw.indices) sliceFor(raw[shstrndx], ".shstrtab") else ByteArray(1)
        sections = raw.mapIndexed { idx, s ->
            ElfSection(if (idx == 0) "" else nameAt(names, s.nameOff), s.type, s.flags, s.addr, s.offset, s.size, s.link, s.info, s.addralign)
        }
        sections.forEachIndexed { idx, s ->
            if (idx != 0 && s.size > 0) sectionData[s.name] = sliceFor(raw[idx], s.name)
        }
        if (elfClass == 2) applyRelocations64(raw, addressSize)
    }

    private fun sliceFor(s: RawSection, label: String): ByteArray {
        if (s.offset < 0 || s.size < 0 || s.offset + s.size > bytes.size.toLong()) {
            warnings.add("section $label header outside file (off=${s.offset} size=${s.size}); truncated")
            val start = s.offset.toInt().coerceIn(0, bytes.size)
            val end = (s.offset + s.size).coerceAtMost(bytes.size.toLong()).toInt()
            return if (end > start) bytes.copyOfRange(start, end) else ByteArray(0)
        }
        return bytes.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
    }

    private fun nameAt(names: ByteArray, off: Int): String {
        if (off < 0 || off >= names.size) return "<bad name @$off>"
        var end = off
        while (end < names.size && names[end].toInt() != 0) end++
        return String(names, off, end - off, Charsets.UTF_8)
    }

    fun section(name: String): ByteArray? = sectionData[name]

    /** 64-bit RELA only; symbol values are added for local symbols (e.g. static functions). */
    private fun applyRelocations64(raw: List<RawSection>, @Suppress("UNUSED_PARAMETER") addressSize: Int) {
        val byIndex = HashMap<Int, List<Reloc>>()
        for ((idx, s) in raw.withIndex()) {
            if (s.type != SHT_RELA) continue
            val target = s.info
            val data = sliceFor(s, ".rela($target)")
            val symSec = if (s.link in raw.indices) raw[s.link] else null
            val symData = symSec?.let { sliceFor(it, ".symtab") }
            val relocR = ByteReader(data, 0, data.size, littleEndian)
            val list = ArrayList<Reloc>()
            while (relocR.hasRemaining()) {
                if (relocR.remaining < 24) {
                    warnings.add("trailing ${relocR.remaining} bytes in relocation section #$idx ignored")
                    break
                }
                val off = relocR.u64()
                val info = relocR.u64()
                val addend = relocR.u64()
                list.add(Reloc(off, info ushr 32, info and 0xFFFFFFFFL, addend))
            }
            byIndex[target] = list
        }
        for ((targetIndex, rels) in byIndex) {
            if (targetIndex !in raw.indices) continue
            val target = raw[targetIndex]
            val buf = sectionData[sections[targetIndex].name]?.copyOf() ?: continue
            val applied = applyToBuffer(buf, rels, sections[targetIndex].name, targetIndex, raw)
            if (applied) sectionData[sections[targetIndex].name] = buf
        }
    }

    private fun applyToBuffer(buf: ByteArray, rels: List<Reloc>, targetName: String, targetIndex: Int, raw: List<RawSection>): Boolean {
        // Find symbol table through the rela section's sh_link instead.
        val rela = raw.firstOrNull { it.type == SHT_RELA && it.info == targetIndex } ?: return false
        val symRaw = raw.getOrNull(rela.link) ?: return false
        val symData = sliceFor(symRaw, ".symtab")
        val symR = ByteReader(symData, 0, symData.size, littleEndian)
        fun symValue(sym: Long): Long {
            val off = (sym * 24).toInt()
            if (off + 24 > symData.size) return 0L
            symR.pos = off + 8
            return symR.u64()
        }
        var any = false
        for (rel in rels) {
            val kindOk = when (machine) {
                62 -> rel.type == 1L   // R_X86_64_64
                183 -> rel.type == 257L // R_AARCH64_ABS64
                else -> true
            }
            if (!kindOk) {
                warnings.add("unsupported relocation type ${rel.type} in .rela for $targetName @${rel.offset}")
                continue
            }
            val off = rel.offset.toInt()
            if (off < 0 || off + 8 > buf.size) {
                warnings.add("relocation for $targetName @${rel.offset} outside section")
                continue
            }
            val value = symValue(rel.sym) + rel.addend
            var v = value
            for (i in 0 until 8) {
                buf[off + i] = (if (littleEndian) (v and 0xFF) else ((v ushr 56) and 0xFF)).toByte()
                v = if (littleEndian) v ushr 8 else v shl 8
            }
            any = true
        }
        return any
    }

    fun rawByteDigest(): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(bytes).joinToString("") { "%02x".format(it) }
    }

    companion object {
        const val ET_REL = 1
        const val ET_EXEC = 2
        const val ET_DYN = 3
        const val SHT_RELA = 4
        const val SHT_REL = 9
    }
}
