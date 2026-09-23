package compass.elf

import compass.ByteReader
import java.security.MessageDigest

/** A single ELF section with raw bytes retained for later DWARF parsing. */
class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val fileOffset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val raw: ByteArray,
)

/** Parsed subset of an ELF executable / shared object / relocatable. */
class ElfFile(
    val elfClass: Int,
    val dataEncoding: Int,
    val type: Int,
    val machine: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val sha256: String,
    val byteSize: Long,
) {
    private val byName = sections.associateBy { it.name }
    fun section(name: String): ElfSection? = byName[name]
    fun hasSection(name: String): Boolean = byName.containsKey(name)

    /** ELF files are relocated with a single load bias (we do not model segment perms). */
    val isRelocatable: Boolean get() = type == ET_DYN

    companion object {
        const val ELFCLASS32 = 1
        const val ELFCLASS64 = 2
        const val ET_REL = 1
        const val ET_EXEC = 2
        const val ET_DYN = 3
    }
}

object ElfParser {

    private const val SHT_NOBITS = 8

    fun parse(bytes: ByteArray): ElfFile {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes)
        val r = ByteReader(bytes)
        if (r.remaining < 16 || r.u8() != 0x7f || r.u8() != 'E'.code || r.u8() != 'L'.code || r.u8() != 'F'.code) {
            throw IllegalArgumentException("not an ELF file (bad magic)")
        }
        val elfClass = r.u8()
        if (elfClass != ElfFile.ELFCLASS32 && elfClass != ElfFile.ELFCLASS64) {
            throw IllegalArgumentException("unsupported ELF class $elfClass")
        }
        val dataEnc = r.u8()
        if (dataEnc != 1) throw IllegalArgumentException("only little-endian ELF supported")
        r.skip(1) // EI_OSABI
        r.skip(8) // padding

        val (type, machine, entry, shoff) = if (elfClass == ElfFile.ELFCLASS64) {
            val t = r.u16(); val m = r.u16()
            r.u32() // version
            val e = r.u64()
            r.u64() // phoff
            val so = r.u64()
            Quint(t, m, e, so)
        } else {
            val t = r.u16(); val m = r.u16()
            r.u32() // version
            val e = r.u32()
            r.u32() // phoff
            val so = r.u32()
            Quint(t, m, e, so)
        }
        r.seek(if (elfClass == ElfFile.ELFCLASS64) 60 else 48)
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()

        if (shnum == 0) return ElfFile(elfClass, dataEnc, type, machine, entry, emptyList(), hex(sha), bytes.size.toLong())

        val rawHeaders = ArrayList<RawShdr>(shnum)
        for (i in 0 until shnum) {
            r.seek((shoff + i.toLong() * shentsize).toIntExact())
            rawHeaders += readShdr(r, elfClass)
        }

        val nameSection = rawHeaders.getOrNull(shstrndx)
            ?: throw IllegalArgumentException("invalid shstrndx $shstrndx")
        val names = bytes.copyOfRange(nameSection.offset.toIntExact(),
            (nameSection.offset + nameSection.size).toIntExact())

        val sections = rawHeaders.mapIndexed { idx, h ->
            val nm = readName(names, h.nameOffset)
            val raw = when {
                h.type == SHT_NOBITS -> ByteArray(0)
                h.size == 0L -> ByteArray(0)
                else -> {
                    val off = h.offset.toIntExact()
                    val len = h.size.toIntExact()
                    if (off < 0 || off + len > bytes.size) {
                        throw IllegalArgumentException("section $nm #$idx extends past file end")
                    }
                    bytes.copyOfRange(off, off + len)
                }
            }
            ElfSection(nm, h.type, h.flags, h.addr, h.offset, h.size, h.link, h.info, h.addralign, raw)
        }
        return ElfFile(elfClass, dataEnc, type, machine, entry, sections, hex(sha), bytes.size.toLong())
    }

    private data class RawShdr(
        val nameOffset: Int, val type: Int, val flags: Long, val addr: Long,
        val offset: Long, val size: Long, val link: Int, val info: Int,
        val addralign: Long, val entsize: Long,
    )

    private fun readShdr(r: ByteReader, elfClass: Int): RawShdr = if (elfClass == ElfFile.ELFCLASS64) {
        val name = r.u32().toIntExact()
        val type = r.u32().toIntExact()
        val flags = r.u64()
        val addr = r.u64()
        val off = r.u64()
        val size = r.u64()
        val link = r.u32().toIntExact()
        val info = r.u32().toIntExact()
        val align = r.u64()
        val entsize = r.u64()
        RawShdr(name, type, flags, addr, off, size, link, info, align, entsize)
    } else {
        val name = r.u32().toIntExact()
        val type = r.u32().toIntExact()
        val flags = r.u32()
        val addr = r.u32()
        val off = r.u32()
        val size = r.u32()
        val link = r.u32().toIntExact()
        val info = r.u32().toIntExact()
        val align = r.u32()
        val entsize = r.u32()
        RawShdr(name, type, flags, addr, off, size, link, info, align, entsize)
    }

    private fun readName(table: ByteArray, offset: Int): String {
        if (offset < 0 || offset >= table.size) return "<bad name $offset>"
        var end = offset
        while (end < table.size && table[end].toInt() != 0) end++
        return String(table, offset, end - offset, Charsets.UTF_8)
    }

    private data class Quint(val type: Int, val machine: Int, val entry: Long, val shoff: Long)

    private fun Long.toIntExact(): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw IllegalArgumentException("offset too large: $this")
        return toInt()
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
}
