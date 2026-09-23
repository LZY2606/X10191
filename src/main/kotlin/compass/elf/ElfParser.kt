package compass.elf

import compass.model.ElfClass
import compass.model.ElfFile
import compass.model.ElfSection
import compass.model.ElfSegment
import compass.model.Endian
import java.security.MessageDigest

class CorruptElfException(message: String) : RuntimeException(message)

/**
 * Minimal, strict ELF parser. Only headers/section tables/segments are read;
 * the raw bytes of debug sections are retained for the DWARF layer.
 */
object ElfParser {

    private val SHT_NOBITS = 8L

    fun parse(bytes: ByteArray, digest: (ByteArray) -> String = ::sha256Prefix): ElfFile {
        if (bytes.size < 16) throw CorruptElfException("file too small for ELF header")
        if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw CorruptElfException("bad ELF magic")

        val elfClass = when (val c = bytes[4].toInt()) {
            1 -> ElfClass.ELF32
            2 -> ElfClass.ELF64
            else -> throw CorruptElfException("unknown EI_CLASS=$c")
        }
        val endian = when (val d = bytes[5].toInt()) {
            1 -> Endian.LITTLE
            2 -> Endian.BIG
            else -> throw CorruptElfException("unknown EI_DATA=$d")
        }
        val r = Reader(bytes, endian)

        val is64 = elfClass == ElfClass.ELF64
        // e_ident(16) e_type(H) e_machine(H) e_version(I) ...
        r.seek(16)
        r.u16() // e_type
        val machine = r.u16()
        r.u32() // e_version
        val entry = if (is64) r.u64() else r.u32()
        if (is64) { r.u64(); r.u64() } else { r.u32(); r.u32() } // phoff, shoff as u32 in ELF32
        // Re-read cleanly with field offsets to avoid confusion.
        val phoff = if (is64) readAt(r, 32) { r.u64() } else readAt(r, 28) { r.u32() }
        val shoff = if (is64) readAt(r, 40) { r.u64() } else readAt(r, 32) { r.u32() }
        r.seek(if (is64) 48 else 36)
        r.u32() // e_flags
        val ehsize = r.u16()
        val phentsize = r.u16()
        val phnum = r.u16()
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()

        if (phoff < 0 || shoff < 0) throw CorruptElfException("negative offsets")

        val segments = parseSegments(r, is64, phoff, phnum, phentsize)
        val rawSections = parseSectionHeaders(r, is64, shoff, shnum, shentsize)
        if (rawSections.isEmpty()) {
            return ElfFile(elfClass, endian, machine, entry, emptyList(), segments, emptyMap())
        }
        val strIdx = when {
            shstrndx in rawSections.indices -> shstrndx
            shstrndx == 0xffff && rawSections.isNotEmpty() && rawSections[0].type == 0L ->
                (rawSections[0].link and 0xffffL).toInt()
            else -> -1
        }
        val strSection = if (strIdx in rawSections.indices) rawSections[strIdx] else null
        val finalSections = rawSections.map { s ->
            val nm = if (strSection != null)
                runCatching { r.cStringAt(strSection.offset.toInt() + s.nameOffset.toInt()) }.getOrDefault("")
            else ""
            s.copy(name = nm)
        }

        val digests = LinkedHashMap<String, String>()
        for (s in finalSections) {
            if (s.name.isEmpty() || s.type.toLong() == SHT_NOBITS || s.size == 0L) continue
            if (s.offset < 0 || s.offset + s.size > bytes.size) {
                digests[s.name] = "error:section-out-of-bounds"
                continue
            }
            val slice = bytes.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
            digests[s.name] = digest(slice)
        }

        return ElfFile(elfClass, endian, machine, entry, finalSections, segments, digests)
    }

    private inline fun <T> readAt(r: Reader, off: Int, block: () -> T): T {
        val saved = r.pos
        r.seek(off)
        val v = block()
        r.seek(saved)
        return v
    }

    private data class RawSection(
        val nameOffset: Long, val type: Long, val flags: Long, val addr: Long,
        val offset: Long, val size: Long, val link: Long, val info: Long,
        val addralign: Long, val entsize: Long,
    ) {
        fun copy(name: String) = ElfSection(name, type.toInt(), flags, addr, offset, size,
            link.toInt(), info.toInt(), addralign, entsize)
    }

    private fun parseSectionHeaders(r: Reader, is64: Boolean, shoff: Long, shnum: Int, shentsize: Int): List<RawSection> {
        if (shnum == 0) return emptyList()
        val expected = if (is64) 64 else 40
        if (shentsize < expected) throw CorruptElfException("shentsize too small")
        val out = ArrayList<RawSection>(shnum)
        for (i in 0 until shnum) {
            val base = shoff + i.toLong() * shentsize
            if (base < 0 || base + expected > r.data.size) throw CorruptElfException("section header out of file")
            r.seek(base.toInt())
            if (is64) {
                val name = r.u32(); val type = r.u32(); val flags = r.u64()
                val addr = r.u64(); val off = r.u64(); val size = r.u64()
                val link = r.u32(); val info = r.u32(); val align = r.u64(); val ent = r.u64()
                out.add(RawSection(name, type, flags, addr, off, size, link, info, align, ent))
            } else {
                val name = r.u32(); val type = r.u32(); val flags = r.u32()
                val addr = r.u32(); val off = r.u32(); val size = r.u32()
                val link = r.u32(); val info = r.u32(); val align = r.u32(); val ent = r.u32()
                out.add(RawSection(name, type, flags, addr, off, size, link, info, align, ent))
            }
        }
        return out
    }

    private fun parseSegments(r: Reader, is64: Boolean, phoff: Long, phnum: Int, phentsize: Int): List<ElfSegment> {
        if (phnum == 0 || phoff == 0L) return emptyList()
        val expected = if (is64) 56 else 32
        if (phentsize < expected) throw CorruptElfException("phentsize too small")
        val out = ArrayList<ElfSegment>(phnum)
        for (i in 0 until phnum) {
            val base = phoff + i.toLong() * phentsize
            if (base + expected > r.data.size) throw CorruptElfException("program header out of file")
            r.seek(base.toInt())
            if (is64) {
                val type = r.u32(); val flags = r.u32()
                val off = r.u64(); val va = r.u64(); val pa = r.u64()
                val fs = r.u64(); val ms = r.u64(); val align = r.u64()
                out.add(ElfSegment(type, flags, off, va, pa, fs, ms, align))
            } else {
                val type = r.u32(); val off = r.u32(); val va = r.u32(); val pa = r.u32()
                val fs = r.u32(); val ms = r.u32(); val flags = r.u32(); val align = r.u32()
                out.add(ElfSegment(type, flags, off, va, pa, fs, ms, align))
            }
        }
        return out
    }
}

fun sha256Prefix(data: ByteArray, prefixBytes: Int = 4096): String {
    val md = MessageDigest.getInstance("SHA-256")
    val n = minOf(data.size, prefixBytes)
    md.update(data, 0, n)
    md.update(intToBytes(data.size))
    return md.digest().joinToString("") { "%02x".format(it) }
}

private fun intToBytes(v: Int): ByteArray =
    byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
