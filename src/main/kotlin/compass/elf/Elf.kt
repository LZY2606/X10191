package compass.elf

import compass.binary.BinaryBoundsException
import compass.binary.ByteReader
import java.security.MessageDigest

/** 目标地址统一为 64 位无符号值（用 Long 存储，比较时按无符号）。 */
typealias ElfAddr = Long

data class ElfSection(
    val nameOffset: Int,
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val entsize: Long,
) {
    fun reader(file: ElfFile): ByteReader? {
        if (size == 0L) return null
        val start = offset
        val end = start + size
        if (start < 0 || end < 0 || end > file.bytes.size.toLong()) return null
        return ByteReader(file.bytes, start.toInt(), end.toInt(), file.littleEndian)
    }
}

data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
)

data class BuildId(val hex: String)

data class ByteDigest(
    val size: Long,
    val sha256: String,
    val firstBytesHex: String,
    val sectionDigests: Map<String, String>,
)

class ElfFile(
    val bytes: ByteArray,
    val elfClass: Int,       // 1=32bit, 2=64bit
    val littleEndian: Boolean,
    val type: Int,
    val machine: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val buildId: BuildId?,
    val shstrtab: ByteArray,
    val digest: ByteDigest,
) {
    val is64 = elfClass == 2
    val isRelocatable = type == ET_REL
    val isDynamic = type == ET_DYN
    val isExecutable = type == ET_EXEC

    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }
    fun sectionReader(name: String): ByteReader? = section(name)?.reader(this)
    fun rawSection(name: String): ByteArray? {
        val s = section(name) ?: return null
        if (s.size == 0L) return ByteArray(0)
        return bytes.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
    }

    /** vaddr -> 所属 PT_LOAD，用于 load bias 推断；返回索引与段。 */
    fun segmentForVaddr(vaddr: Long): ElfSegment? =
        segments.firstOrNull { vaddr in it.vaddr until it.vaddr + it.memsz }

    companion object {
        const val ET_REL = 1
        const val ET_EXEC = 2
        const val ET_DYN = 3
        const val PT_LOAD = 1
        const val PT_NOTE = 4
        const val SHT_NOBITS = 8
        const val SHF_ALLOC = 2L
    }
}

class ElfParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

object ElfParser {
    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ElfParseException("不是 ELF 文件（魔数不匹配）")
        val elfClass = bytes[4].toInt() and 0xff
        if (elfClass != 1 && elfClass != 2) throw ElfParseException("未知 ELFCLASS=$elfClass")
        val endianByte = bytes[5].toInt() and 0xff
        val littleEndian = when (endianByte) { 1 -> true; 2 -> false; else -> throw ElfParseException("未知 ELFDATA") }
        val r = ByteReader(bytes, 0, bytes.size, littleEndian)
        r.pos = 16
        val type = r.u16()
        val machine = r.u16()
        r.u32() // e_version
        val entry = if (elfClass == 2) r.u64() else r.u32()

        if (elfClass == 2) {
            val phoff = r.u64(); val shoff = r.u64(); r.u32()
            val ehsize = r.u16(); val phentsize = r.u16(); val phnum = r.u16()
            val shentsize = r.u16(); val shnum = r.u16(); val shstrndx = r.u16()
            val segments = readSegments64(r, phoff, phentsize, phnum)
            val (sections, shstr) = readSections64(r, shoff, shentsize, shnum, shstrndx)
            val buildId = readBuildId(bytes, segments, littleEndian, elfClass)
            val digest = buildDigest(bytes, sections)
            return ElfFile(bytes, elfClass, littleEndian, type, machine, entry, sections, segments, buildId, shstr, digest)
        } else {
            val phoff = r.u32(); val shoff = r.u32(); r.u32()
            val ehsize = r.u16(); val phentsize = r.u16(); val phnum = r.u16()
            val shentsize = r.u16(); val shnum = r.u16(); val shstrndx = r.u16()
            val segments = readSegments32(r, phoff, phentsize, phnum)
            val (sections, shstr) = readSections32(r, shoff, shentsize, shnum, shstrndx)
            val buildId = readBuildId(bytes, segments, littleEndian, elfClass)
            val digest = buildDigest(bytes, sections)
            return ElfFile(bytes, elfClass, littleEndian, type, machine, entry, sections, segments, buildId, shstr, digest)
        }
    }

    private fun readSections64(r: ByteReader, shoff: Long, shentsize: Int, shnum: Int, shstrndx: Int): Pair<List<ElfSection>, ByteArray> {
        if (shnum == 0 || shoff == 0L) return emptyList<ElfSection>() to ByteArray(0)
        if (shnum > 1_000_000) throw ElfParseException("节数量异常: $shnum")
        val raw = (0 until shnum).map { i ->
            val base = (shoff + i.toLong() * shentsize).toInt()
            val sr = r.slice(base, minOf(base + shentsize, bytesEnd(r)))
            val nameOff = sr.u32().toInt(); val type = sr.u32().toInt(); val flags = sr.u64()
            val addr = sr.u64(); val off = sr.u64(); val size = sr.u64()
            val link = sr.u32().toInt(); val info = sr.u32().toInt(); val align = sr.u64(); val ent = sr.u64()
            RawSec(nameOff, type, flags, addr, off, size, link, info, align, ent)
        }
        val shstr = if (shstrndx in raw.indices) extract(r.data, raw[shstrndx]) else ByteArray(0)
        return raw.mapIndexed { idx, s -> ElfSection(s.nameOff, secName(shstr, s.nameOff), s.type, s.flags, s.addr, s.off, s.size, s.link, s.info, s.align, s.ent) } to shstr
    }

    private fun readSections32(r: ByteReader, shoff: Long, shentsize: Int, shnum: Int, shstrndx: Int): Pair<List<ElfSection>, ByteArray> {
        if (shnum == 0 || shoff == 0L) return emptyList<ElfSection>() to ByteArray(0)
        if (shnum > 1_000_000) throw ElfParseException("节数量异常: $shnum")
        val raw = (0 until shnum).map { i ->
            val base = (shoff + i.toLong() * shentsize).toInt()
            val sr = r.slice(base, minOf(base + shentsize, bytesEnd(r)))
            val nameOff = sr.u32().toInt(); val type = sr.u32().toInt(); val flags = sr.u32(); val addr = sr.u32(); val off = sr.u32(); val size = sr.u32()
            val link = sr.u32().toInt(); val info = sr.u32().toInt(); val align = sr.u32(); val ent = sr.u32()
            RawSec(nameOff, type, flags, addr, off, size, link, info, align, ent)
        }
        val shstr = if (shstrndx in raw.indices) extract(r.data, raw[shstrndx]) else ByteArray(0)
        return raw.map { s -> ElfSection(s.nameOff, secName(shstr, s.nameOff), s.type, s.flags, s.addr, s.off, s.size, s.link, s.info, s.align, s.ent) } to shstr
    }

    private data class RawSec(val nameOff: Int, val type: Int, val flags: Long, val addr: Long, val off: Long, val size: Long, val link: Int, val info: Int, val align: Long, val ent: Long)

    private fun readSegments64(r: ByteReader, phoff: Long, phentsize: Int, phnum: Int): List<ElfSegment> {
        if (phnum == 0 || phoff == 0L) return emptyList()
        if (phnum > 1_000_000) throw ElfParseException("段数量异常")
        return (0 until phnum).map { i ->
            val base = (phoff + i.toLong() * phentsize).toInt()
            val pr = r.slice(base, minOf(base + phentsize, bytesEnd(r)))
            val type = pr.u32().toInt(); val flags = pr.u32().toInt()
            val off = pr.u64(); val vaddr = pr.u64(); val paddr = pr.u64(); val filesz = pr.u64(); val memsz = pr.u64(); val align = pr.u64()
            ElfSegment(type, flags, off, vaddr, paddr, filesz, memsz, align)
        }
    }

    private fun readSegments32(r: ByteReader, phoff: Long, phentsize: Int, phnum: Int): List<ElfSegment> {
        if (phnum == 0 || phoff == 0L) return emptyList()
        if (phnum > 1_000_000) throw ElfParseException("段数量异常")
        return (0 until phnum).map { i ->
            val base = (phoff + i.toLong() * phentsize).toInt()
            val pr = r.slice(base, minOf(base + phentsize, bytesEnd(r)))
            val type = pr.u32().toInt(); val off = pr.u32(); val vaddr = pr.u32(); val paddr = pr.u32(); val filesz = pr.u32(); val memsz = pr.u32()
            val flags = pr.u32().toInt(); val align = pr.u32()
            ElfSegment(type, flags, off, vaddr, paddr, filesz, memsz, align)
        }
    }

    private fun bytesEnd(r: ByteReader) = r.end

    private fun extract(data: ByteArray, s: RawSec): ByteArray {
        val start = s.off.toInt(); val end = start + s.size.toInt()
        if (start < 0 || end > data.size) throw BinaryBoundsException("节越界: off=${s.off} size=${s.size}")
        return data.copyOfRange(start, end)
    }

    private fun secName(strtab: ByteArray, off: Int): String {
        if (off < 0 || off >= strtab.size) return ""
        var end = off
        while (end < strtab.size && strtab[end].toInt() != 0) end++
        return String(strtab, off, end - off, Charsets.UTF_8)
    }

    private fun sha256(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun buildDigest(bytes: ByteArray, sections: List<ElfSection>): ByteDigest {
        val first = bytes.copyOfRange(0, minOf(32, bytes.size)).joinToString("") { "%02x".format(it) }
        val sd = sections.filter { it.name.isNotEmpty() && it.type != ElfFile.SHT_NOBITS && it.size > 0 }
            .associate { it.name to sha256(bytes.copyOfRange(it.offset.toInt(), (it.offset + it.size).toInt())) }
        return ByteDigest(bytes.size.toLong(), sha256(bytes), first, sd)
    }

    private fun readBuildId(bytes: ByteArray, segments: List<ElfSegment>, le: Boolean, elfClass: Int): BuildId? {
        for (note in segments.filter { it.type == ElfFile.PT_NOTE }) {
            try {
                val start = note.offset.toInt(); val end = start + note.filesz.toInt()
                if (start < 0 || end > bytes.size) continue
                val r = ByteReader(bytes, start, end, le)
                while (r.remaining() >= 12) {
                    val namesz = (if (elfClass == 2) r.u32() else r.u32()).toInt()
                    val descsz = r.u32().toInt()
                    val ntype = r.u32().toInt()
                    val nameStart = r.pos
                    val name = r.readN(namesz)
                    r.align(4)
                    val descStart = r.pos
                    val desc = r.readN(descsz)
                    r.align(4)
                    val nameStr = String(name, 0, namesz - if (namesz > 0) 1 else 0, Charsets.UTF_8)
                    if (ntype == 3 && (nameStr == "GNU" || nameStr.startsWith("GNU")) && descsz in 4..64) {
                        return BuildId(desc.joinToString("") { "%02x".format(it) })
                    }
                }
            } catch (_: Exception) { /* 损坏 note 不影响主体解析 */ }
        }
        return null
    }
}
