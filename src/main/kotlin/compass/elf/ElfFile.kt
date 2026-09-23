package compass.elf

import java.security.MessageDigest

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val address: Long,
    val fileOffset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val entrySize: Long,
    val bytes: ByteArray,
) {
    override fun equals(other: Any?) = other is ElfSection && name == other.name && fileOffset == other.fileOffset
    override fun hashCode(): Int = name.hashCode() * 31 + fileOffset.hashCode()
    fun isAllocated(): Boolean = flags and 0x2L != 0L // SHF_ALLOC
}

data class LoadSegment(
    val type: Int,
    val flags: Int,
    val fileOffset: Long,
    val vaddr: Long,
    val fileSize: Long,
    val memSize: Long,
    val align: Long,
) {
    /** ELF 文件视角的“优先装载基址”：第一个 PT_LOAD 的 vaddr（通常为 0）。 */
    fun contains(vaddr: Long): Boolean = vaddr >= this.vaddr && vaddr < this.vaddr + this.memSize
}

data class SectionDigest(
    val name: String,
    val size: Long,
    val sha256: String,
    val head16: String,
    val tail16: String,
)

data class ElfFile(
    val elfClass: Int,        // 1 = ELF32, 2 = ELF64
    val littleEndian: Boolean,
    val entry: Long,
    val machine: Int,
    val sections: List<ElfSection>,
    val segments: List<LoadSegment>,
    val buildId: String?,
    val fileSha256: String,
    val fileSize: Long,
    val sectionDigests: List<SectionDigest>,
    val rawBytes: ByteArray,
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    fun sectionReader(name: String): ByteReader? =
        section(name)?.let { ByteReader(it.bytes, littleEndian) }

    /** 装载段覆盖的（运行时 vaddr）范围；用于模块归属与 load bias 计算。 */
    fun coversVaddr(vaddr: Long): Boolean = segments.any { it.contains(vaddr) }

    fun fileOffsetForVaddr(vaddr: Long): Long? {
        val seg = segments.firstOrNull { it.contains(vaddr) } ?: return null
        if (vaddr - seg.vaddr >= seg.fileSize) return null // bss 区域：文件中不存在
        return seg.fileOffset + (vaddr - seg.vaddr)
    }
}

class ElfParseException(message: String) : RuntimeException(message)

object ElfParser {
    private const val PT_LOAD = 1
    private const val SHT_STRTAB = 3
    private const val SHT_NOTE = 7
    private const val NT_GNU_BUILD_ID = 3

    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 64) throw ElfParseException("file too small for ELF")
        if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            throw ElfParseException("missing \\x7fELF magic")
        }
        val cls = bytes[4].toInt()
        if (cls != 1 && cls != 2) throw ElfParseException("unknown EI_CLASS=${bytes[4]}")
        val endian = when (bytes[5].toInt()) {
            1 -> true
            2 -> false
            else -> throw ElfParseException("unknown EI_DATA=${bytes[5]}")
        }
        val r = ByteReader(bytes, endian)

        val (entry, machine, phOff, shOff, phentsize, phnum, shentsize, shnum, shstrndx) = if (cls == 2) {
            r.pos = 0x18
            val eType = r.u16()
            val eMachine = r.u16()
            val eEntry = r.u64()
            r.pos = 0x20
            val ePhoff = r.u64()
            val eShoff = r.u64()
            r.pos = 0x36
            val ePhentsize = r.u16()
            val ePhnum = r.u16()
            val eShentsize = r.u16()
            val eShnum = r.u16()
            val eShstrndx = r.u16()
            if (eType == 0) throw ElfParseException("e_type=ET_NONE, not an object file")
            Nine(eEntry, eMachine, ePhoff, eShoff, ePhentsize, ePhnum, eShentsize, eShnum, eShstrndx)
        } else {
            r.pos = 0x18
            val eMachine = r.u16()
            val eEntry = r.u32asLong()
            r.pos = 0x1c
            val ePhoff = r.u32asLong()
            val eShoff = r.u32asLong()
            r.pos = 0x2a
            val ePhentsize = r.u16()
            val ePhnum = r.u16()
            val eShentsize = r.u16()
            val eShnum = r.u16()
            val eShstrndx = r.u16()
            Nine(eEntry, eMachine, ePhoff, eShoff, ePhentsize, ePhnum, eShentsize, eShnum, eShstrndx)
        }

        if (shnum == 0 || shOff == 0L) throw ElfParseException("no section headers")
        if (shstrndx.toLong() >= shnum.toLong()) throw ElfParseException("invalid shstrndx=$shstrndx")

        val segments = parseProgramHeaders(r, phOff, phentsize, phnum, cls)

        val rawHeaders = parseSectionHeaders(r, shOff, shentsize, shnum, cls)
        val strtab = rawHeaders[shstrndx]
        if (strtab.fileOffset > Int.MAX_VALUE.toLong()) throw ElfParseException("shstrtab offset too large")
        val nameReader = ByteReader(bytes, endian, strtab.fileOffset.toInt(), strtab.size.toInt())
        val sections = rawHeaders.mapIndexed { idx, h ->
            val nm = runCatching { nameReader.cStringAt(h.nameOffset) }.getOrDefault("")
            val data = extractSectionBytes(bytes, h, idx)
            ElfSection(
                name = nm,
                type = h.type,
                flags = h.flags,
                address = h.address,
                fileOffset = h.fileOffset,
                size = h.size,
                link = h.link,
                info = h.info,
                addralign = h.addralign,
                entrySize = h.entrySize,
                bytes = data,
            )
        }

        val buildId = findBuildId(sections, endian)
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes)
        val hex = sha.toHex()
        val digests = sections
            .filter { it.size > 0 }
            .map { s ->
                val d = MessageDigest.getInstance("SHA-256").digest(s.bytes)
                val head = s.bytes.copyOfRange(0, minOf(16, s.bytes.size))
                val tail = s.bytes.copyOfRange(maxOf(0, s.bytes.size - 16), s.bytes.size)
                SectionDigest(s.name, s.size, d.toHex(), head.toHex(), tail.toHex())
            }

        return ElfFile(
            elfClass = cls,
            littleEndian = endian,
            entry = entry,
            machine = machine,
            sections = sections,
            segments = segments,
            buildId = buildId,
            fileSha256 = hex,
            fileSize = bytes.size.toLong(),
            sectionDigests = digests,
            rawBytes = bytes,
        )
    }

    private data class RawShdr(
        val nameOffset: Int, val type: Int, val flags: Long, val address: Long,
        val fileOffset: Long, val size: Long, val link: Int, val info: Int,
        val addralign: Long, val entrySize: Long,
    )

    private data class Nine<A, B, C, D, E, F, G, H, I>(
        val a: A, val b: B, val c: C, val d: D, val e: E, val f: F, val g: G, val h: H, val i: I,
    )

    private fun parseProgramHeaders(r: ByteReader, off: Long, entsize: Int, num: Int, cls: Int): List<LoadSegment> {
        if (off == 0L || num == 0) return emptyList()
        if (off > Int.MAX_VALUE.toLong() || off + entsize.toLong() * num > r.size.toLong()) {
            throw ElfParseException("program header table out of file")
        }
        val out = ArrayList<LoadSegment>(num)
        for (idx in 0 until num) {
            r.pos = (off + idx.toLong() * entsize).toInt()
            val seg = if (cls == 2) {
                val type = r.u32()
                val flags = r.u32()
                val foff = r.u64()
                val vaddr = r.u64()
                val paddr = r.u64()
                val filesz = r.u64()
                val memsz = r.u64()
                val align = r.u64()
                LoadSegment(type, flags, foff, vaddr, filesz, memsz, align)
            } else {
                val type = r.u32()
                val foff = r.u32asLong()
                val vaddr = r.u32asLong()
                val paddr = r.u32asLong()
                val filesz = r.u32asLong()
                val memsz = r.u32asLong()
                val flags = r.u32()
                val align = r.u32asLong()
                LoadSegment(type, flags, foff, vaddr, filesz, memsz, align)
            }
            if (seg.type == PT_LOAD) out.add(seg)
        }
        return out.sortedBy { it.vaddr }
    }

    private fun parseSectionHeaders(r: ByteReader, off: Long, entsize: Int, num: Int, cls: Int): List<RawShdr> {
        if (off > Int.MAX_VALUE.toLong() || off + entsize.toLong() * num > r.size.toLong()) {
            throw ElfParseException("section header table out of file")
        }
        val out = ArrayList<RawShdr>(num)
        for (idx in 0 until num) {
            r.pos = (off + idx.toLong() * entsize).toInt()
            if (cls == 2) {
                val name = r.u32(); val type = r.u32(); val flags = r.u64()
                val addr = r.u64(); val foff = r.u64(); val size = r.u64()
                val link = r.u32(); val info = r.u32()
                r.u64() // addralign
                val ent = r.u64()
                out.add(RawShdr(name, type, flags, addr, foff, size, link, info, 0, ent))
            } else {
                val name = r.u32(); val type = r.u32(); val flags = r.u32asLong()
                val addr = r.u32asLong(); val foff = r.u32asLong(); val size = r.u32asLong()
                val link = r.u32(); val info = r.u32()
                r.u32asLong()
                val ent = r.u32asLong()
                out.add(RawShdr(name, type, flags, addr, foff, size, link, info, 0, ent))
            }
        }
        return out
    }

    private fun extractSectionBytes(file: ByteArray, h: RawShdr, idx: Int): ByteArray {
        // SHT_NOBITS (type 8) 不占文件空间。
        if (h.type == 8) return ByteArray(0)
        if (h.size == 0L) return ByteArray(0)
        if (h.fileOffset < 0 || h.fileOffset + h.size > file.size.toLong() || h.size > 64L * 1024 * 1024 * 1024) {
            throw ElfParseException("section #$idx '${h.nameOffset}' bytes out of file: off=${h.fileOffset} size=${h.size}")
        }
        return file.copyOfRange(h.fileOffset.toInt(), (h.fileOffset + h.size).toInt())
    }

    private fun findBuildId(sections: List<ElfSection>, littleEndian: Boolean): String? {
        val note = sections.firstOrNull { it.name == ".note.gnu.build-id" } ?: return null
        if (note.bytes.size < 12) return null
        return try {
            val r = ByteReader(note.bytes, littleEndian)
            while (r.remaining() > 0) {
                val namesz = r.u32asLong()
                val descsz = r.u32asLong()
                val type = r.u32()
                val nameStart = r.pos
                r.pos = (nameStart + ((namesz + 3) and 3L.inv())).toInt()
                val descStart = r.pos
                if (type == NT_GNU_BUILD_ID) {
                    val desc = r.take(descsz.toInt())
                    return desc.toHex()
                }
                r.pos = (descStart + ((descsz + 3) and 3L.inv())).toInt()
            }
            null
        } catch (_: EndOfDataException) {
            null
        }
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
