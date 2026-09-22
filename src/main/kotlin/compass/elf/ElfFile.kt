package compass.elf

import java.security.MessageDigest

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
    val entsize: Long,
    val data: ByteArray,
    val sha256: String?
) {
    /** True for sections like .bss that occupy no file space. */
    val isNoBits: Boolean get() = type == SHT_NOBITS
}

data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val fileSize: Long,
    val memSize: Long,
    val align: Long
)

data class ElfHeader(
    val elfClass: Int,
    val endian: Int,
    val machine: Int,
    val entry: Long,
    val phoff: Long,
    val shoff: Long,
    val phentsize: Int,
    val phnum: Int,
    val shentsize: Int,
    val shnum: Int,
    val shstrndx: Int
) {
    val is64 get() = elfClass == 2
    val isLittle get() = endian == 1
}

const val SHT_NOBITS = 8
const val PT_LOAD = 1

/** Parsed ELF container: sections + segments + digests. No symbol resolution. */
class ElfFile(
    val path: String?,
    val bytes: ByteArray,
    val header: ElfHeader,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>
) {
    val fileSha256: String = sha256Hex(bytes)
    private val byName = sections.filter { it.name.isNotEmpty() }.associateBy { it.name }

    fun section(name: String): ElfSection? = byName[name]

    /** DWARF section lookup tolerant of split-DWARF section suffixes (.zdebug not supported). */
    fun dwarfSection(name: String): ElfSection? {
        byName[name]?.let { return it }
        if (name.startsWith(".debug_")) {
            byName["$name.dwo"]?.let { return it }
        }
        return null
    }

    /** All loadable PT_LOAD segments, used for load-bias / vaddr validation. */
    val loadSegments: List<ElfSegment> get() = segments.filter { it.type == PT_LOAD }

    /**
     * Load bias needed to map the file's virtual addresses to a runtime base:
     * bias = runtimeBase - lowestAlignedVaddrOfFirstLoadSegment.
     * Callers supply the observed module base; here we expose the file base.
     */
    fun preferredBase(): Long? =
        loadSegments.minWithOrNull(compareBy({ it.vaddr and -4096L }, { it.vaddr }))
            ?.let { it.vaddr and -4096L }

    fun containsVaddr(vaddr: Long): Boolean =
        loadSegments.any { vaddr >= it.vaddr && vaddr < it.vaddr + it.memSize }

    companion object {
        private val MAGIC = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())

        fun parse(bytes: ByteArray, path: String? = null): ElfFile {
            if (bytes.size < 16 || !bytes.copyOfRange(0, 4).contentEquals(MAGIC))
                throw ElfFormatException("not an ELF file: bad magic")
            val elfClass = bytes[4].toInt() and 0xff
            val endian = bytes[5].toInt() and 0xff
            if (elfClass != 1 && elfClass != 2) throw ElfFormatException("unknown ELF class $elfClass")
            if (endian != 1 && endian != 2) throw ElfFormatException("unknown ELF data encoding $endian")
            // ELF endianness is always little on targets we generate/expect; support big explicitly.
            if (endian == 2) throw ElfFormatException("big-endian ELF is not supported by this implementation")
            val r = ByteReader(bytes)
            val machine: Int
            val entry: Long
            val phoff: Long
            val shoff: Long
            val phentsize: Int
            val phnum: Int
            val shentsize: Int
            val shnum: Int
            val shstrndx: Int
            if (elfClass == 2) {
                r.seek(16)
                val type = r.u2()
                machine = r.u2()
                r.u4() // version
                entry = r.u8()
                phoff = r.u8()
                shoff = r.u8()
                r.u4() // flags
                r.u2() // ehsize
                phentsize = r.u2()
                phnum = r.u2()
                shentsize = r.u2()
                shnum = r.u2()
                shstrndx = r.u2()
                if (type == 0) throw ElfFormatException("ET_NONE object")
            } else {
                r.seek(16)
                val type = r.u2()
                machine = r.u2()
                r.u4()
                entry = r.u4().toLong() and 0xffffffffL
                phoff = r.u4().toLong() and 0xffffffffL
                shoff = r.u4().toLong() and 0xffffffffL
                r.u4()
                r.u2()
                phentsize = r.u2()
                phnum = r.u2()
                shentsize = r.u2()
                shnum = r.u2()
                shstrndx = r.u2()
                if (type == 0) throw ElfFormatException("ET_NONE object")
            }

            val segments = parseSegments(r, elfClass, phoff, phentsize, phnum)
            val sections = parseSections(bytes, r, elfClass, shoff, shentsize, shnum, shstrndx)
            return ElfFile(
                path, bytes,
                ElfHeader(elfClass, endian, machine, entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx),
                sections, segments
            )
        }

        private fun parseSegments(r: ByteReader, elfClass: Int, phoff: Long, entsize: Int, num: Int): List<ElfSegment> {
            val out = ArrayList<ElfSegment>(num)
            if (phoff == 0L || num == 0) return out
            for (i in 0 until num) {
                r.seek((phoff + i.toLong() * entsize).toInt())
                if (elfClass == 2) {
                    val type = r.u4()
                    val flags = r.u4()
                    val off = r.u8()
                    val vaddr = r.u8()
                    r.u8() // paddr
                    val filesz = r.u8()
                    val memsz = r.u8()
                    val align = r.u8()
                    out.add(ElfSegment(type, flags, off, vaddr, filesz, memsz, align))
                } else {
                    val type = r.u4()
                    val off = r.u4().toLong() and 0xffffffffL
                    val vaddr = r.u4().toLong() and 0xffffffffL
                    r.u4() // paddr
                    val filesz = r.u4().toLong() and 0xffffffffL
                    val memsz = r.u4().toLong() and 0xffffffffL
                    val flags = r.u4()
                    val align = r.u4().toLong() and 0xffffffffL
                    out.add(ElfSegment(type, flags, off, vaddr, filesz, memsz, align))
                }
            }
            return out
        }

        private fun parseSections(
            bytes: ByteArray, r: ByteReader, elfClass: Int,
            shoff: Long, entsize: Int, num: Int, shstrndx: Int
        ): List<ElfSection> {
            if (shoff == 0L || num == 0) return emptyList()
            // read raw headers
            data class Raw(val nameOff: Int, val type: Int, val flags: Long, val addr: Long,
                          val off: Long, val size: Long, val link: Int, val info: Int,
                          val align: Long, val entsize: Long)
            val raws = ArrayList<Raw>(num)
            for (i in 0 until num) {
                r.seek((shoff + i.toLong() * entsize).toInt())
                if (elfClass == 2) {
                    val nameOff = r.u4(); val type = r.u4(); val flags = r.u8()
                    val addr = r.u8(); val off = r.u8(); val size = r.u8()
                    val link = r.u4(); val info = r.u4(); val align = r.u8(); val es = r.u8()
                    raws.add(Raw(nameOff, type, flags, addr, off, size, link, info, align, es))
                } else {
                    val nameOff = r.u4(); val type = r.u4(); val flags = r.u4().toLong() and 0xffffffffL
                    val addr = r.u4().toLong() and 0xffffffffL
                    val off = r.u4().toLong() and 0xffffffffL
                    val size = r.u4().toLong() and 0xffffffffL
                    val link = r.u4(); val info = r.u4()
                    val align = r.u4().toLong() and 0xffffffffL
                    val es = r.u4().toLong() and 0xffffffffL
                    raws.add(Raw(nameOff, type, flags, addr, off, size, link, info, align, es))
                }
            }
            if (shstrndx >= raws.size) throw ElfFormatException("e_shstrndx $shstrndx out of range (${raws.size})")
            val strtab = raws[shstrndx]
            val strData = sliceBytes(bytes, strtab.off, strtab.size)

            fun sectionName(off: Int): String {
                if (off < 0 || off >= strData.size) return ""
                var end = off
                while (end < strData.size && strData[end].toInt() != 0) end++
                return String(strData, off, end - off, Charsets.UTF_8)
            }

            return raws.mapIndexed { idx, s ->
                val name = sectionName(s.nameOff)
                val (data, digest) = when {
                    s.type == SHT_NOBITS -> ByteArray(0) to null
                    s.off + s.size > bytes.size ->
                        throw ElfFormatException("section #$idx '$name' [${s.off},+${s.size}) exceeds file")
                    else -> {
                        val d = sliceBytes(bytes, s.off, s.size)
                        d to sha256Hex(d)
                    }
                }
                ElfSection(name, s.type, s.flags, s.addr, s.off, s.size, s.link, s.info, s.align, s.entsize, data, digest)
            }
        }

        private fun sliceBytes(bytes: ByteArray, off: Long, size: Long): ByteArray {
            val o = off.toInt()
            val n = size.toInt()
            return bytes.copyOfRange(o, o + n)
        }

        fun sha256Hex(data: ByteArray): String {
            val d = MessageDigest.getInstance("SHA-256").digest(data)
            val sb = StringBuilder(d.size * 2)
            for (b in d) sb.append(String.format("%02x", b))
            return sb.toString()
        }
    }
}

class ElfFormatException(message: String) : RuntimeException(message)
