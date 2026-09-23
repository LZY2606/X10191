package compass.elf

import compass.util.BinReader
import compass.util.BoundsException
import compass.util.UnsupportedEncodingException
import java.util.zip.Inflater

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val align: Long,
    val entsize: Long,
    val bytes: ByteArray,
)

data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
)

data class ElfHeader(
    val elfClass: Int,       // 1 = 32, 2 = 64
    val le: Boolean,
    val type: Int,
    val machine: Int,
    val entry: Long,
    val phoff: Long,
    val shoff: Long,
    val phentsize: Int,
    val phnum: Int,
    val shentsize: Int,
    val shnum: Int,
    val shstrndx: Int,
)

data class ByteSummary(val sha256: String, val size: Long, val head: String, val tail: String)

class ElfFile(
    val raw: ByteArray,
    val header: ElfHeader,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val summary: ByteSummary,
) {
    val sectionByName: Map<String, ElfSection> = sections.associateBy { it.name }

    /** 可加载段中最小 vaddr（文件内字节）；ET_DYN 通常为 0。 */
    val baseAddress: Long by lazy {
        segments.filter { it.type == PT_LOAD && it.filesz > 0 }.minOfOrNull { it.vaddr } ?: 0L
    }

    val isRelocatable: Boolean get() = header.type == ET_DYN || header.type == ET_REL

    /** 文件偏移到链接时 vaddr 的映射，用于分段地址检查。 */
    fun vaddrAtFileOffset(off: Long): Long? {
        for (s in segments) {
            if (s.type == PT_LOAD && off in s.offset until s.offset + s.filesz) {
                return s.vaddr + (off - s.offset)
            }
        }
        return null
    }

    fun dwarfSections(): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        for (sec in sections) {
            val name = when {
                sec.name.startsWith(".debug_") -> sec.name
                sec.name.startsWith(".zdebug_") -> ".debug_" + sec.name.removePrefix(".zdebug_")
                else -> continue
            }
            if (out.containsKey(name)) continue
            out[name] = decompressIfNeeded(sec)
        }
        return out
    }

    private fun decompressIfNeeded(sec: ElfSection): ByteArray {
        if (sec.name.startsWith(".zdebug_")) {
            val b = sec.bytes
            if (b.size < 12 || !(b[0] == 'Z'.code.toByte() && b[1] == 'L'.code.toByte() && b[2] == 'I'.code.toByte() && b[3] == 'B'.code.toByte())) {
                throw UnsupportedEncodingException("bad .zdebug magic in ${sec.name}")
            }
            var size = 0L
            for (i in 4 until 12) size = (size shl 8) or (b[i].toLong() and 0xff)
            return inflate(b, 12, size.toIntChecked())
        }
        if (sec.flags and SHF_COMPRESSED != 0L && sec.bytes.isNotEmpty()) {
            val r = BinReader(sec.bytes, le = header.le)
            if (header.elfClass == 2) {
                val chType = r.u32().toInt(); r.u32()
                val chSize = r.u64()
                if (chType != ELFCOMPRESS_ZLIB) throw UnsupportedEncodingException("unknown ch_type $chType in ${sec.name}")
                return inflate(sec.bytes, 16, chSize.toIntChecked())
            } else {
                val chType = r.u32().toInt()
                val chSize = r.u32().toLong()
                if (chType != ELFCOMPRESS_ZLIB) throw UnsupportedEncodingException("unknown ch_type $chType in ${sec.name}")
                return inflate(sec.bytes, 8, chSize.toIntChecked())
            }
        }
        return sec.bytes
    }

    private fun inflate(b: ByteArray, skip: Int, expected: Int): ByteArray {
        val inf = Inflater()
        inf.setInput(b, skip, b.size - skip)
        val out = ByteArray(expected.coerceAtLeast(16))
        val n = inf.inflate(out)
        inf.end()
        if (n != expected) throw BoundsException("decompressed size mismatch: $n != $expected")
        return out
    }

    companion object {
        const val PT_LOAD = 1
        const val ET_REL = 1
        const val ET_EXEC = 2
        const val ET_DYN = 3
        const val SHF_COMPRESSED = 0x800L
        const val ELFCOMPRESS_ZLIB = 1

        fun parse(raw: ByteArray): ElfFile {
            if (raw.size < 64) throw BoundsException("file too small for ELF")
            if (!(raw[0] == 0x7f.toByte() && raw[1] == 'E'.code.toByte() && raw[2] == 'L'.code.toByte() && raw[3] == 'F'.code.toByte())) {
                throw UnsupportedEncodingException("not an ELF file (bad magic)")
            }
            val elfClass = raw[4].toInt()
            if (elfClass != 1 && elfClass != 2) throw UnsupportedEncodingException("unknown EI_CLASS=$elfClass")
            val dataEnc = raw[5].toInt()
            if (dataEnc != 1 && dataEnc != 2) throw UnsupportedEncodingException("unknown EI_DATA=$dataEnc")
            val le = dataEnc == 1
            val r = BinReader(raw, le = le)
            r.seek(16)
            val type = r.u16()
            val machine = r.u16()
            val header = if (elfClass == 2) {
                r.seek(32)
                val entry = r.u64()
                val phoff = r.u64()
                val shoff = r.u64()
                r.seek(52)
                val flags = r.u32().toInt()
                val ehsize = r.u16()
                val phentsize = r.u16(); val phnum = r.u16()
                val shentsize = r.u16(); val shnum = r.u16(); val shstrndx = r.u16()
                ElfHeader(elfClass, le, type, machine, entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx)
            } else {
                r.seek(24)
                val entry = r.u32()
                val phoff = r.u32()
                val shoff = r.u32()
                r.seek(36)
                val flags = r.u32().toInt()
                val ehsize = r.u16()
                val phentsize = r.u16(); val phnum = r.u16()
                val shentsize = r.u16(); val shnum = r.u16(); val shstrndx = r.u16()
                ElfHeader(elfClass, le, type, machine, entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx)
            }
            val sections = parseSections(raw, header)
            val segments = parseSegments(raw, header)
            val summary = ByteSummary(
                BinReader.sha256(raw),
                raw.size.toLong(),
                BinReader.hex(raw.copyOfRange(0, minOf(16, raw.size))),
                BinReader.hex(raw.copyOfRange(maxOf(0, raw.size - 16), raw.size)),
            )
            return ElfFile(raw, header, sections, segments, summary)
        }

        private fun parseSections(raw: ByteArray, h: ElfHeader): List<ElfSection> {
            if (h.shoff == 0L || h.shnum == 0) return emptyList()
            if (h.shnum > 100_000) throw BoundsException("too many sections: ${h.shnum}")
            val raws = ArrayList<Pair<Int, ElfSection>>(h.shnum)
            for (i in 0 until h.shnum) {
                val off = (h.shoff + i.toLong() * h.shentsize).toIntChecked()
                val r = BinReader(raw, off, raw.size, h.le)
                val nameIdx: Int; val stype: Int
                var flags = 0L; var addr = 0L; var soff = 0L; var ssize = 0L
                var link = 0; var info = 0; var align = 0L; var entsize = 0L
                if (h.elfClass == 2) {
                    nameIdx = r.u32().toInt(); stype = r.u32().toInt()
                    flags = r.u64(); addr = r.u64(); soff = r.u64(); ssize = r.u64()
                    link = r.u32().toInt(); info = r.u32().toInt()
                    align = r.u64(); entsize = r.u64()
                } else {
                    nameIdx = r.u32().toInt(); stype = r.u32().toInt()
                    flags = r.u32(); addr = r.u32(); soff = r.u32(); ssize = r.u32()
                    link = r.u32().toInt(); info = r.u32().toInt()
                    align = r.u32(); entsize = r.u32()
                }
                raws.add(nameIdx to ElfSection("", stype, flags, addr, soff, ssize, link, info, align, entsize, ByteArray(0)))
            }
            val names = run {
                if (h.shstrndx !in raws.indices) return@run ByteArray(0)
                val s = raws[h.shstrndx].second
                val off = s.offset.toIntChecked(); val len = s.size.toIntChecked()
                if (off < 0L || off + len.toLong() > raw.size) throw BoundsException("shstrtab out of file")
                raw.copyOfRange(off, off + len)
            }
            return raws.map { (nameIdx, s) ->
                val end = if (nameIdx in names.indices) {
                    var e = nameIdx
                    while (e < names.size && names[e].toInt() != 0) e++
                    e
                } else nameIdx
                val name = if (nameIdx in names.indices) String(names, nameIdx, end - nameIdx, Charsets.UTF_8) else ""
                val off = s.offset.toIntChecked(); val len = s.size.toIntChecked()
                val bytes = if (s.type == 8 || len == 0) ByteArray(0)
                else { if (off < 0 || off + len > raw.size) throw BoundsException("section $name bytes out of file"); raw.copyOfRange(off, off + len) }
                s.copy(name = name, bytes = bytes)
            }
        }

        private fun parseSegments(raw: ByteArray, h: ElfHeader): List<ElfSegment> {
            if (h.phoff == 0L || h.phnum == 0) return emptyList()
            if (h.phnum > 100_000) throw BoundsException("too many segments: ${h.phnum}")
            val out = ArrayList<ElfSegment>(h.phnum)
            for (i in 0 until h.phnum) {
                val off = (h.phoff + i.toLong() * h.phentsize).toIntChecked()
                val r = BinReader(raw, off, raw.size, h.le)
                if (h.elfClass == 2) {
                    val pType = r.u32().toInt(); val pFlags = r.u32().toInt()
                    val pOff = r.u64(); val vaddr = r.u64(); val paddr = r.u64()
                    val filesz = r.u64(); val memsz = r.u64(); val pAlign = r.u64()
                    out.add(ElfSegment(pType, pFlags, pOff, vaddr, filesz, memsz, pAlign))
                } else {
                    val pType = r.u32().toInt()
                    val pOff = r.u32(); val vaddr = r.u32(); val paddr = r.u32()
                    val filesz = r.u32(); val memsz = r.u32()
                    val pFlags = r.u32().toInt(); val pAlign = r.u32()
                    out.add(ElfSegment(pType, pFlags, pOff, vaddr, filesz, memsz, pAlign))
                }
            }
            return out
        }
    }
}

internal fun Long.toIntChecked(): Int {
    if (this < 0 || this > Int.MAX_VALUE.toLong()) throw BoundsException("offset/size out of range: $this")
    return toInt()
}
