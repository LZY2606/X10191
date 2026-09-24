package luopan.elf

import luopan.dwarf.ByteReader
import luopan.dwarf.DwarfBoundsException
import luopan.dwarf.DwarfFormatException
import luopan.model.AddressRange
import luopan.model.ElfInfo
import luopan.model.ParsedElf
import luopan.model.ProgramHeader
import luopan.model.SectionBlob
import luopan.model.SectionSummary
import java.security.MessageDigest

object ElfParser {

    private val MACHINE_NAMES = mapOf(
        0x03 to "EM_386",
        0x3e to "EM_X86_64",
        0xb7 to "EM_AARCH64",
        0x28 to "EM_ARM",
        0xf3 to "EM_RISCV",
        0x14 to "EM_PPC",
        0x15 to "EM_PPC64",
        0x08 to "EM_MIPS",
        0x101 to "EM_LOONGARCH"
    )
    private val TYPE_NAMES = mapOf(
        0 to "ET_NONE", 1 to "ET_REL", 2 to "ET_EXEC", 3 to "ET_DYN", 4 to "ET_CORE"
    )

    fun parse(bytes: ByteArray): ParsedElf {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw DwarfFormatException("not an ELF file (bad magic)")
        val elfClass = bytes[4].toInt() and 0xff
        if (elfClass != 1 && elfClass != 2) throw DwarfFormatException("bad EI_CLASS=$elfClass")
        val endianByte = bytes[5].toInt() and 0xff
        if (endianByte != 1 && endianByte != 2) throw DwarfFormatException("bad EI_DATA=$endianByte")
        val le = endianByte == 1
        val r = ByteReader.of(bytes, le)
        r.seek(16)
        val type = r.u16()
        val machine = r.u16()
        val version = r.u32()
        if (version != 1L) throw DwarfFormatException("bad e_version=$version")
        val entry: Long
        val phoff: Long
        val shoff: Long
        val ehsize: Int
        val phentsize: Int
        val phnum: Int
        val shentsize: Int
        val shnum: Int
        val shstrndx: Int
        if (elfClass == 2) {
            entry = r.u64()
            phoff = r.u64()
            shoff = r.u64()
            r.u32(); r.u32() // flags, ehsize
            ehsize = 0
            phentsize = r.u16().toInt(); val phn = r.u16().toInt()
            shentsize = r.u16().toInt(); val shn = r.u16().toInt()
            shstrndx = r.u16().toInt()
            phnum = phn; shnum = shn
        } else {
            entry = r.u32()
            phoff = r.u32()
            shoff = r.u32()
            r.u32() // flags
            val ehs = r.u16().toInt()
            phentsize = r.u16().toInt(); val phn = r.u16().toInt()
            shentsize = r.u16().toInt(); val shn = r.u16().toInt()
            shstrndx = r.u16().toInt()
            phnum = phn; shnum = shn; ehsize = ehs
        }

        val elfInfo = ElfInfo(
            elfClass = elfClass,
            endian = if (le) "LSB" else "MSB",
            machine = machine,
            machineName = MACHINE_NAMES[machine] ?: "EM_0x${machine.toString(16)}",
            type = type,
            typeName = TYPE_NAMES[type] ?: "ET_$type",
            entry = entry,
            littleEndian = le
        )

        val phdrs = parseProgramHeaders(bytes, le, elfClass, phoff, phentsize, phnum)
        val sections = parseSections(bytes, le, elfClass, shoff, shentsize, shnum, shstrndx)
        val summaries = sections.map { summarize(it) }
        return ParsedElf(elfInfo, sections, summaries, phdrs)
    }

    private fun parseProgramHeaders(
        bytes: ByteArray, le: Boolean, elfClass: Int,
        phoff: Long, phentsize: Int, phnum: Int
    ): List<ProgramHeader> {
        if (phoff == 0L || phnum == 0) return emptyList()
        if (phoff > bytes.size || phoff + phentsize.toLong() * phnum > bytes.size) {
            throw DwarfBoundsException("program header table out of bounds")
        }
        val out = ArrayList<ProgramHeader>(phnum)
        for (i in 0 until phnum) {
            val r = ByteReader.of(bytes, le).seek((phoff + i.toLong() * phentsize).toInt())
            val ptype = r.u32().toInt()
            val poff: Long; val pvaddr: Long; val ppaddr: Long; val pfilesz: Long; val pmemsz: Long
            if (elfClass == 2) {
                val pflags = r.u32()
                poff = r.u64(); pvaddr = r.u64(); ppaddr = r.u64()
                pfilesz = r.u64(); pmemsz = r.u64()
                r.u64(); r.u64() // align
                out += ProgramHeader(ptype, poff, pvaddr, ppaddr, pfilesz, pmemsz, pflags, 0)
            } else {
                poff = r.u32(); pvaddr = r.u32(); ppaddr = r.u32()
                pfilesz = r.u32(); pmemsz = r.u32()
                val pflags = r.u32()
                r.u32()
                out += ProgramHeader(ptype, poff, pvaddr, ppaddr, pfilesz, pmemsz, pflags, 0)
            }
        }
        return out
    }

    /** 读取 section 表（不假设表项大小固定）。 */
    private fun parseSections(
        bytes: ByteArray, le: Boolean, elfClass: Int,
        shoff: Long, shentsize: Int, shnum: Int, shstrndx: Int
    ): List<SectionBlob> {
        if (shoff == 0L || shnum == 0) return emptyList()
        if (shoff > bytes.size || shoff + shentsize.toLong() * shnum > bytes.size) {
            throw DwarfBoundsException("section header table out of bounds")
        }
        data class Raw(val nameOff: Int, val type: Long, val flags: Long, val addr: Long,
                       val offset: Long, val size: Long, val link: Int)
        val raws = ArrayList<Raw>(shnum)
        for (i in 0 until shnum) {
            val r = ByteReader.of(bytes, le).seek((shoff + i.toLong() * shentsize).toInt())
            val nameOff = r.u32().toInt()
            if (elfClass == 2) {
                val type = r.u32(); val flags = r.u64(); val addr = r.u64()
                val offset = r.u64(); val size = r.u64()
                r.u32(); val link = r.u32(); r.u32(); r.u32(); r.u64(); r.u64()
                raws += Raw(nameOff, type, flags, addr, offset, size, link)
            } else {
                val type = r.u32(); val flags = r.u32(); val addr = r.u32()
                val offset = r.u32(); val size = r.u32()
                val link = r.u32().toInt(); r.u32(); r.u32(); r.u32(); r.u32(); r.u32()
                raws += Raw(nameOff, type, flags, addr, offset, size, link)
            }
        }
        if (shstrndx >= raws.size) throw DwarfFormatException("bad e_shstrndx=$shstrndx")
        val str = raws[shstrndx]
        if (str.offset + str.size > bytes.size) throw DwarfBoundsException(".shstrtab out of bounds")
        fun nameAt(off: Int): String {
            val base = str.offset.toInt() + off
            if (base < str.offset || base >= bytes.size) throw DwarfBoundsException("sh_name out of bounds")
            var end = base
            while (end < bytes.size && bytes[end].toInt() != 0) end++
            return String(bytes, base, end - base, Charsets.UTF_8)
        }
        return raws.mapIndexed { idx, raw ->
            val name = if (idx == 0) "" else nameAt(raw.nameOff)
            // SHT_NOBITS (8) 不占文件
            val data = when {
                raw.type == 8L -> ByteArray(0)
                raw.size == 0L -> ByteArray(0)
                raw.offset + raw.size > bytes.size ->
                    throw DwarfBoundsException("section $name bytes out of bounds")
                else -> bytes.copyOfRange(raw.offset.toInt(), (raw.offset + raw.size).toInt())
            }
            SectionBlob(name, data, raw.addr, raw.offset)
        }
    }

    private fun summarize(s: SectionBlob): SectionSummary {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(s.data)
        val sha = digest.joinToString("") { "%02x".format(it) }
        val head = s.data.take(16).joinToString(" ") { "%02x".format(it) }
        // 简单香农熵，帮助判断是否压缩/损坏
        val counts = IntArray(256)
        for (b in s.data) counts[b.toInt() and 0xff]++
        var entropy = 0.0
        if (s.data.isNotEmpty()) {
            for (c in counts) if (c > 0) {
                val p = c.toDouble() / s.data.size
                entropy -= p * (Math.log(p) / Math.log(2.0))
            }
        }
        return SectionSummary(s.name, s.fileOffset, s.data.size.toLong(), s.address, sha, entropy, head)
    }

    /** 把文件偏移（ET_REL 常见）转成相对虚拟地址：用 section sh_addr。 */
    fun fileOffsetToVaddr(parsed: ParsedElf, fileOffset: Long): Long? {
        val s = parsed.sections.firstOrNull {
            it.fileOffset <= fileOffset && fileOffset < it.fileOffset + it.data.size
        } ?: return null
        return s.address + (fileOffset - s.fileOffset)
    }

    /** 所有 SHF_ALLOC section 的覆盖区间（用于判定运行时地址落在哪个段）。 */
    fun allocRanges(parsed: ParsedElf): List<AddressRange> =
        parsed.sections.filter { it.address != 0L && it.data.isNotEmpty() }
            .map { AddressRange(it.address, it.address + it.data.size) }
}
