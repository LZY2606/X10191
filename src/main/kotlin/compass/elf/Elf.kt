package compass.elf

import compass.dwarf.BinReader
import compass.dwarf.ParseException
import java.security.MessageDigest

data class ElfSection(
    val index: Int,
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
    fun containsAddr(a: Long): Boolean = size > 0 && a in addr until addr + size
    fun slice(bytes: ByteArray): ByteArray {
        val o = offset.toInt(); val s = size.toInt()
        if (o < 0 || s < 0 || o.toLong() != offset || s.toLong() != size || o + s > bytes.size)
            throw ParseException("section $name 文件范围非法")
        return bytes.copyOfRange(o, o + s)
    }
}

data class ElfSegment(
    val type: Int, val flags: Int, val offset: Long, val vaddr: Long,
    val paddr: Long, val filesz: Long, val memsz: Long, val align: Long,
)

data class ElfSymbol(val nameIndex: Int, val value: Long, val size: Long, val info: Int, val other: Int, val shndx: Int) {
    val type: Int get() = info and 0xf
}

data class ElfModel(
    val bytes: ByteArray,
    val elfClass: Int,       // 1 = 32-bit, 2 = 64-bit
    val endian: Int,        // 1 = LE, 2 = BE
    val machine: Int,
    val type: Int,          // e_type: 1=REL,2=EXEC,3=DYN
    val entry: Long,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val symbols: Map<Int, ElfSymbol>,
    val sectionSha: Map<String, String>,
    val fileSha: String,
    val warnings: MutableList<String> = mutableListOf(),
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    companion object {
        const val MACHINE_X86_64 = 62
        const val MACHINE_AARCH64 = 183
        const val SHT_RELA = 4
        const val SHT_REL = 9
        const val PT_LOAD = 1
        const val ET_REL = 1
        const val ET_EXEC = 2
        const val ET_DYN = 3
    }
}

class ElfParser(private val bytes: ByteArray) {
    private var elfClass = 2
    private var endian = 1
    private var machine = 0
    private var eType = 0
    private var entry = 0L
    private val md = MessageDigest.getInstance("SHA-256")

    fun parse(): ElfModel {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ParseException("不是 ELF 文件（魔数不符）")
        elfClass = bytes[4].toInt()
        endian = bytes[5].toInt()
        if (elfClass !in 1..2) throw ParseException("非法 EI_CLASS=$elfClass")
        if (endian !in 1..2) throw ParseException("非法 EI_DATA=$endian")
        val r = BinReader(bytes)
        val is64 = elfClass == 2
        // ELF header
        r.seek(16)
        eType = r.u16e()
        machine = r.u16e()
        r.u32e() // version
        entry = if (is64) r.u64e() else r.u32e()
        val phoff = if (is64) r.u64e() else r.u32e()
        val shoff = if (is64) r.u64e() else r.u32e()
        r.u32e() // flags
        r.u16e(); r.u16e() // ehsize
        val phentsize = r.u16e()
        val phnum = r.u16e()
        val shentsize = r.u16e()
        var shnum = r.u16e()
        var shstrndx = r.u16e()

        val sections = parseSections(shoff, shentsize, shnum, shstrndx, is64)
        val segments = parseSegments(phoff, phentsize, phnum, is64)
        val symbols = parseSymbols(sections)
        val shaMap = linkedMapOf<String, String>()
        for (s in sections) {
            if (s.name.isNotEmpty() && s.size > 0) shaMap[s.name] = shaHex(s.slice(bytes))
        }
        return ElfModel(bytes, elfClass, endian, machine, eType, entry, sections, segments, symbols, shaMap, shaHex(bytes))
    }

    private fun parseSections(shoff: Long, shentsize: Int, shnumIn: Int, shstrndxIn: Int, is64: Boolean): List<ElfSection> {
        if (shoff == 0L) return emptyList()
        val r = BinReader(bytes)
        // 扩展编号：shnum==0 / shstrndx==SHN_XINDEX 时从 section 0 取真实值
        var shnum = shnumIn
        var shstrndx = shstrndxIn
        if (shnum == 0 || shstrndx == 0xffff) {
            r.seek((shoff + if (is64) 32 else 16).toInt())
            shnum = r.u32e().toInt()
            if (shstrndx == 0xffff) {
                r.seek((shoff + if (is64) 40 else 20).toInt())
                shstrndx = r.u32e().toInt()
            }
        }
        val raw = ArrayList<ElfSection>(shnum)
        val nameOffs = IntArray(shnum)
        for (i in 0 until shnum) {
            val base = (shoff + i.toLong() * shentsize).toInt()
            r.seek(base)
            val nameOff = r.u32e(); nameOffs[i] = nameOff
            val type = r.u32e()
            val flags: Long; val addr: Long; val offset: Long; val size: Long
            val link: Int; val info: Int; val addralign: Long; val entsize: Long
            if (is64) {
                flags = r.u64e(); addr = r.u64e(); offset = r.u64e(); size = r.u64e()
                link = r.u32e(); info = r.u32e(); addralign = r.u64e(); entsize = r.u64e()
            } else {
                flags = r.u32e(); addr = r.u32e(); offset = r.u32e(); size = r.u32e()
                link = r.u32e(); info = r.u32e(); addralign = r.u32e(); entsize = r.u32e()
            }
            raw.add(ElfSection(i, "", type, flags, addr, offset, size, link, info, addralign, entsize))
        }
        val nameSec = if (shstrndx in raw.indices) raw[shstrndx] else null
        fun nameAt(off: Int): String {
            if (nameSec == null || off < 0) return ""
            val start = (nameSec.offset + off).toInt()
            if (start < 0 || start >= bytes.size) return ""
            var end = start
            while (end < bytes.size && bytes[end].toInt() != 0) end++
            return String(bytes, start, end - start, Charsets.UTF_8)
        }
        return raw.mapIndexed { i, sec -> if (i == 0) sec else sec.copy(name = nameAt(nameOffs[i])) }
    }

    private fun parseSegments(phoff: Long, phentsize: Int, phnum: Int, is64: Boolean): List<ElfSegment> {
        if (phoff == 0L) return emptyList()
        val r = BinReader(bytes)
        val out = ArrayList<ElfSegment>(phnum)
        for (i in 0 until phnum) {
            r.seek((phoff + i.toLong() * phentsize).toInt())
            if (is64) {
                val type = r.u32e(); val flags = r.u32e()
                val off = r.u64e(); val va = r.u64e(); val pa = r.u64e()
                val fsz = r.u64e(); val msz = r.u64e(); val align = r.u64e()
                out.add(ElfSegment(type, flags, off, va, pa, fsz, msz, align))
            } else {
                val type = r.u32e()
                val off = r.u32e(); val va = r.u32e(); val pa = r.u32e()
                val fsz = r.u32e(); val msz = r.u32e(); val flags = r.u32e(); val align = r.u32e()
                out.add(ElfSegment(type, flags, off, va, pa, fsz, msz, align))
            }
        }
        return out
    }

    private fun parseSymbols(sections: List<ElfSection>): Map<Int, ElfSymbol> {
        val out = linkedMapOf<Int, ElfSymbol>()
        for (s in sections) {
            if (s.type != 2 /*SHT_SYMTAB*/ && s.type != 11 /*SHT_DYNSYM*/) continue
            val r = BinReader(bytes); r.seek(s.offset.toInt())
            val is64 = elfClass == 2
            val n = if (s.entsize > 0) (s.size / s.entsize).toInt() else 0
            for (i in 0 until n) {
                val base = s.offset.toInt() + i * s.entsize.toInt()
                r.seek(base)
                if (is64) {
                    val name = r.u32e(); val info = r.u8e(); val other = r.u8e()
                    val shndx = r.u16e(); val value = r.u64e(); val size = r.u64e()
                    out[s.index * 1_000_000 + i] = ElfSymbol(name, value, size, info, other, shndx)
                } else {
                    val name = r.u32e(); val value = r.u32e(); val size = r.u32e()
                    val info = r.u8e(); val other = r.u8e(); val shndx = r.u16e()
                    out[s.index * 1_000_000 + i] = ElfSymbol(name, value, size, info, other, shndx)
                }
            }
        }
        return out
    }

    private fun shaHex(b: ByteArray): String = md.digest(b).joinToString("") { "%02x".format(it) }

    // 大小端读取辅助
    private fun BinReader.u16e(): Int = if (endian == 1) u16() else ((u8() shl 8) or u8())
    private fun BinReader.u32e(): Long = if (endian == 1) u32() else
        ((u8().toLong() shl 24) or (u8().toLong() shl 16) or (u8().toLong() shl 8) or u8().toLong())
    private fun BinReader.u64e(): Long = if (endian == 1) u64() else {
        var v = 0L; for (i in 0 until 8) v = (v shl 8) or u8().toLong(); v
    }
    private fun BinReader.u8e(): Int = u8()
}

/**
 * 默认 load bias 推断：
 * - ET_EXEC/ET_REL：0（绝对地址 / 目标文件按 0 加载）
 * - ET_DYN（PIE/共享库）：加载基址 - 最低 PT_LOAD 段 vaddr（通常最低段为 0，故等于加载基址）
 */
fun defaultLoadBias(elf: ElfModel, loadBase: Long = 0L): Long = when (elf.type) {
    ElfModel.ET_REL -> 0L
    ElfModel.ET_EXEC -> 0L
    else -> {
        val firstLoad = elf.segments.filter { it.type == ElfModel.PT_LOAD && it.memsz > 0 }.minByOrNull { it.vaddr }
        loadBase - (firstLoad?.vaddr ?: 0L)
    }
}
