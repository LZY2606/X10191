package compass

data class ElfSection(
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val data: ByteArray
)

data class ElfFile(
    val is64: Boolean,
    val littleEndian: Boolean,
    val machine: Int,
    val sections: List<ElfSection>
) {
    fun sectionMap(): Map<String, ByteArray> =
        sections.filter { it.name.isNotEmpty() }.associate { it.name to it.data }
}

object Elf {
    const val MAX_SECTIONS = 4096

    fun isElf(bytes: ByteArray): Boolean =
        bytes.size >= 4 && bytes[0] == 0x7f.toByte() && bytes[1] == 'E'.code.toByte() &&
            bytes[2] == 'L'.code.toByte() && bytes[3] == 'F'.code.toByte()

    fun parse(bytes: ByteArray): ElfFile {
        if (!isElf(bytes)) throw DwarfException("不是 ELF 文件（缺少 magic）")
        if (bytes.size < 16) throw DwarfException("ELF 头不完整")
        val cls = bytes[4].toInt()
        val dataEnc = bytes[5].toInt()
        val is64 = when (cls) {
            1 -> false
            2 -> true
            else -> throw DwarfException("未知 ELF class $cls")
        }
        val little = when (dataEnc) {
            1 -> true
            2 -> false
            else -> throw DwarfException("未知 ELF 字节序 $dataEnc")
        }
        val c = Cursor(bytes, 0, bytes.size, little)
        c.pos = 0x12
        val machine = c.u16()
        c.pos = if (is64) 0x28 else 0x20
        val shoff = if (is64) c.u64() else c.u32()
        c.pos = if (is64) 0x3A else 0x2E
        val shentsize = c.u16()
        val shnum = c.u16()
        val shstrndx = c.u16()
        if (shoff == 0L || shnum == 0) return ElfFile(is64, little, machine, emptyList())
        if (shnum > MAX_SECTIONS) throw DwarfException("section 数量超限: $shnum")
        if (shoff + shentsize.toLong() * shnum > bytes.size) {
            throw DwarfException("section header 表越界 shoff=$shoff num=$shnum")
        }
        data class RawSh(val nameOff: Long, val type: Long, val addr: Long, val off: Long, val size: Long)
        val raws = ArrayList<RawSh>()
        for (i in 0 until shnum) {
            c.pos = (shoff + i.toLong() * shentsize).toInt()
            val nameOff = c.u32()
            val type = c.u32()
            if (is64) {
                c.u64() // flags
                val addr = c.u64(); val off = c.u64(); val size = c.u64()
                raws.add(RawSh(nameOff, type, addr, off, size))
            } else {
                c.u32()
                val addr = c.u32(); val off = c.u32(); val size = c.u32()
                raws.add(RawSh(nameOff, type, addr, off, size))
            }
        }
        if (shstrndx >= raws.size) throw DwarfException("shstrndx 越界")
        val strSh = raws[shstrndx]
        if (strSh.off + strSh.size > bytes.size) throw DwarfException("shstrtab 越界")
        val strTab = Cursor(bytes, strSh.off.toInt(), (strSh.off + strSh.size).toInt(), little)
        val sections = ArrayList<ElfSection>()
        for (r in raws) {
            val name = try {
                strTab.pos = r.nameOff.toInt()
                strTab.cstr()
            } catch (e: DwarfException) { "" }
            val data = if (r.type == 8L /* SHT_NOBITS */ || r.size == 0L) {
                ByteArray(0)
            } else {
                if (r.off < 0 || r.size < 0 || r.off + r.size > bytes.size) {
                    throw DwarfException("section '$name' 数据越界 off=${r.off} size=${r.size}")
                }
                bytes.copyOfRange(r.off.toInt(), (r.off + r.size).toInt())
            }
            sections.add(ElfSection(name, r.type, r.addr, r.off, r.size, data))
        }
        return ElfFile(is64, little, machine, sections)
    }
}
