package compass.elf

import compass.dwarf.DwarfException
import compass.dwarf.hexU
import java.security.MessageDigest

class ElfException(message: String) : Exception(message)

data class ElfSection(
    val index: Int,
    val name: String,
    val type: Long,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Long,
    val entsize: Long,
    val nameOffset: Long = 0L,
) {
    val alloc: Boolean get() = flags and 0x2L != 0L
    val isDebug: Boolean get() = name.startsWith(".debug")
    fun bytes(whole: ByteArray): ByteArray {
        if (type == 8L) return ByteArray(0) // SHT_NOBITS
        if (offset < 0 || size < 0 || offset + size > whole.size)
            throw ElfException("section $name 范围越界: off=${hexU(offset)} size=${hexU(size)} 文件=${whole.size}")
        return whole.copyOfRange(offset.toInt(), (offset + size).toInt())
    }
    fun sha256(whole: ByteArray): String = sha256Hex(bytes(whole))
}

fun sha256Hex(data: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

/** 只读 ELF（32/64 位、小/大端），提取 section 表与原始字节。 */
class ElfFile(val bytes: ByteArray) {
    val is64: Boolean
    val littleEndian: Boolean
    val elfType: Int
    val machine: Int
    val sections: List<ElfSection>

    init {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte()
            || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ElfException("不是 ELF 文件（魔数不匹配）")
        is64 = when (bytes[4].toInt()) {
            1 -> false; 2 -> true
            else -> throw ElfException("未知 ELFCLASS: ${bytes[4]}")
        }
        littleEndian = when (bytes[5].toInt()) {
            1 -> true; 2 -> false
            else -> throw ElfException("未知 ELFDATA: ${bytes[5]}")
        }
        elfType = u16At(16)
        machine = u16At(18)
        sections = parseSections()
    }

    private fun u16At(off: Int): Int {
        if (off + 2 > bytes.size) throw ElfException("ELF 头越界 @ $off")
        return if (littleEndian)
            (bytes[off].toInt() and 0xff) or ((bytes[off + 1].toInt() and 0xff) shl 8)
        else
            ((bytes[off].toInt() and 0xff) shl 8) or (bytes[off + 1].toInt() and 0xff)
    }

    private fun u32At(off: Int): Long {
        if (off + 4 > bytes.size) throw ElfException("ELF 头越界 @ $off")
        var v = 0L
        if (littleEndian) for (i in 0..3) v = v or ((bytes[off + i].toLong() and 0xff) shl (8 * i))
        else for (i in 0..3) v = (v shl 8) or (bytes[off + i].toLong() and 0xff)
        return v
    }

    private fun u64At(off: Int): Long {
        if (off + 8 > bytes.size) throw ElfException("ELF 头越界 @ $off")
        var v = 0L
        if (littleEndian) for (i in 0..7) v = v or ((bytes[off + i].toLong() and 0xff) shl (8 * i))
        else for (i in 0..7) v = (v shl 8) or (bytes[off + i].toLong() and 0xff)
        return v
    }

    private fun parseSections(): List<ElfSection> {
        val shoff: Long
        val shentsize: Int
        var shnum: Int
        var shstrndx: Int
        if (is64) {
            shoff = u64At(0x28); shentsize = u16At(0x3a); shnum = u16At(0x3c); shstrndx = u16At(0x3e)
        } else {
            shoff = u32At(0x20); shentsize = u16At(0x2e); shnum = u16At(0x30); shstrndx = u16At(0x32)
        }
        if (shoff == 0L) return emptyList()
        val minSize = if (is64) 64 else 40
        if (shentsize < minSize) throw ElfException("e_shentsize 异常: $shentsize")
        if (shoff + shentsize > bytes.size) throw ElfException("section 表越界: shoff=${hexU(shoff)}")

        fun field(i: Int, off: Int, wide: Boolean): Long {
            val base = shoff + i.toLong() * shentsize + off
            if (base < 0 || base + (if (wide) 8 else 4) > bytes.size)
                throw ElfException("section 头越界: #$i")
            return if (wide) u64At(base.toInt()) else u32At(base.toInt())
        }

        // 扩展编号：e_shnum==0 时真实数量在 section#0 的 sh_size；e_shstrndx==0xffff 时在 sh_link
        if (shnum == 0) shnum = field(0, if (is64) 0x20 else 0x14, is64).toInt()
        if (shstrndx == 0xffff) shstrndx = field(0, if (is64) 0x28 else 0x18, false).toInt()
        if (shnum < 0 || shnum > 1_000_000) throw ElfException("section 数量异常: $shnum")
        if (shoff + shnum.toLong() * shentsize > bytes.size)
            throw ElfException("section 表越界: shnum=$shnum shentsize=$shentsize")

        val raw = ArrayList<ElfSection>(shnum)
        for (i in 0 until shnum) {
            val (nameOff, type, flags, addr, off, size, link, entsize) = if (is64) {
                listOf(
                    field(i, 0x00, false), field(i, 0x04, false), field(i, 0x08, true),
                    field(i, 0x10, true), field(i, 0x18, true), field(i, 0x20, true),
                    field(i, 0x28, false), field(i, 0x38, true),
                )
            } else {
                listOf(
                    field(i, 0x00, false), field(i, 0x04, false), field(i, 0x08, false),
                    field(i, 0x0c, false), field(i, 0x10, false), field(i, 0x14, false),
                    field(i, 0x18, false), field(i, 0x24, false),
                )
            }
            raw.add(ElfSection(i, "", type, flags, addr, off, size, link, entsize, nameOff))
        }
        val names = if (shstrndx in raw.indices) raw[shstrndx] else null
        return raw.map { sec ->
            val nm = if (names != null && names.type != 8L) readStr(names, sec.nameOffset) else ""
            sec.copy(name = nm)
        }
    }

    private fun readStr(strtab: ElfSection, at: Long): String {
        if (at < 0 || at >= strtab.size) return ""
        val start = (strtab.offset + at).toInt()
        if (start >= bytes.size) return ""
        var end = start
        val limit = minOf(bytes.size, (strtab.offset + strtab.size).toInt())
        while (end < limit && bytes[end].toInt() != 0) end++
        return String(bytes, start, end - start, Charsets.UTF_8)
    }

    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    fun sectionBytes(name: String): ByteArray? = section(name)?.bytes(bytes)

    /** 首选链接基址：可加载 section 的最小虚拟地址（用于 load bias 计算）。 */
    val preferredBase: Long
        get() = sections.filter { it.alloc && it.addr != 0L }.minOfOrNull { it.addr } ?: 0L

    val debugSectionNames: List<String>
        get() = sections.filter { it.isDebug }.map { it.name }
}
