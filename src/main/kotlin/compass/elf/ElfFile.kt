package compass.elf

import compass.dwarf.DwarfException
import java.security.MessageDigest

class ElfSection(
    val name: String,
    val type: Long,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Long,
    val info: Long,
    val addralign: Long,
    val entsize: Long,
) {
    fun sha256(fileBytes: ByteArray): String {
        if (type == SHT_NOBITS || size == 0L) return sha256Of(ByteArray(0))
        val off = offset.toInt()
        val len = size.toInt()
        if (off < 0 || off + len > fileBytes.size) throw DwarfException("section $name 越界")
        return sha256Of(fileBytes.copyOfRange(off, off + len))
    }

    fun bytes(fileBytes: ByteArray): ByteArray {
        if (type == SHT_NOBITS || size == 0L) return ByteArray(0)
        val off = offset.toInt()
        val len = size.toInt()
        if (off < 0 || off + len > fileBytes.size) throw DwarfException("section $name 越界: offset=$offset size=$size")
        return fileBytes.copyOfRange(off, off + len)
    }

    companion object {
        const val SHT_NOBITS = 8L
        fun sha256Of(b: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    }
}

class ElfFile(
    val bytes: ByteArray,
    val is64: Boolean,
    val littleEndian: Boolean,
    val machine: Int,
    val sections: List<ElfSection>,
) {
    val sha256: String = ElfSection.sha256Of(bytes)

    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    companion object {
        fun parse(bytes: ByteArray): ElfFile {
            if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte()
                || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
            ) throw DwarfException("不是 ELF 文件")
            val elfClass = bytes[4].toInt()
            val is64 = when (elfClass) { 1 -> false; 2 -> true; else -> throw DwarfException("未知 ELF class $elfClass") }
            val little = when (bytes[5].toInt()) { 1 -> true; 2 -> false; else -> throw DwarfException("未知 ELF 字节序") }
            val r = compass.dwarf.Reader(bytes, little)

            fun u16(off: Int) = r.u16At(off)
            fun u32(off: Int) = r.u32At(off)
            fun u64(off: Int) = r.u64At(off)

            val machine = u16(18)
            val shoff: Long
            var shnum: Long
            var shstrndx: Long
            val shentsize: Int
            if (is64) {
                shoff = u64(0x28)
                shentsize = u16(0x3A)
                shnum = u16(0x3C).toLong()
                shstrndx = u16(0x3E).toLong()
            } else {
                shoff = u32(0x20).toLong()
                shentsize = u16(0x2E)
                shnum = u16(0x30).toLong()
                shstrndx = u16(0x32).toLong()
            }
            if (shoff == 0L) return ElfFile(bytes, is64, little, machine, emptyList())
            if (shentsize <= 0) throw DwarfException("section header entry size 非法")

            fun shAt(i: Long): LongArray {
                val base = shoff + i * shentsize
                if (base < 0 || base + shentsize > bytes.size) throw DwarfException("section header 越界: index=$i")
                return if (is64) longArrayOf(
                    u32(base.toInt()).toLong(), u32(base.toInt() + 4).toLong(),
                    u64(base.toInt() + 8), u64(base.toInt() + 16), u64(base.toInt() + 24),
                    u64(base.toInt() + 32), u32(base.toInt() + 40).toLong(), u32(base.toInt() + 44).toLong(),
                    u64(base.toInt() + 48), u64(base.toInt() + 56),
                ) else longArrayOf(
                    u32(base.toInt()).toLong(), u32(base.toInt() + 4).toLong(), u32(base.toInt() + 8).toLong(),
                    u32(base.toInt() + 12).toLong(), u32(base.toInt() + 16).toLong(), u32(base.toInt() + 20).toLong(),
                    u32(base.toInt() + 24).toLong(), u32(base.toInt() + 28).toLong(),
                    u32(base.toInt() + 32).toLong(), u32(base.toInt() + 34).toLong(),
                )
            }

            // 扩展编号: shnum==0 时真实数量在 section[0].sh_size
            if (shnum == 0L) {
                val s0 = shAt(0)
                shnum = s0[5]
                if (shstrndx == 0xffffL) shstrndx = s0[7]
            }
            if (shnum <= 0 || shnum > 100000) throw DwarfException("section 数量非法: $shnum")

            val raw = (0 until shnum).map { shAt(it) }
            val strSec = raw.getOrNull(shstrndx.toInt()) ?: throw DwarfException("shstrndx 越界")
            val strOff = strSec[4]
            val strSize = strSec[5]
            if (strOff + strSize > bytes.size) throw DwarfException("shstrtab 越界")

            fun strAt(nameOff: Long): String {
                var p = (strOff + nameOff).toInt()
                val end = (strOff + strSize).toInt()
                if (p >= end) return ""
                val sb = StringBuilder()
                while (p < end && bytes[p] != 0.toByte()) { sb.append(bytes[p].toInt().toChar()); p++ }
                return sb.toString()
            }

            val sections = raw.map { s ->
                ElfSection(
                    name = strAt(s[0]), type = s[1], flags = s[2], addr = s[3], offset = s[4],
                    size = s[5], link = s[6], info = s[7], addralign = s[8], entsize = s[9],
                )
            }
            return ElfFile(bytes, is64, little, machine, sections)
        }
    }
}
