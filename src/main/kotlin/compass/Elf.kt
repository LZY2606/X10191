package compass

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

class ElfException(message: String) : Exception(message)

fun sha256Hex(data: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

data class ElfSection(
    val index: Int,
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val data: ByteArray,
) {
    val sha256: String get() = sha256Hex(data)
    val allocated: Boolean get() = addr != 0L
}

data class ElfFile(
    val is64: Boolean,
    val littleEndian: Boolean,
    val elfType: Int,
    val machine: Int,
    val sections: List<ElfSection>,
    val baseVaddr: Long,
    val imageSize: Long,
    val sha256: String,
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }
    val elfClass: String get() = if (is64) "ELF64" else "ELF32"
}

object ElfParser {
    private const val SHT_NOBITS = 8L
    private const val PT_LOAD = 1
    private const val SHN_UNDEF = 0
    private const val SHN_XINDEX = 0xffff

    fun parse(bytes: ByteArray): ElfFile {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte()
            || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ElfException("不是 ELF 文件（魔数不匹配）")
        val is64 = when (bytes[4].toInt()) {
            1 -> false; 2 -> true
            else -> throw ElfException("未知 ELF class: ${bytes[4]}")
        }
        val little = when (bytes[5].toInt()) {
            1 -> true; 2 -> false
            else -> throw ElfException("未知 ELF 字节序: ${bytes[5]}")
        }
        val buf = ByteBuffer.wrap(bytes).order(if (little) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
        fun u16(off: Int) = buf.getShort(off).toInt() and 0xffff
        fun u32(off: Int) = buf.getInt(off).toLong() and 0xffffffffL
        fun u64(off: Int) = buf.getLong(off)
        val elfType = u16(16)
        val machine = u16(18)
        val phoff: Long; val shoff: Long; val phentsize: Int; val phnumRaw: Int
        val shentsize: Int; val shnumRaw: Int; val shstrndxRaw: Int
        if (is64) {
            phoff = u64(0x20); shoff = u64(0x28)
            phentsize = u16(0x36); phnumRaw = u16(0x38)
            shentsize = u16(0x3a); shnumRaw = u16(0x3c); shstrndxRaw = u16(0x3e)
        } else {
            phoff = u32(0x1c); shoff = u32(0x20)
            phentsize = u16(0x2a); phnumRaw = u16(0x2c)
            shentsize = u16(0x2e); shnumRaw = u16(0x30); shstrndxRaw = u16(0x32)
        }
        // 程序头：计算 PT_LOAD 最小 vaddr 与映像大小
        var baseVaddr = Long.MAX_VALUE
        var imageEnd = 0L
        var phnum = phnumRaw
        if (phoff != 0L && phnum > 0) {
            if (phnum == 0xffff) phnum = 0xffff // PN_XNUM 情形罕见，按表头值解析即可
            var i = 0
            while (i < phnum) {
                val off = phoff + i.toLong() * phentsize
                if (off + phentsize > bytes.size) break
                val pType = if (is64) u32(off.toInt()) else u32(off.toInt())
                val vaddr: Long; val memsz: Long
                if (is64) { vaddr = u64(off.toInt() + 0x10); memsz = u64(off.toInt() + 0x28) }
                else { vaddr = u32(off.toInt() + 0x8); memsz = u32(off.toInt() + 0x14) }
                if (pType.toInt() == PT_LOAD) {
                    if (vaddr < baseVaddr) baseVaddr = vaddr
                    if (vaddr + memsz > imageEnd) imageEnd = vaddr + memsz
                }
                i++
            }
        }
        if (baseVaddr == Long.MAX_VALUE) baseVaddr = 0L

        if (shoff == 0L) throw ElfException("ELF 缺少 section header 表")
        // 读取第 0 个 section 以处理扩展编号
        fun shField(idx: Int, off64: Int, off32: Int, wide: Boolean): Long {
            val base = shoff + idx.toLong() * shentsize
            if (base + shentsize > bytes.size) throw ElfException("section header 越界")
            return if (wide) u64(base.toInt() + if (is64) off64 else off32)
            else if (is64) u32(base.toInt() + off64) else u32(base.toInt() + off32)
        }
        var shnum = shnumRaw
        var shstrndx = shstrndxRaw
        if (shnum == 0 && shoff != 0L) shnum = shField(0, 0x28, 0x20, wide = true).toInt()
        if (shstrndx == SHN_XINDEX) shstrndx = shField(0, 0x2c, 0x28, wide = false).toInt()
        if (shnum <= 0 || shnum > 100000) throw ElfException("section 数量异常: $shnum")

        data class RawSh(val nameOff: Long, val type: Long, val addr: Long, val off: Long, val size: Long)
        val raws = ArrayList<RawSh>(shnum)
        for (i in 0 until shnum) {
            val base = (shoff + i.toLong() * shentsize).toInt()
            if (base + shentsize > bytes.size) throw ElfException("section header $i 越界")
            if (is64) raws += RawSh(u32(base), u32(base + 4), u64(base + 0x10), u64(base + 0x18), u64(base + 0x20))
            else raws += RawSh(u32(base), u32(base + 4), u32(base + 0xc), u32(base + 0x10), u32(base + 0x14))
        }
        if (shstrndx == SHN_UNDEF || shstrndx >= shnum) throw ElfException("缺少 shstrtab")
        val strSh = raws[shstrndx]
        fun nameAt(no: Long): String {
            var p = (strSh.off + no).toInt()
            if (p < 0 || p >= bytes.size) return ""
            val sb = StringBuilder()
            var guard = 0
            while (p < bytes.size && bytes[p] != 0.toByte() && guard < 4096) {
                sb.append(bytes[p].toInt().toChar()); p++; guard++
            }
            return sb.toString()
        }
        val sections = raws.mapIndexed { i, sh ->
            val data = when {
                sh.type == SHT_NOBITS -> ByteArray(0)
                sh.size == 0L -> ByteArray(0)
                sh.off < 0 || sh.off + sh.size > bytes.size ->
                    throw ElfException("section #$i 数据越界 (off=${sh.off} size=${sh.size})")
                else -> bytes.copyOfRange(sh.off.toInt(), (sh.off + sh.size).toInt())
            }
            ElfSection(i, nameAt(sh.nameOff), sh.type, sh.addr, sh.off, sh.size, data)
        }
        return ElfFile(is64, little, elfType, machine, sections, baseVaddr, imageEnd, sha256Hex(bytes))
    }
}
