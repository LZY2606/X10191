package compass.elf

import compass.dwarf.DwarfBoundsException
import java.security.MessageDigest

class ElfException(message: String) : RuntimeException(message)

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
    val entsize: Long
) {
    fun containsAddress(vaddr: Long): Boolean = vaddr >= addr && vaddr < addr + size
}

data class ProgramHeader(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long
) {
    /** Translate a runtime-relative vaddr into a file offset using this LOAD segment. */
    fun fileOffsetOf(vaddr: Long): Long? {
        if (vaddr < vaddr || vaddr >= vaddr + filesz) return null
        return vaddr - vaddr + offset
    }
}

data class ElfFile(
    val path: String?,
    val raw: ByteArray,
    val elfClass: Int,       // 1 = 32-bit, 2 = 64-bit
    val littleEndian: Boolean,
    val machine: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val segments: List<ProgramHeader>,
    val sectionNames: List<String>
) {
    val is64: Boolean get() = elfClass == 2
    val addressSize: Int get() = if (is64) 8 else 4

    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    fun sectionBytes(name: String): ByteArray? =
        section(name)?.let { sec ->
            if (sec.offset < 0 || sec.offset + sec.size > raw.size)
                throw ElfException("section $name 的文件范围越界")
            raw.copyOfRange(sec.offset.toInt(), (sec.offset + sec.size).toInt())
        }

    fun buildId(): String? {
        val note = section(".note.gnu.build-id") ?: section(".notes") ?: return null
        return parseBuildId(note)
    }

    private fun parseBuildId(sec: ElfSection): String? {
        val base = sec.offset.toInt()
        var p = base
        val end = base + sec.size.toInt()
        try {
            while (p + 12 <= end) {
                val namesz = readInt(p, 4); p += 4
                val descsz = readInt(p, 4); p += 4
                val type = readInt(p, 4); p += 4
                val nameStart = p
                p += (namesz + 3) and 3.inv()
                if (type == 3 && descsz in 4..64 && p + descsz <= end) {
                    val desc = raw.copyOfRange(p, p + descsz)
                    return desc.joinToString("") { "%02x".format(it) }
                }
                p = nameStart + ((namesz + 3) and 3.inv()) + ((descsz + 3) and 3.inv())
            }
        } catch (_: Exception) { return null }
        return null
    }

    private fun readInt(off: Int, n: Int): Int {
        var v = 0
        for (i in 0 until n) {
            val b = raw[off + i].toInt() and 0xff
            v = if (littleEndian) v or (b shl (8 * i)) else (v shl 8) or b
        }
        return v
    }

    /** File offset for a virtual address via PT_LOAD segments (first match wins). */
    fun vaddrToOffset(vaddr: Long): Long? {
        for (seg in segments) {
            if (seg.type == PT_LOAD) seg.fileOffsetOf(vaddr)?.let { return it }
        }
        // Fall back to section headers.
        return sectionAt(vaddr)?.let { vaddr - it.addr + it.offset }
    }

    fun sectionAt(vaddr: Long): ElfSection? = sections.firstOrNull { it.size > 0 && it.containsAddress(vaddr) }

    fun sha256(): String = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it) }

    companion object {
        const val PT_LOAD = 1
        const val PT_NOTE = 4
        const val SHT_SYMTAB = 2
        const val SHT_STRTAB = 3
    }
}

object ElfParser {
    fun parse(bytes: ByteArray, path: String? = null): ElfFile {
        if (bytes.size < 16 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte()
            || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte())
            throw ElfException("不是 ELF 文件（魔数不匹配）")
        val elfClass = bytes[4].toInt()
        if (elfClass != 1 && elfClass != 2) throw ElfException("未知 ELF 类别 $elfClass")
        val dataEnc = bytes[5].toInt()
        if (dataEnc != 1 && dataEnc != 2) throw ElfException("未知 ELF 数据编码 $dataEnc")
        val le = dataEnc == 1

        fun u16(o: Int): Int = if (le) (bytes[o].toInt() and 0xff) or ((bytes[o + 1].toInt() and 0xff) shl 8)
        else ((bytes[o].toInt() and 0xff) shl 8) or (bytes[o + 1].toInt() and 0xff)
        fun u32(o: Int): Long {
            var v = 0L
            for (i in 0 until 4) {
                val b = bytes[o + i].toLong() and 0xff
                v = if (le) v or (b shl (8 * i)) else (v shl 8) or b
            }
            return v
        }
        fun u64(o: Int): Long {
            var v = 0L
            for (i in 0 until 8) {
                val b = bytes[o + i].toLong() and 0xff
                v = if (le) v or (b shl (8 * i)) else (v shl 8) or b
            }
            return v
        }

        val is64 = elfClass == 2
        val machine = u16(18)
        val entry = if (is64) u64(24) else u32(24)

        // Section header table
        val e_shoff = if (is64) u64(40) else u32(32)
        val e_shentsize = u16(if (is64) 58 else 46)
        val e_shnum = u16(if (is64) 60 else 48)
        val e_shstrndx = u16(if (is64) 62 else 50)

        if (e_shoff == 0L || e_shnum == 0) throw ElfException("ELF 缺少 section header 表")
        if (e_shoff >= bytes.size.toLong()) throw ElfException("e_shoff 越界")

        val rawSections = ArrayList<Pair<Long, Long>>() // (offset, size) by index
        val infos = ArrayList<LongArray>()
        for (i in 0 until e_shnum) {
            val base = (e_shoff + i.toLong() * e_shentsize).toInt()
            if (base + e_shentsize > bytes.size) throw ElfException("section header #$i 越界")
            if (is64) {
                infos.add(longArrayOf(
                    u32(base).toLong(), u32(base + 4).toLong(), u64(base + 8), u64(base + 16),
                    u64(base + 24), u64(base + 32), u32(base + 40).toLong(), u32(base + 44).toLong(),
                    u64(base + 48), u64(base + 56)
                ))
            } else {
                infos.add(longArrayOf(
                    u32(base).toLong(), u32(base + 4).toLong(), u32(base + 8), u32(base + 12),
                    u32(base + 16), u32(base + 20), u32(base + 24).toLong(), u32(base + 28).toLong(),
                    u32(base + 32), u32(base + 36)
                ))
            }
        }
        if (e_shstrndx >= infos.size) throw ElfException("e_shstrndx 越界")
        val shstr = infos[e_shstrndx]
        val strOff = shstr[3]; val strSize = shstr[4]
        if (strOff + strSize > bytes.size.toLong()) throw ElfException(".shstrtab 越界")
        fun nameAt(idx: Int): String {
            var p = (strOff + idx).toInt()
            if (p < 0 || p >= bytes.size) return ""
            val start = p
            while (p < bytes.size && bytes[p].toInt() != 0) p++
            return String(bytes, start, p - start, Charsets.UTF_8)
        }

        val sections = infos.mapIndexed { idx, a ->
            ElfSection(
                name = if (idx == 0) "" else nameAt(a[0].toInt()),
                type = a[1].toInt(), flags = a[2], addr = a[3], offset = a[4], size = a[5],
                link = a[6].toInt(), info = a[7].toInt(), addralign = a[8], entsize = a[9]
            )
        }

        // Program header table
        val e_phoff = if (is64) u64(32) else u32(28)
        val e_phentsize = u16(if (is64) 54 else 42)
        val e_phnum = u16(if (is64) 56 else 44)
        val segs = ArrayList<ProgramHeader>()
        if (e_phoff != 0L) for (i in 0 until e_phnum) {
            val base = (e_phoff + i.toLong() * e_phentsize).toInt()
            if (base + e_phentsize > bytes.size) throw ElfException("program header #$i 越界")
            if (is64) {
                segs.add(ProgramHeader(
                    u32(base).toInt(), u32(base + 4).toInt(),
                    u64(base + 8), u64(base + 16), u64(base + 24),
                    u64(base + 32), u64(base + 40), u64(base + 48)))
            } else {
                segs.add(ProgramHeader(
                    u32(base).toInt(), u32(base + 28).toInt(),
                    u32(base + 4), u32(base + 8), u32(base + 12),
                    u32(base + 16), u32(base + 20), u32(base + 24)))
            }
        }

        return ElfFile(
            path, bytes, elfClass, le, machine, entry, sections, segs,
            sections.map { it.name })
    }
}
