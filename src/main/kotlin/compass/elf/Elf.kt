package compass.elf

import compass.dwarf.ByteView
import compass.dwarf.DwarfFormatException

/** ELF section header。 */
data class ElfSection(
    val name: String,
    val type: Long,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Long,
    val align: Long,
    val entsize: Long,
)

data class ElfSegment(
    val type: Long,
    val flags: Long,
    val offset: Long,
    val vaddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
) {
    fun contains(va: Long): Boolean = va in vaddr until vaddr + filesz
    fun vaddrToOffset(va: Long): Long? = if (contains(va)) va - vaddr + offset else null
}

data class ElfFile(
    val elfClass: Int,
    val dataEncoding: Int,
    val type: Int,
    val machine: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val raw: ByteArray,
    private val byName: Map<String, ElfSection>,
) {
    fun section(name: String): ElfSection? = byName[name]

    fun debugSections(): List<ElfSection> =
        sections.filter {
            it.name.startsWith(".debug_") || it.name.startsWith(".zdebug_") ||
                it.name == ".gdb_index" || it.name == ".eh_frame"
        }

    /**
     * 链接地址（DWARF 中使用的相对虚拟地址）-> 文件偏移。
     * 可执行/共享库走 PT_LOAD；可重定位 .o 回退到 SHF_ALLOC section。
     */
    fun linkAddrToFileOffset(linkAddr: Long): Long? {
        segments.filter { it.type == PT_LOAD }.forEach { it.vaddrToOffset(linkAddr)?.let { off -> return off } }
        sections.filter { it.flags and SHF_ALLOC != 0L && it.size > 0 }.forEach { s ->
            if (linkAddr in s.addr until s.addr + s.size) return linkAddr - s.addr + s.offset
        }
        return null
    }

    companion object {
        const val PT_LOAD = 1L
        const val SHF_ALLOC = 0x2L
    }
}

object ElfParser {
    private class RawSh(
        val nameOff: Long, val type: Long, val flags: Long, val addr: Long,
        val offset: Long, val size: Long, val link: Int, val info: Long, val align: Long, val entsize: Long,
    )

    fun parse(bytes: ByteArray): ElfFile {
        val v = ByteView(bytes)
        if (bytes.size < 64 || v.u8(0) != 0x7f || v.u8(1) != 'E'.code || v.u8(2) != 'L'.code || v.u8(3) != 'F'.code) {
            throw DwarfFormatException("not an ELF file (bad magic or truncated header)")
        }
        val elfClass = v.u8(4)
        require(elfClass == 1 || elfClass == 2) { "bad EI_CLASS=$elfClass" }
        val encoding = v.u8(5)
        require(encoding == 1) { "only little-endian ELF supported, got EI_DATA=$encoding" }

        val type = v.u16(16)
        val machine = v.u16(18)
        val entry = if (elfClass == 2) v.u64(24) else v.u32(24)
        val segments = if (elfClass == 2) parsePh64(v) else parsePh32(v)
        val rawSections = if (elfClass == 2) parseSh64(v) else parseSh32(v)
        val shstrndx = if (elfClass == 2) v.u16(62) else v.u16(50)

        val nameTab: ByteArray? = rawSections.getOrNull(shstrndx)?.let { sh ->
            runCatching { bytes.copyOfRange(sh.offset.toInt(), (sh.offset + sh.size).toInt()) }.getOrNull()
        }
        val sections = rawSections.map { r ->
            var nm = ""
            if (nameTab != null && r.nameOff >= 0 && r.nameOff < nameTab.size) {
                var end = r.nameOff.toInt()
                while (end < nameTab.size && nameTab[end].toInt() != 0) end++
                nm = String(nameTab, r.nameOff.toInt(), end - r.nameOff.toInt(), Charsets.UTF_8)
            }
            ElfSection(nm, r.type, r.flags, r.addr, r.offset, r.size, r.link, r.info, r.align, r.entsize)
        }
        val byName = linkedMapOf<String, ElfSection>()
        sections.forEach { if (it.name.isNotEmpty()) byName.putIfAbsent(it.name, it) }
        return ElfFile(elfClass, encoding, type, machine, entry, sections, segments, bytes, byName)
    }

    private fun parseSh32(v: ByteView): List<RawSh> {
        val shoff = v.u32(28)
        val shentsize = v.u16(46)
        var shnum = v.u16(48)
        if (shoff == 0L) return emptyList()
        require(shentsize >= 40) { "bad shentsize=$shentsize" }
        if (shnum == 0 && shentsize > 0) {
            // ELF 规范：节数溢出到第 0 节 sh_size
            shnum = v.u32(shoff.toInt() + 20).toInt()
        }
        return (0 until shnum).map { i ->
            val o = (shoff + i.toLong() * shentsize).toInt()
            RawSh(
                v.u32(o), v.u32(o + 4), v.u32(o + 8), v.u32(o + 12),
                v.u32(o + 16), v.u32(o + 20), v.u16(o + 24), v.u32(o + 28),
                v.u32(o + 32), v.u32(o + 36),
            )
        }
    }

    private fun parseSh64(v: ByteView): List<RawSh> {
        val shoff = v.u64(40)
        val shentsize = v.u16(58)
        var shnum = v.u16(60)
        if (shoff == 0L) return emptyList()
        require(shentsize >= 64) { "bad shentsize=$shentsize" }
        if (shnum == 0 && shentsize > 0) {
            shnum = v.u64(shoff.toInt() + 32).toInt()
        }
        return (0 until shnum).map { i ->
            val o = (shoff + i.toLong() * shentsize).toInt()
            RawSh(
                v.u32(o), v.u32(o + 4), v.u64(o + 8), v.u64(o + 16),
                v.u64(o + 24), v.u64(o + 32), v.u32(o + 40), v.u64(o + 44),
                v.u64(o + 48), v.u64(o + 56),
            )
        }
    }

    private fun parsePh32(v: ByteView): List<ElfSegment> {
        val phoff = v.u32(28 + 4)
        val phentsize = v.u16(42)
        val phnum = v.u16(44)
        if (phoff == 0L) return emptyList()
        require(phentsize >= 32) { "bad phentsize=$phentsize" }
        return (0 until phnum).map { i ->
            val o = (phoff + i.toLong() * phentsize).toInt()
            ElfSegment(v.u32(o), v.u32(o + 24), v.u32(o + 4), v.u32(o + 8), v.u32(o + 16), v.u32(o + 20), v.u32(o + 28))
        }
    }

    private fun parsePh64(v: ByteView): List<ElfSegment> {
        val phoff = v.u64(32)
        val phentsize = v.u16(54)
        val phnum = v.u16(56)
        if (phoff == 0L) return emptyList()
        require(phentsize >= 56) { "bad phentsize=$phentsize" }
        return (0 until phnum).map { i ->
            val o = (phoff + i.toLong() * phentsize).toInt()
            ElfSegment(v.u32(o), v.u32(o + 4), v.u64(o + 8), v.u64(o + 16), v.u64(o + 32), v.u64(o + 40), v.u64(o + 48))
        }
    }
}
