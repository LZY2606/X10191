package addresscompass.dwarf

import addresscompass.elf.ElfFile

/** Raw bytes of all DWARF carrying sections. Missing sections are null. */
class DebugSections(private val elf: ElfFile) {
    val info: ByteArray? = elf.section(".debug_info")?.bytes
    val abbrev: ByteArray? = elf.section(".debug_abbrev")?.bytes
    val line: ByteArray? = elf.section(".debug_line")?.bytes
    val ranges: ByteArray? = elf.section(".debug_ranges")?.bytes
    val rnglists: ByteArray? = elf.section(".debug_rnglists")?.bytes
    val str: ByteArray? = elf.section(".debug_str")?.bytes
    val lineStr: ByteArray? = elf.section(".debug_line_str")?.bytes
    val addr: ByteArray? = elf.section(".debug_addr")?.bytes
    val strOffsets: ByteArray? = elf.section(".debug_str_offsets")?.bytes
    val abbrevDwo: ByteArray? = elf.section(".debug_abbrev.dwo")?.bytes
    val infoDwo: ByteArray? = elf.section(".debug_info.dwo")?.bytes
    val rnglistsDwo: ByteArray? = elf.section(".debug_rnglists.dwo")?.bytes
    val strDwo: ByteArray? = elf.section(".debug_str.dwo")?.bytes
    val strOffsetsDwo: ByteArray? = elf.section(".debug_str_offsets.dwo")?.bytes
    val lineDwo: ByteArray? = elf.section(".debug_line.dwo")?.bytes

    fun has(s: ByteArray?): Boolean = s != null && s.isNotEmpty()
}
