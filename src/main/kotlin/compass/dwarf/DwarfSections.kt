package compass.dwarf

import compass.binary.ByteReader
import compass.elf.ElfFile

/**
 * Raw DWARF sections for one debug object (main executable, .dwo, .gnu_debugdata...).
 * Missing sections stay null; every reader is freshly windowed to the section bounds.
 */
class DwarfSections(
    val elf: ElfFile,
    val sections: Map<String, ByteArray>,
) {
    fun has(name: String): Boolean = sections[name] != null
    fun bytes(name: String): ByteArray? = sections[name]
    fun reader(name: String): ByteReader? = sections[name]?.let { ByteReader(it) }

    val debugInfo get() = bytes(".debug_info")
    val debugAbbrev get() = bytes(".debug_abbrev")
    val debugLine get() = bytes(".debug_line")
    val debugLineStr get() = bytes(".debug_line_str")
    val debugStr get() = bytes(".debug_str")
    val debugStrOffsets get() = bytes(".debug_str_offsets")
    val debugAddr get() = bytes(".debug_addr")
    val debugRanges get() = bytes(".debug_ranges")
    val debugRnglists get() = bytes(".debug_rnglists")

    companion object {
        /** DWARF section names we read (plain and split-dwo variants). */
        val DWARF_SECTION_NAMES = listOf(
            ".debug_info", ".debug_types", ".debug_abbrev", ".debug_line", ".debug_line_str",
            ".debug_str", ".debug_str_offsets", ".debug_addr", ".debug_ranges", ".debug_rnglists",
            ".debug_abbrev.dwo", ".debug_info.dwo", ".debug_line.dwo", ".debug_line_str.dwo",
            ".debug_str.dwo", ".debug_str_offsets.dwo", ".debug_addr", ".debug_rnglists.dwo",
        )

        fun fromElf(elf: ElfFile): DwarfSections {
            val map = LinkedHashMap<String, ByteArray>()
            for (name in DWARF_SECTION_NAMES) {
                val s = elf.section(name) ?: continue
                if (s.size == 0) continue
                val bytes = ByteArray(s.size)
                System.arraycopy(elf.bytes, s.offset, bytes, 0, s.size)
                map[name] = bytes
            }
            // SHT_NOBITS sections are absent from file bytes; that is handled by size==0 above.
            return DwarfSections(elf, map)
        }
    }
}
