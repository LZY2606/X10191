package compass.dwarf

/** View over the sections of one file. When [preferDwo] is set, ".dwo" variants
 *  are consulted first (used while parsing split-DWARF units). */
class SectionSet(sections: List<SectionInfo>, private val preferDwo: Boolean = false) {
    private val map = sections.associateBy { it.name }

    fun get(name: String): ByteArray? {
        if (preferDwo) map[name + ".dwo"]?.let { return it.data }
        return map[name]?.data ?: map[name + ".dwo"]?.data
    }

    fun has(name: String): Boolean = map.containsKey(name)

    fun str(offset: Long, lineStr: Boolean): String? {
        val sec = get(if (lineStr) ".debug_line_str" else ".debug_str") ?: return null
        if (offset < 0 || offset >= sec.size) return null
        return try { Reader(sec, offset.toInt()).cstr() } catch (e: DwarfException) { null }
    }

    /** DWARF5 strx: index into .debug_str_offsets (base from DW_AT_str_offsets_base). */
    fun strx(index: Long, base: Long, dwarf64: Boolean): String? {
        val sec = get(".debug_str_offsets") ?: return null
        val entrySize = if (dwarf64) 8 else 4
        val at = base + index * entrySize
        if (at < 0 || at + entrySize > sec.size) return null
        val off = Reader(sec, at.toInt()).offset(dwarf64)
        return str(off, lineStr = false)
    }

    /** DWARF5 addrx: index into .debug_addr (base from DW_AT_addr_base). */
    fun addrx(index: Long, base: Long, addrSize: Int): Long? {
        val sec = get(".debug_addr") ?: return null
        val at = base + index * addrSize
        if (at < 0 || at + addrSize > sec.size) return null
        return Reader(sec, at.toInt()).addr(addrSize)
    }
}
