package compass.dwarf

data class AbbrevAttr(val name: Int, val form: Int)

data class Abbreviation(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val attrs: List<AbbrevAttr>,
)

class AbbreviationTable(val entries: Map<Long, Abbreviation>) {
    fun get(code: Long): Abbreviation? = entries[code]
}

object AbbrevParser {
    /** Parse a .debug_abbrev table set starting at the CU's debug_abbrev_offset. */
    fun parse(section: ByteArray?, offset: Long): AbbreviationTable {
        if (section == null) return AbbreviationTable(emptyMap())
        val c = DwarfCursor(section, offset.toInt().coerceAtLeast(0))
        val map = LinkedHashMap<Long, Abbreviation>()
        while (!c.atEnd()) {
            val code = c.uleb()
            if (code == 0L) break
            val tag = c.uleb().toInt()
            val hasChildren = c.u8() == 1
            val attrs = ArrayList<AbbrevAttr>()
            while (true) {
                val name = c.uleb().toInt()
                val form = c.uleb().toInt()
                if (name == 0 && form == 0) break
                attrs += AbbrevAttr(name, form)
            }
            map[code] = Abbreviation(code, tag, hasChildren, attrs)
        }
        return AbbreviationTable(map)
    }
}
