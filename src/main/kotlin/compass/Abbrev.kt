package compass

data class AbbrevAttr(val nameCode: Long, val formCode: Long, val implicitConst: Long?)

data class AbbrevEntry(val code: Long, val tag: Long, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

class AbbrevTable(val entries: Map<Long, AbbrevEntry>, val warnings: List<String>)

/**
 * Parse one .debug_abbrev declaration set starting at [offset].
 * Declaration sets are terminated by a 0 code and concatenated in the section.
 */
object AbbrevParser {
    fun parse(section: ByteArray, offset: Int, warnings: MutableList<ParseWarning>): AbbrevTable {
        val map = LinkedHashMap<Long, AbbrevEntry>()
        val localWarnings = mutableListOf<String>()
        try {
            val c = ByteCursor(section, offset, section.size, ".debug_abbrev")
            var count = 0
            while (true) {
                if (c.remaining == 0) break
                val code = c.uleb()
                if (code == 0L) break
                if (++count > Limits.MAX_ABBREV_ENTRIES) throw CursorException(".debug_abbrev: too many entries from $offset")
                val tag = c.uleb()
                val hasChildren = c.u8() == 1
                val attrs = mutableListOf<AbbrevAttr>()
                var ac = 0
                while (true) {
                    if (++ac > Limits.MAX_ABBREV_ATTRS) throw CursorException(".debug_abbrev: too many attributes")
                    val nameCode = c.uleb()
                    val formCode = c.uleb()
                    if (nameCode == 0L && formCode == 0L) break
                    var implicit: Long? = null
                    if (formCode == Dw.FORM_IMPLICIT_CONST) implicit = c.sleb()
                    attrs.add(AbbrevAttr(nameCode, formCode, implicit))
                    if (!FormReader.isSkippable(formCode)) {
                        throw CursorException(".debug_abbrev: unknown form 0x${formCode.toString(16)} in abbrev $code; CU will be isolated")
                    }
                }
                map[code] = AbbrevEntry(code, tag, hasChildren, attrs)
            }
        } catch (e: CursorException) {
            localWarnings.add(e.message ?: "abbrev parse error")
            warnings.add(ParseWarning("abbrev", "error", e.message ?: "abbrev parse error"))
        }
        return AbbrevTable(map, localWarnings)
    }
}
