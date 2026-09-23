package compass.dwarf

/** A single abbreviation declaration. spec = (attr, form, implicitConstValue?) */
data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val specs: List<Triple<Int, Int, Long?>>)

class AbbrevTable(val decls: Map<Long, AbbrevDecl>, val warnings: List<String>)

/** Parses one .debug_abbrev set (a table ends at a null byte after its decls). */
object AbbrevParser {
    fun parse(r: Reader, tableOffset: Long): AbbrevTable {
        val decls = LinkedHashMap<Long, AbbrevDecl>()
        val warnings = mutableListOf<String>()
        try {
            r.seek(tableOffset.toIntExact())
        } catch (e: Exception) {
            return AbbrevTable(emptyMap(), listOf("abbrev table offset 0x${tableOffset.toString(16)} out of bounds"))
        }
        var guard = 0
        while (r.remaining() > 0 && guard++ < MAX_ABBREVS) {
            val code = r.uleb128()
            if (code == 0L) break
            val tag = r.uleb128().toInt()
            val hasChildren = r.u8() == DW.CHILDREN_yes
            val specs = mutableListOf<Triple<Int, Int, Long?>>()
            var specGuard = 0
            while (specGuard++ < MAX_ATTRS) {
                val attr = r.uleb128().toInt()
                val form = r.uleb128().toInt()
                if (attr == 0 && form == 0) break
                val implicit = if (form == DW.FORM_implicit_const) r.sleb128() else null
                specs += Triple(attr, form, implicit)
            }
            decls[code] = AbbrevDecl(code, tag, hasChildren, specs)
        }        if (guard >= MAX_ABBREVS) warnings += "abbrev table at 0x${tableOffset.toString(16)} hit decl cap"
        return AbbrevTable(decls, warnings)
    }

    private const val MAX_ABBREVS = 500_000
    private const val MAX_ATTRS = 400
}
