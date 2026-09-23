package addresscompass.dwarf

import addresscompass.model.ParseIssue
import addresscompass.model.Severity

data class AbbrevAttrSpec(val attr: Int, val form: Int, val implicitConst: Long?)

data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttrSpec>) {
    val isNull: Boolean get() = code == 0L
}

class AbbrevTable(val declarations: Map<Long, AbbrevDecl>, val issues: List<ParseIssue>) {
    fun byCode(code: Long): AbbrevDecl? = declarations[code]
}

object AbbrevParser {
    /**
     * Parse abbreviation tables starting at [offset] in .debug_abbrev.
     * A table ends at a zero abbrev code; the CU points at its own table start.
     */
    fun parseTable(section: ByteArray?, offset: Long, endian: java.nio.ByteOrder): AbbrevTable {
        val issues = mutableListOf<ParseIssue>()
        if (section == null) {
            return AbbrevTable(emptyMap(), listOf(ParseIssue(Severity.ERROR, ".debug_abbrev", 0, "section missing")))
        }
        if (offset < 0 || offset >= section.size) {
            return AbbrevTable(emptyMap(), listOf(ParseIssue(Severity.ERROR, ".debug_abbrev", offset, "abbrev offset out of bounds", true)))
        }
        val r = ByteReader(section, endian = endian)
        r.seek(offset.toInt())
        val map = LinkedHashMap<Long, AbbrevDecl>()
        try {
            while (r.remaining > 0) {
                val code = r.uleb()
                if (code == 0L) break
                val tag = r.uleb().toInt()
                val hasChildren = r.u8() == 1
                val attrs = mutableListOf<AbbrevAttrSpec>()
                while (true) {
                    val attr = r.uleb().toInt()
                    val form = r.uleb().toInt()
                    if (attr == 0 && form == 0) break
                    val implicit = if (form == Dwarf.DW_FORM_implicit_const) r.sleb() else null
                    attrs += AbbrevAttrSpec(attr, form, implicit)
                }
                map[code] = AbbrevDecl(code, tag, hasChildren, attrs)
            }
        } catch (e: SectionTruncatedException) {
            issues += ParseIssue(Severity.ERROR, ".debug_abbrev", r.absoluteOffsetInSection(), e.message ?: "truncated", true)
        }
        return AbbrevTable(map, issues)
    }
}
