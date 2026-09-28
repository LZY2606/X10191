package com.linecompass.dwarf

import com.linecompass.io.ByteReader

data class AbbrevAttr(val name: Int, val form: Int, val implicitConst: Long = 0)

data class AbbrevDecl(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val attrs: List<AbbrevAttr>
)

class AbbrevTable(val decls: Map<Long, AbbrevDecl>) {
    fun lookup(code: Long): AbbrevDecl? = decls[code]
}

object AbbrevParser {
    /** Parse a single abbreviation table starting at [tableOffset]. */
    fun parseTable(abbrev: ByteArray, tableOffset: Long, le: Boolean, issues: MutableList<ParseIssue>): AbbrevTable? {
        if (tableOffset < 0 || tableOffset >= abbrev.size) {
            issues += ParseIssue(".debug_abbrev", "ERROR", "ABBREV_TABLE_OOB",
                "abbrev table offset 0x${tableOffset.toString(16)} out of bounds")
            return null
        }
        val r = ByteReader(abbrev, le, ".debug_abbrev", tableOffset.toInt())
        val decls = LinkedHashMap<Long, AbbrevDecl>()
        try {
            while (true) {
                val code = r.uleb128()
                if (code == 0L) break
                val tag = r.uleb128().toInt()
                val hasChildren = r.u1() == 1
                val attrs = mutableListOf<AbbrevAttr>()
                while (true) {
                    val name = r.uleb128().toInt()
                    val form = r.uleb128().toInt()
                    if (name == 0 && form == 0) break
                    val implicit = if (form == DW.FORM_implicit_const) r.sleb128() else 0L
                    attrs += AbbrevAttr(name, form, implicit)
                }
                if (decls.size >= Limits.MAX_CUS * 4L) {
                    issues += ParseIssue(".debug_abbrev", "ERROR", "ABBREV_TOO_MANY",
                        "abbreviation table exceeds safety limit at 0x${r.offset.toString(16)}")
                    break
                }
                decls[code] = AbbrevDecl(code, tag, hasChildren, attrs)
            }
        } catch (e: Exception) {
            issues += ParseIssue(".debug_abbrev", "ERROR", "ABBREV_TRUNCATED",
                "abbrev table truncated/corrupt at 0x${r.offset.toString(16)}: ${e.message}")
        }
        return AbbrevTable(decls)
    }
}
