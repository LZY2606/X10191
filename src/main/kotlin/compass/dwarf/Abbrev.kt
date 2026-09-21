package compass.dwarf

import compass.util.ByteReader
import compass.util.Limits
import compass.util.ParseException
import compass.util.U64

data class AbbrevAttr(val attr: Int, val form: Int, val implicitValue: Long? = null)
data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

/**
 * Parses one .debug_abbrev (or .debug_abbrev.dwo) table lazily by CU offset.
 * A malformed abbreviation table aborts only CUs that reference the bad region.
 */
class AbbreviationTables(private val sections: Sections) {
    private data class CacheKey(val section: String, val offset: U64)
    private val cache = HashMap<CacheKey, ParseResult>()

    sealed interface ParseResult {
        data class Ok(val decls: Map<Long, AbbrevDecl>) : ParseResult
        data class Bad(val issue: ParseIssue) : ParseResult
    }

    fun tableAt(tableOffset: U64, dwo: Boolean): ParseResult {
        val secName = if (dwo) ".debug_abbrev.dwo" else ".debug_abbrev"
        return cache.getOrPut(CacheKey(secName, tableOffset)) {
            val bytes = sections[secName]
                ?: return@getOrPut ParseResult.Bad(
                    ParseIssue("error", "MISSING_ABBREV", "abbreviation section not found", secName, null, null)
                )
            val off = tableOffset.v.toInt()
            if (off < 0 || off >= bytes.size) {
                return@getOrPut ParseResult.Bad(
                    ParseIssue("error", "ABBREV_OFFSET_OOB", "abbrev offset ${tableOffset} out of section", secName, tableOffset, null)
                )
            }
            try {
                val r = ByteReader(bytes, off)
                val decls = LinkedHashMap<Long, AbbrevDecl>()
                while (true) {
                    if (r.eof()) throw ParseException("abbrev table unterminated")
                    val code = r.uleb128()
                    if (code == 0L) break
                    if (decls.size > Limits.MAX_TABLE_ENTRIES) throw ParseException("abbrev table too large")
                    val tag = r.uleb128().toInt()
                    val hasChildren = r.u8() == 1
                    val attrs = ArrayList<AbbrevAttr>()
                    while (true) {
                        val attr = r.uleb128().toInt()
                        val form = r.uleb128().toInt()
                        if (attr == 0 && form == 0) break
                        if (attrs.size > Limits.MAX_TABLE_ENTRIES) throw ParseException("abbrev attr list too long")
                        val implicit = if (form == DwForm.IMPLICIT_CONST) r.sleb128() else null
                        attrs += AbbrevAttr(attr, form, implicit)
                    }
                    decls[code] = AbbrevDecl(code, tag, hasChildren, attrs)
                }
                ParseResult.Ok(decls)
            } catch (e: ParseException) {
                ParseResult.Bad(
                    ParseIssue("error", "BAD_ABBREV", e.message ?: "abbrev parse failed", secName, U64(off.toLong()), null)
                )
            }
        }
    }
}
