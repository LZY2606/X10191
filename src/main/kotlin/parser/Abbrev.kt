package parser

data class AbbrevAttr(val name: Int, val form: Int, val implicitConst: Long = 0)
data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

class AbbrevTable(val decls: Map<Long, AbbrevDecl>)

/**
 * Parses .debug_abbrev starting at a CU-specific offset. A malformed entry (unknown attr
 * form is still read structurally here) only breaks decoding when the form size cannot
 * be determined — in that case ParseException is thrown for that CU alone.
 */
object AbbrevParser {
    fun parseAt(section: ByteArray?, offset: Long): AbbrevTable {
        if (section == null) return AbbrevTable(emptyMap())
        val r = BinaryReader(section)
        if (offset < 0 || offset >= section.size) throw ParseException("abbrev offset out of bounds: $offset")
        r.seek(offset.toInt())
        val map = LinkedHashMap<Long, AbbrevDecl>()
        var guard = 0
        while (!r.atEnd() && guard++ < 5_000_000) {
            val code = r.uleb128()
            if (code == 0L) break
            val tag = r.uleb128()
            val hasChildren = r.u8() == 1
            val attrs = mutableListOf<AbbrevAttr>()
            var attrGuard = 0
            while (attrGuard++ < 1_000_000) {
                val name = r.uleb128()
                val form = r.uleb128()
                var implicit = 0L
                if (form == DW.FORM_IMPLICIT_CONST.toLong()) implicit = r.sleb128()
                attrs.add(AbbrevAttr(name.toInt(), form.toInt(), implicit))
                if (name == 0L && form == 0L) break
            }
            map[code] = AbbrevDecl(code, tag.toInt(), hasChildren, attrs)
        }
        return AbbrevTable(map)
    }
}
