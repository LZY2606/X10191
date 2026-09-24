package linecompass.dwarf

/** One abbreviation declaration. attr -> form; implicit constants keep their folded value. */
data class AbbrevAttr(val attr: Int, val form: Int, val implicitConst: Long? = null)
data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

/**
 * A decoded .debug_abbrev table. Tables are shared by CUs via table offset;
 * each table is decoded once and bounded by the section end (tables are
 * terminated by a zero declaration byte, after which the next table begins).
 */
class AbbrevTable(val decls: Map<Long, AbbrevDecl>) {
    companion object {
        fun read(data: ByteArray, offset: Int): AbbrevTable {
            val r = BoundedReader(data, offset, data.size - offset, "debug_abbrev", maxJumps = 64)
            val map = LinkedHashMap<Long, AbbrevDecl>()
            while (true) {
                if (r.remaining == 0) break
                val code = r.uleb()
                if (code == 0L) break
                val tag = r.uleb().toInt()
                val hasChildren = r.u8() == 1
                val attrs = ArrayList<AbbrevAttr>()
                while (true) {
                    val attr = r.uleb().toInt()
                    val form = r.uleb().toInt()
                    if (attr == 0 && form == 0) break
                    val implicit = if (form == Form.IMPLICIT_CONST) r.sleb() else null
                    attrs.add(AbbrevAttr(attr, form, implicit))
                }
                map[code] = AbbrevDecl(code, tag, hasChildren, attrs)
            }
            return AbbrevTable(map)
        }
    }
}
