package compass.dwarf

data class AttrSpec(val name: Int, val form: Int, val implicitConst: Long? = null)

data class AbbrevDecl(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val attrs: List<AttrSpec>,
)

/** Parses one .debug_abbrev table starting at [offset]. */
object AbbrevTable {
    fun parse(buf: ByteArray, offset: Int, order: java.nio.ByteOrder): Map<Long, AbbrevDecl> {
        if (offset < 0 || offset >= buf.size) {
            throw DwarfParseException("abbrev offset 0x${offset.toString(16)} out of .debug_abbrev bounds")
        }
        val c = Cursor(buf, offset, buf.size, order)
        val decls = LinkedHashMap<Long, AbbrevDecl>()
        while (true) {
            if (decls.size > Dw.MAX_ABBREV_DECLS) throw DwarfParseException("abbrev table too large")
            val code = c.uleb()
            if (code == 0L) break
            val tag = c.uleb().toInt()
            val children = c.u8()
            val attrs = mutableListOf<AttrSpec>()
            while (true) {
                if (attrs.size > Dw.MAX_ABBREV_ATTRS) throw DwarfParseException("abbrev decl too many attrs")
                val name = c.uleb().toInt()
                val form = c.uleb().toInt()
                if (name == 0 && form == 0) break
                val implicit = if (form == Dw.FORM_implicit_const) c.sleb() else null
                attrs.add(AttrSpec(name, form, implicit))
            }
            decls[code] = AbbrevDecl(code, tag, children == Dw.CHILDREN_yes, attrs)
        }
        return decls
    }
}
