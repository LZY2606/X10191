package compass.dwarf

data class AbbrevAttr(val name: Int, val form: Int, val implicitConst: Long? = null)

data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

class AbbrevTable(val decls: Map<Long, AbbrevDecl>) {
    fun lookup(code: Long): AbbrevDecl? = decls[code]
}

object AbbrevParser {
    const val MAX_ABBREVS = 4096
    const val MAX_ATTRS_PER_DECL = 512

    /** Parses one abbrev table starting at [offset]; returns the table. */
    fun parse(section: ByteArray, offset: Int, bigEndian: Boolean = false): AbbrevTable {
        if (offset < 0 || offset >= section.size) {
            throw DwarfParseException("abbrev offset $offset out of bounds (${section.size})")
        }
        val r = ByteReader(section, offset, section.size, bigEndian)
        val decls = LinkedHashMap<Long, AbbrevDecl>()
        var count = 0
        while (true) {
            if (count++ > MAX_ABBREVS) throw DwarfParseException("abbrev table too large")
            val code = r.uleb128()
            if (code == 0L) break
            val tag = r.uleb128().toInt()
            val hasChildren = r.u1() != 0
            val attrs = mutableListOf<AbbrevAttr>()
            var acount = 0
            while (true) {
                if (acount++ > MAX_ATTRS_PER_DECL) throw DwarfParseException("abbrev decl too large")
                val name = r.uleb128().toInt()
                var form = r.uleb128().toInt()
                var implicit: Long? = null
                if (form == Form.IMPLICIT_CONST) implicit = r.sleb128()
                if (name == 0 && form == 0) break
                attrs.add(AbbrevAttr(name, form, implicit))
            }
            decls[code] = AbbrevDecl(code, tag, hasChildren, attrs)
        }
        return AbbrevTable(decls)
    }
}
