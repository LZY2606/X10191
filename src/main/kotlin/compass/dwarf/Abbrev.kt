package compass.dwarf

class AbbrevAttr(val attr: Long, val form: Long, val implicitConst: Long?)

class AbbrevDecl(val code: Long, val tag: Long, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

class AbbrevTable(val decls: Map<Long, AbbrevDecl>) {
    fun decl(code: Long): AbbrevDecl? = decls[code]

    companion object {
        const val MAX_DECLS = 100000
        fun parse(bytes: ByteArray, offset: Long, little: Boolean): AbbrevTable {
            if (offset < 0 || offset >= bytes.size) throw DwarfException("abbrev 偏移越界: $offset")
            val r = Reader(bytes, little, offset.toInt())
            val decls = HashMap<Long, AbbrevDecl>()
            while (true) {
                val code = r.uleb()
                if (code == 0L) break
                if (decls.size >= MAX_DECLS) throw DwarfException("abbrev 声明数量超限")
                val tag = r.uleb()
                val hasChildren = r.u8() != 0
                val attrs = ArrayList<AbbrevAttr>()
                while (true) {
                    val attr = r.uleb()
                    val form = r.uleb()
                    if (attr == 0L && form == 0L) break
                    if (attrs.size >= 4096) throw DwarfException("abbrev 属性数量超限")
                    val implicit = if (form == Form.IMPLICIT_CONST) r.sleb() else null
                    attrs.add(AbbrevAttr(attr, form, implicit))
                }
                decls[code] = AbbrevDecl(code, tag, hasChildren, attrs)
            }
            return AbbrevTable(decls)
        }
    }
}
