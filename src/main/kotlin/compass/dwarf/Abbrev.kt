package compass.dwarf

data class AbbrevAttr(val name: Int, val form: Int, val implicitConst: Long?)
data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

class AbbrevTable(private val decls: Map<Long, AbbrevDecl>) {
    fun get(code: Long): AbbrevDecl? = decls[code]

    companion object {
        fun parse(data: ByteArray, startOffset: Long): AbbrevTable {
            val r = BinReader(data, startOffset.toInt(), littleEndian = true)
            val decls = linkedMapOf<Long, AbbrevDecl>()
            var guard = 0
            while (true) {
                if (r.remaining() <= 0) break
                if (++guard > 1_000_000) throw ParseException("abbrev 条目数超限", startOffset)
                val code = r.uleb()
                if (code == 0L) break
                val tag = r.uleb().toInt()
                val hasChildren = r.u8() == 1
                val attrs = mutableListOf<AbbrevAttr>()
                var aguard = 0
                while (true) {
                    if (++aguard > 100_000) throw ParseException("abbrev 属性数超限")
                    val name = r.uleb().toInt()
                    val form = r.uleb().toInt()
                    if (name == 0 && form == 0) break
                    var implicit: Long? = null
                    if (form == DW_FORM.IMPLICIT_CONST) implicit = r.sleb()
                    attrs.add(AbbrevAttr(name, form, implicit))
                }
                decls[code] = AbbrevDecl(code, tag, hasChildren, attrs)
            }
            return AbbrevTable(decls)
        }
    }
}
