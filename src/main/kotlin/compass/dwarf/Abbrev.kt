package compass.dwarf

import compass.elf.Reader

data class AbbrevAttr(val attr: Long, val form: Long, val implicitConst: Long = 0L)

data class AbbrevDef(val code: Long, val tag: Long, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

object AbbrevTable {
    /** Parse one abbreviation table starting at [offset]. Returns code -> def.
     *  Bounded by [Limits.MAX_ABBREV_ATTRS] so a corrupt table cannot loop forever. */
    fun parse(data: ByteArray, offset: Int, bigEndian: Boolean): Map<Long, AbbrevDef> {
        if (offset < 0 || offset >= data.size) throw BadReference("abbrev offset $offset out of bounds (size ${data.size})")
        val r = Reader(data, offset, data.size, bigEndian)
        val out = HashMap<Long, AbbrevDef>()
        while (true) {
            val code = r.uleb128()
            if (code == 0L) break
            val tag = r.uleb128()
            val children = r.u8() != 0
            val attrs = ArrayList<AbbrevAttr>()
            var count = 0
            while (true) {
                if (++count > Limits.MAX_ABBREV_ATTRS) throw BadReference("abbrev $code has too many attributes")
                val attr = r.uleb128()
                val form = r.uleb128()
                if (attr == 0L && form == 0L) break
                val implicit = if (form == Form.IMPLICIT_CONST) r.sleb128() else 0L
                attrs.add(AbbrevAttr(attr, form, implicit))
            }
            out[code] = AbbrevDef(code, tag, children, attrs)
        }
        return out
    }
}
