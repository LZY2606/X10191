package compass.dwarf

data class AbbrevAttr(val attr: Int, val form: Int, val implicitConst: Long? = null)

data class Abbrev(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

class AbbrevTable(val byCode: Map<Long, Abbrev>) {
    fun lookup(code: Long): Abbrev? = byCode[code]

    companion object {
        const val MAX_ABBREVS = 4096
        const val MAX_ATTRS = 1024

        fun parse(section: ByteArray, offset: Long, littleEndian: Boolean = true): AbbrevTable {
            if (offset < 0 || offset >= section.size) {
                throw DwarfParseException("abbrev offset $offset out of bounds (section size ${section.size})")
            }
            val r = Reader(section, offset.toInt(), section.size, littleEndian)
            val map = LinkedHashMap<Long, Abbrev>()
            while (r.remaining() > 0) {
                if (map.size >= MAX_ABBREVS) throw LimitExceededException("too many abbrev entries")
                val code = r.uleb()
                if (code == 0L) break
                val tag = r.uleb().toInt()
                val hasChildren = r.u8() != 0
                val attrs = ArrayList<AbbrevAttr>()
                while (true) {
                    if (attrs.size >= MAX_ATTRS) throw LimitExceededException("too many abbrev attributes")
                    val attr = r.uleb().toInt()
                    var form = r.uleb().toInt()
                    var implicit: Long? = null
                    if (attr == 0 && form == 0) break
                    if (form == Dw.FORM_implicit_const) {
                        implicit = r.sleb()
                    }
                    attrs.add(AbbrevAttr(attr, form, implicit))
                }
                map[code] = Abbrev(code, tag, hasChildren, attrs)
            }
            return AbbrevTable(map)
        }
    }
}
