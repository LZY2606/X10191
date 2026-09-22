package compass.dwarf

import compass.Limits

class AbbrevAttr(val attr: Int, val form: Int, val implicitConst: Long?)

class Abbrev(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

/** Parses one .debug_abbrev table starting at [offset]. */
fun parseAbbrevTable(bytes: ByteArray, offset: Int): Map<Long, Abbrev> {
    if (offset < 0 || offset >= bytes.size) {
        if (bytes.isEmpty() && offset == 0) return emptyMap()
        throw ParseException("abbrev offset 0x${offset.toString(16)} out of section (size 0x${bytes.size.toString(16)})")
    }
    val r = Reader(bytes, offset)
    val out = LinkedHashMap<Long, Abbrev>()
    while (!r.eof) {
        val code = r.uleb()
        if (code == 0L) break
        if (out.size >= Limits.MAX_ABBREV_CODES) throw ParseException("too many abbrev codes")
        val tag = r.uleb()
        if (tag > Int.MAX_VALUE) throw ParseException("tag too large")
        val children = r.u8() != 0
        val attrs = ArrayList<AbbrevAttr>()
        while (true) {
            if (attrs.size >= Limits.MAX_ABBREV_ATTRS) throw ParseException("too many abbrev attributes")
            val a = r.uleb()
            val f = r.uleb()
            if (a == 0L && f == 0L) break
            if (a > Int.MAX_VALUE || f > Int.MAX_VALUE) throw ParseException("abbrev attr/form too large")
            val implicit = if (f.toInt() == F.IMPLICIT_CONST) r.sleb() else null
            attrs.add(AbbrevAttr(a.toInt(), f.toInt(), implicit))
        }
        out[code] = Abbrev(code, tag.toInt(), children, attrs)
    }
    return out
}
