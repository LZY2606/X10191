package compass.dwarf

import compass.elf.Reader

class UnknownFormException(val form: Int) : RuntimeException("unknown DWARF form 0x${"%x".format(form)}")

data class AbbrevAttr(val attr: Int, val form: Int, val implicitConst: Long = 0)
data class Abbrev(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

/**
 * All abbreviation tables of one .debug_abbrev section, keyed by table offset.
 * Tables are parsed on demand with a bounded scan; zero code ends a table.
 */
class AbbrevTables(private val data: ByteArray, private val endianBig: Boolean) {
    private val cache = HashMap<Long, Map<Long, Abbrev>>()

    fun tableAt(offset: Long): Map<Long, Abbrev> {
        cache[offset]?.let { return it }
        val r = Reader(data, compass.model.Endian.entries.first { it.big == endianBig })
        if (offset < 0 || offset >= data.size) throw compass.elf.BinaryTruncatedException("abbrev offset out of range")
        r.seek(offset.toInt())
        val out = LinkedHashMap<Long, Abbrev>()
        while (r.remaining() > 0) {
            val code = r.uleb128()
            if (code == 0L) break
            val tag = r.uleb128().toInt()
            val hasChildren = r.u8() == DW.CHILDREN_yes
            val attrs = ArrayList<AbbrevAttr>()
            while (true) {
                val attr = r.uleb128().toInt()
                val form = r.uleb128().toInt()
                if (attr == 0 && form == 0) break
                var implicit = 0L
                if (form == DW.FORM_indirect) {
                    // FORM_indirect cannot appear in abbrev declarations meaningfully; keep it
                }
                if (form == DW.FORM_implicit_const) implicit = r.sleb128()
                attrs.add(AbbrevAttr(attr, form, implicit))
            }
            out[code] = Abbrev(code, tag, hasChildren, attrs)
        }
        cache[offset] = out
        return out
    }
}
