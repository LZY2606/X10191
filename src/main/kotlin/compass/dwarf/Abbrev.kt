package compass.dwarf

data class AttrSpec(val attr: Long, val form: Long, val implicitConst: Long? = null)

data class Abbrev(
    val code: Long,
    val tag: Long,
    val hasChildren: Boolean,
    val attrs: List<AttrSpec>,
)

object AbbrevTable {
    const val MAX_ABBREVS = 100_000
    const val MAX_ATTRS = 4096

    /** Parse one abbrev table starting at [offset] in .debug_abbrev. */
    fun parse(bytes: ByteArray, offset: Long, littleEndian: Boolean, issues: MutableList<String>): Map<Long, Abbrev> {
        val out = LinkedHashMap<Long, Abbrev>()
        if (offset < 0 || offset >= bytes.size) {
            issues.add("abbrev offset 0x${offset.toString(16)} out of bounds (section size 0x${bytes.size.toString(16)})")
            return out
        }
        val r = Reader(bytes, offset.toInt(), bytes.size, littleEndian)
        try {
            while (!r.eof()) {
                if (out.size >= MAX_ABBREVS) {
                    issues.add("abbrev table exceeds $MAX_ABBREVS entries; truncated")
                    break
                }
                val code = r.uleb()
                if (code == 0L) break
                val tag = r.uleb()
                val hasChildren = r.u8() == 1
                val attrs = ArrayList<AttrSpec>()
                while (true) {
                    if (attrs.size >= MAX_ATTRS) {
                        issues.add("abbrev code $code exceeds $MAX_ATTRS attributes; truncated")
                        break
                    }
                    val at = r.uleb()
                    val form = r.uleb()
                    if (at == 0L && form == 0L) break
                    val implicit = if (form == Form.IMPLICIT_CONST) r.sleb() else null
                    attrs.add(AttrSpec(at, form, implicit))
                }
                out[code] = Abbrev(code, tag, hasChildren, attrs)
            }
        } catch (e: DwarfException) {
            issues.add("abbrev table parse error: ${e.message}")
        }
        return out
    }
}
