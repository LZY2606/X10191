package compass.dwarf

data class AbbrevAttr(val name: Int, val form: Int, val implicitConst: Long)
data class Abbreviation(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

/** Parses and memoizes abbreviation declarations keyed by their table offset. */
class AbbreviationTables(private val debugAbbrev: ByteReader?) {
    private val cache = HashMap<Long, Map<Long, Abbreviation>>()
    private val badTables = HashSet<Long>()

    fun table(offset: Long): Map<Long, Abbreviation>? {
        if (debugAbbrev == null) return emptyMap()
        cache[offset]?.let { return it }
        if (offset in badTables) return null
        val map = LinkedHashMap<Long, Abbreviation>()
        try {
            val r = debugAbbrev.subReader(debugAbbrev.base, debugAbbrev.limit)
            r.seek(offset)
            var guard = 0
            while (true) {
                if (++guard > 5_000_000) throw BoundsException("abbrev table too large")
                val code = r.uleb()
                if (code == 0L) break
                val tag = r.uleb().toInt()
                val children = r.u8()
                val attrs = ArrayList<AbbrevAttr>()
                while (true) {
                    val name = r.uleb().toInt()
                    var form = r.uleb().toInt()
                    if (name == 0 && form == 0) break
                    var implicit = 0L
                    if (form == Form.IMPLICIT_CONST) implicit = r.sleb()
                    attrs.add(AbbrevAttr(name, form, implicit))
                }
                map[code] = Abbreviation(code, tag, children == Children.YES, attrs)
            }
            cache[offset] = map
            return map
        } catch (e: Exception) {
            badTables.add(offset)
            return null
        }
    }
}
