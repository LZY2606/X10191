package compass.dwarf

import compass.ByteReader

/** Parses .debug_abbrev into offset-keyed declaration tables. */
object AbbrevParser {

    class BadAbbrev(message: String) : RuntimeException(message)

    /** The signed inline value lives next to the (attr, implicit_const) pair. */
    data class AbbrevEntry(val attr: Int, val form: Int, val implicitConst: Long?)

    class Decl(
        val code: Long,
        val tag: Int,
        val hasChildren: Boolean,
        val entries: List<AbbrevEntry>,
    )

    fun parse(data: ByteArray): Map<Long, Map<Long, Decl>> {
        val tables = LinkedHashMap<Long, LinkedHashMap<Long, Decl>>()
        val r = ByteReader(data)
        var guard = 0
        while (r.remaining > 0) {
            if (++guard > 100_000) throw BadAbbrev("abbrev table count limit")
            val tableOffset = r.pos.toLong()
            val table = LinkedHashMap<Long, Decl>()
            while (r.remaining > 0) {
                val code = r.uleb()
                if (code == 0L) break
                if (table.size > 1_000_000) throw BadAbbrev("abbrev decl limit")
                val tag = r.uleb().toIntExact()
                val hasChildren = r.u8() == 1
                val entries = ArrayList<AbbrevEntry>()
                while (true) {
                    val attr = r.uleb().toIntExact()
                    val form = r.uleb().toIntExact()
                    if (attr == 0 && form == 0) break
                    if (entries.size > 10_000) throw BadAbbrev("attribute count limit")
                    val inlineConst = if (form == DW.FORM_implicit_const) r.sleb() else null
                    entries.add(AbbrevEntry(attr, form, inlineConst))
                }
                table[code] = Decl(code, tag, hasChildren, entries)
            }
            tables[tableOffset] = table
            // An empty table (two terminating zeros in a row) ends the section.
            if (table.isEmpty()) break
        }
        return tables
    }

    private fun Long.toIntExact(): Int {
        if (this < 0) throw BadAbbrev("negative field")
        return toInt()
    }
}
