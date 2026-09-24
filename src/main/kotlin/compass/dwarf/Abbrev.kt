package compass.dwarf

import compass.binary.ByteReader
import compass.binary.ParseException
import compass.binary.uleb

data class AbbrevAttr(val name: Int, val form: Int, val implicitConst: Long)

data class Abbreviation(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val attributes: List<AbbrevAttr>,
)

class AbbrevTable(val declarations: Map<Long, Abbreviation>) {
    fun get(code: Long): Abbreviation? = declarations[code]
}

/**
 * Parses .debug_abbrev. A single section may hold many tables, each terminated
 * by a zero code; CU headers point at table starts. Unknown forms are retained
 * here (with attribute known), and the info parser isolates the CU at a DIE
 * boundary instead of losing cursor alignment.
 */
object AbbrevParser {
    fun parse(section: ByteArray): Map<Long, AbbrevTable> {
        val tables = LinkedHashMap<Long, AbbrevTable>()
        val r = ByteReader(section)
        while (r.remaining() > 0) {
            val tableStart = r.pos.toLong()
            if (tables.containsKey(tableStart)) {
                // Should not happen with sequential scans, but stay defensive.
                break
            }
            val decls = LinkedHashMap<Long, Abbreviation>()
            while (true) {
                if (r.remaining() == 0) break
                val code = r.uleb()
                if (code == 0L) break
                val tag = r.uleb().toInt()
                val children = r.u1() == DW.CHILDREN_yes
                val attrs = mutableListOf<AbbrevAttr>()
                while (true) {
                    val attrName = r.uleb().toInt()
                    val form = r.uleb().toInt()
                    if (attrName == 0 && form == 0) break
                    var implicit = 0L
                    if (form == DW.FORM.implicit_const) implicit = r.sleb()
                    attrs.add(AbbrevAttr(attrName, form, implicit))
                }
                decls[code] = Abbreviation(code, tag, children, attrs)
            }
            tables[tableStart] = AbbrevTable(decls)
        }
        return tables
    }

    fun parseAt(section: ByteArray?, offset: Long): AbbrevTable? {
        if (section == null) throw ParseException("missing .debug_abbrev")
        if (offset < 0 || offset >= section.size) throw ParseException("abbrev offset 0x${offset.toString(16)} out of bounds")
        val r = ByteReader(section, offset.toInt(), section.size, offset.toInt())
        val decls = LinkedHashMap<Long, Abbreviation>()
        while (r.remaining() > 0) {
            val code = r.uleb()
            if (code == 0L) break
            val tag = r.uleb().toInt()
            val children = r.u1() == DW.CHILDREN_yes
            val attrs = mutableListOf<AbbrevAttr>()
            while (true) {
                val attrName = r.uleb().toInt()
                val form = r.uleb().toInt()
                if (attrName == 0 && form == 0) break
                var implicit = 0L
                if (form == DW.FORM.implicit_const) implicit = r.sleb()
                attrs.add(AbbrevAttr(attrName, form, implicit))
            }
            decls[code] = Abbreviation(code, tag, children, attrs)
        }
        return AbbrevTable(decls)
    }
}
