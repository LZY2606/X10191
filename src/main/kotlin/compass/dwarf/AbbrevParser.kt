package compass.dwarf

import compass.binfmt.Cursor
import compass.binfmt.DwarfParseException

object AbbrevParser {
    /** Parse the whole .debug_abbrev section into offset -> Abbrev maps per abbrev table. */
    fun parse(data: ByteArray, littleEndian: Boolean): Map<Long, Map<Long, Abbrev>> {
        val tables = mutableMapOf<Long, Map<Long, Abbrev>>()
        var tableStart = 0L
        var c = Cursor(data, 0, data.size, 0, littleEndian)
        while (c.available() > 0) {
            tableStart = (c.pos).toLong()
            val map = mutableMapOf<Long, Abbrev>()
            while (true) {
                val code = c.uleb128()
                if (code == 0L) break
                val tag = c.uleb128().toInt()
                val hasChildren = c.u8() == Dw.CHILDREN_yes
                val specs = mutableListOf<AttributeSpec>()
                while (true) {
                    val name = c.uleb128().toInt()
                    val form = c.uleb128().toInt()
                    if (name == 0 && form == 0) break
                    val implicit = if (form == Dw.FORM_implicit_const) c.sleb128() else null
                    specs.add(AttributeSpec(name, form, implicit))
                }
                map[code] = Abbrev(code, tag, hasChildren, specs)
            }
            tables[tableStart] = map
            // consecutive tables; continue scanning (zero byte marks table end, already consumed)
        }
        return tables
    }
}
