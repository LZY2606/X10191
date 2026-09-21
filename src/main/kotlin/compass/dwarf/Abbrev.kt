package compass.dwarf

import compass.binary.ByteReader
import compass.binary.DwarfParseException

data class AttrSpec(val attr: Int, val form: Int, val implicitConst: Long? = null)
data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AttrSpec>)

/** Parses one .debug_abbrev contribution starting at [tableOffset]. */
class AbbrevTable(val decls: Map<Long, AbbrevDecl>) {
    companion object {
        fun parse(data: ByteArray, tableOffset: Long): AbbrevTable {
            if (data.isEmpty()) throw DwarfParseException(".debug_abbrev 为空")
            if (tableOffset < 0 || tableOffset >= data.size) {
                throw DwarfParseException("abbrev 表偏移越界 offset=$tableOffset")
            }
            val r = ByteReader(data, tableOffset.toInt(), data.size)
            val map = LinkedHashMap<Long, AbbrevDecl>()
            var guard = 0
            while (true) {
                if (++guard > MAX_ABBREVS) throw DwarfParseException("abbrev 条目过多")
                val code = r.uleb()
                if (code == 0L) break
                val tag = r.uleb().toInt()
                val hasChildren = r.u8() == 1
                val attrs = ArrayList<AttrSpec>()
                while (true) {
                    val attr = r.uleb().toInt()
                    val form = r.uleb().toInt()
                    if (attr == 0 && form == 0) break
                    val value: Long? = if (form == DW.FORM.implicit_const) r.sleb() else null
                    attrs += AttrSpec(attr, form, value)
                }
                map[code] = AbbrevDecl(code, tag, hasChildren, attrs)
            }
            return AbbrevTable(map)
        }

        const val MAX_ABBREVS = 1 shl 20
    }
}
