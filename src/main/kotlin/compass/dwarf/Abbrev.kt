package compass.dwarf

import compass.elf.ByteReader

data class AbbrevDecl(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    /** Pairs of (attribute, form); implicit const stores its value alongside via [implicitValues]. */
    val specs: List<Pair<Int, Int>>,
    val implicitValues: Map<Int, Long>
)

/** One .debug_abbrev table starting at a given offset; decl code 0 ends it. */
class AbbrevTable(val decls: Map<Long, AbbrevDecl>) {
    companion object {
        /**
         * Parse a table starting at [startOffset] in [section]. Reading is bounded:
         * malformed LEBs or runs without a terminator throw and isolate the table.
         */
        fun parse(section: ByteReader, startOffset: Long): AbbrevTable {
            val r = section.subReader(startOffset.toInt(), section.size - startOffset.toInt())
            val map = LinkedHashMap<Long, AbbrevDecl>()
            var guard = 0
            while (!r.atEnd) {
                if (++guard > Limits.MAX_ABBREV_DECLS)
                    throw DwarfParseException("abbrev table at $startOffset exceeds ${Limits.MAX_ABBREV_DECLS} decls")
                val code = r.uleb()
                if (code == 0L) break
                val tag = r.uleb().toInt()
                val hasChildren = r.u1() == 1
                val specs = ArrayList<Pair<Int, Int>>()
                val implicits = HashMap<Int, Long>()
                var attrGuard = 0
                while (true) {
                    if (++attrGuard > Limits.MAX_ATTRS_PER_DIE)
                        throw DwarfParseException("abbrev $code has too many attributes")
                    val attr = r.uleb().toInt()
                    val form = r.uleb().toInt()
                    if (attr == 0 && form == 0) break
                    specs.add(attr to form)
                    if (form == DW.FORM_implicit_const) implicits[attr] = r.sleb()
                }
                map[code] = AbbrevDecl(code, tag, hasChildren, specs, implicits)
            }
            return AbbrevTable(map)
        }
    }
}

class DwarfParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
