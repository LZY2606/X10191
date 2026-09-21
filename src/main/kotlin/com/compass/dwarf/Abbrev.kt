package com.compass.dwarf

/** One abbreviation declaration: tag + ordered (attr, form, implicitConst). */
data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean,
                      val attrs: List<Triple<Int, Long, Long>>)

/**
 * One .debug_abbrev table, keyed by abbreviation code. DWARF5 tables are per
 * CU; DWARF4 shares one table but keying by table offset keeps both correct.
 */
class AbbrevTable(val decls: Map<Long, AbbrevDecl>)

object AbbrevReader {
    /** Parses a single abbreviation table starting at [start], stopping at the null decl. */
    fun read(buf: Buf, start: Int): AbbrevTable {
        val map = linkedMapOf<Long, AbbrevDecl>()
        buf.seek(start)
        var safety = 0
        while (true) {
            if (++safety > Limits.MAX_ABBREV_DECLS) throw ParseException("abbrev table too many declarations")
            val code = buf.uleb().toLong()
            if (code == 0L) break
            val tag = buf.uleb().toInt()
            val hasChildren = buf.u8() == DW_CHILDREN_yes
            val attrs = mutableListOf<Triple<Int, Long, Long>>()
            var attrGuard = 0
            while (true) {
                if (++attrGuard > Limits.MAX_ATTRS) throw ParseException("abbrev $code too many attributes")
                val name = buf.uleb().toInt()
                var form = buf.uleb().toLong()
                var implicit = 0L
                if (form == DW_FORM_indirect.toLong()) form = buf.uleb().toLong()
                if (form == DW_FORM_implicit_const.toLong()) implicit = buf.sleb()
                if (name == 0 && form == 0L) break
                attrs += Triple(name, form, implicit)
            }
            map[code] = AbbrevDecl(code, tag, hasChildren, attrs)
        }
        return AbbrevTable(map)
    }
}

object Limits {
    const val MAX_DIES_PER_CU = 200_000
    const val MAX_DEPTH = 128
    const val MAX_ABBREV_DECLS = 500_000
    const val MAX_ATTRS = 1024
    const val MAX_RANGES = 1_000_000
    const val MAX_SEQUENCES = 100_000
    const val MAX_REF_HOPS = 128
}
