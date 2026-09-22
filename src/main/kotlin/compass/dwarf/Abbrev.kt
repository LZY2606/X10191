package compass.dwarf

import compass.ByteReader
import compass.DwarfFormatException
import compass.DwarfTruncationException

/**
 * Parse the abbreviation table that begins at [tableOffset] in .debug_abbrev.
 * The abbrev stream is shared by many CUs; an abbrev table is bounded implicitly
 * by the zero declaration terminator, so the reader end defaults to the section end.
 */
object AbbrevParser {

    fun parse(section: ByteArray, tableOffset: Long, littleEndian: Boolean = true): List<AbbrevDecl> {
        if (tableOffset < 0 || tableOffset >= section.size) {
            throw DwarfTruncationException("abbrev offset $tableOffset out of section (size=${section.size})")
        }
        val r = ByteReader(section, tableOffset.toInt(), section.size, littleEndian)
        val decls = mutableListOf<AbbrevDecl>()
        var guard = 0
        while (!r.exhausted) {
            if (++guard > 1_000_000) throw DwarfFormatException("abbrev table too large")
            val code = r.uleb128()
            if (code == 0UL) break
            val tag = r.uleb128().toInt()
            val hasChildren = r.u8() == 1
            val attrs = mutableListOf<Pair<Int, Int>>()
            var implicitConst: Long? = null
            var attrGuard = 0
            while (true) {
                if (++attrGuard > 100_000) throw DwarfFormatException("abbrev has too many attrs")
                val attr = r.uleb128().toInt()
                val form = r.uleb128().toInt()
                if (attr == 0 && form == 0) break
                if (form == DW.FORM_IMPLICIT_CONST) {
                    implicitConst = r.sleb128()
                }
                attrs += attr to form
            }
            decls += AbbrevDecl(code, tag, hasChildren, attrs, implicitConst)
        }
        return decls
    }
}
