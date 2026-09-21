package compass.dwarf

import compass.elf.ByteReader
import compass.elf.ByteSlice
import compass.elf.ParseException

class AbbrevAttr(val name: Int, val form: Int, val implicitConst: Long)

class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

/**
 * One .debug_abbrev section is a flat sequence of declaration sets.
 * Each CU points at a set's byte offset; we parse lazily and cache per offset.
 */
class AbbrevTable(private val section: ByteSlice) {
    private val cache = HashMap<Long, Map<Long, AbbrevDecl>>()

    fun setAt(offset: Long): Map<Long, AbbrevDecl> = cache.getOrPut(offset) { parseSet(offset) }

    private fun parseSet(offset: Long): Map<Long, AbbrevDecl> {
        if (offset < 0 || offset >= section.length) {
            throw ParseException("abbrev offset 越界: $offset")
        }
        val r = ByteReader(section.data, section.offset + offset.toInt())
        val end = section.offset + section.length
        val out = LinkedHashMap<Long, AbbrevDecl>()
        var guard = 0
        while (true) {
            if (r.pos >= end) break
            val code = Leb.uleb(r, "abbrev code")
            if (code == 0L) break
            if (++guard > Limits.MAX_ABBREV_PER_SET) throw ParseException("abbrev 声明过多 (>${Limits.MAX_ABBREV_PER_SET})")
            val tag = Leb.uleb(r, "abbrev tag").toInt()
            val hasChildren = r.u8("DW_CHILDREN") == 1
            val attrs = ArrayList<AbbrevAttr>()
            var aguard = 0
            while (true) {
                if (++aguard > Limits.MAX_ATTRS_PER_DIE) throw ParseException("abbrev 属性过多")
                val name = Leb.uleb(r, "attr name").toInt()
                val form = Leb.uleb(r, "attr form").toInt()
                if (name == 0 && form == 0) break
                var implicit = 0L
                if (form == DW_FORM_implicit_const) implicit = Leb.sleb(r, "implicit_const")
                attrs.add(AbbrevAttr(name, form, implicit))
            }
            out[code] = AbbrevDecl(code, tag, hasChildren, attrs)
        }
        return out
    }
}

object Limits {
    const val MAX_DIE_DEPTH = 128
    const val MAX_DIES_PER_CU = 500_000
    const val MAX_ABBREV_PER_SET = 100_000
    const val MAX_ATTRS_PER_DIE = 4096
    const val MAX_LINE_ROWS = 2_000_000
    const val MAX_LINE_SEQUENCES = 100_000
    const val MAX_RANGES = 500_000
    const val MAX_REF_HOPS = 64
    const val MAX_UNITS = 100_000
    const val MAX_FORWARD_SKIP = 64 * 1024 * 1024
}
