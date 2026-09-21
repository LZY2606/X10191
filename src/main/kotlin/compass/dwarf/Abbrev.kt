package compass.dwarf

import compass.BinReader

data class AbbrevDecl(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    /** attribute -> (form, implicit_const 或 null)。同一 attr 出现多次时保留全部（用 list）。 */
    val specs: List<Triple<Int, Int, Long?>>
)

data class AbbrevTable(val offset: Long, val decls: Map<Long, AbbrevDecl>)

object AbbrevParser {
    private const val MAX_DECLS = 100_000
    private const val MAX_ATTRS = 1000

    /** 从 .debug_abbrev 的 offset 处解析一张表（到 code=0 结束）。 */
    fun parseTable(section: ByteArray, offset: Long): AbbrevTable {
        val r = BinReader(section, offset.toIntSafeA())
        val decls = LinkedHashMap<Long, AbbrevDecl>()
        while (true) {
            if (decls.size > MAX_DECLS) throw DwarfParseError("abbrev 表条目过多")
            val code = r.uleb128().toLong()
            if (code == 0L) break
            val tag = r.uleb128().toInt()
            val hasChildren = r.u1() == 1
            val specs = mutableListOf<Triple<Int, Int, Long?>>()
            while (true) {
                if (specs.size > MAX_ATTRS) throw DwarfParseError("abbrev 属性过多")
                val attr = r.uleb128().toInt()
                var form = r.uleb128().toInt()
                var implicit: Long? = null
                if (form == DW_FORM_implicit_const) implicit = r.sleb128()
                if (attr == 0 && form == 0) break
                specs.add(Triple(attr, form, implicit))
            }
            if (decls.containsKey(code)) throw DwarfParseError("abbrev code=$code 重复，表已损坏")
            decls[code] = AbbrevDecl(code, tag, hasChildren, specs)
        }
        return AbbrevTable(offset, decls)
    }
}

internal fun Long.toIntSafeA(): Int {
    if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseError("偏移超出范围: $this")
    return toInt()
}
