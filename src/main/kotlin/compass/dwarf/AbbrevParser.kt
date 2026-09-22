package compass.dwarf

/** 一条 abbrev 声明。implicitConst 携带其内联常量值。 */
data class AbbrevDecl(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val spec: List<Triple<Int, Int, Long?>> // attr, form, implicitConst
)

/** .debug_abbrev 解析结果：offset -> 该 CU 的 abbrev 表。 */
class AbbrevTable(val decls: Map<Long, AbbrevDecl>) {
    fun get(code: Long): AbbrevDecl? = decls[code]
}

object AbbrevParser {
    fun parse(bytes: ByteArray?): Pair<Map<Long, AbbrevTable>, List<Diagnostic>> {
        val diags = mutableListOf<Diagnostic>()
        if (bytes == null) return emptyMap<Long, AbbrevTable>() to diags
        val tables = LinkedHashMap<Long, AbbrevTable>()
        val c = Cursor(ByteView(bytes))
        while (c.remaining > 0) {
            val tableStart = c.pos
            val decls = LinkedHashMap<Long, AbbrevDecl>()
            while (true) {
                val code = try { c.uleb() } catch (e: CursorException) {
                    diags += Diagnostic("ERROR", "abbrev", "abbrev code 读取失败: ${e.message}")
                    return tables to diags
                }
                if (code == 0L) break
                val tag = c.uleb().toInt()
                val hasChildren = c.u8() == 1
                val spec = ArrayList<Triple<Int, Int, Long?>>()
                while (true) {
                    val attr = c.uleb().toInt()
                    val form = c.uleb().toInt()
                    var implicit: Long? = null
                    if (form == DW.FORM_IMPLICIT_CONST) implicit = c.sleb()
                    spec += Triple(attr, form, implicit)
                    if (attr == 0 && form == 0) break
                }
                decls[code] = AbbrevDecl(code, tag, hasChildren, spec)
            }
            tables[tableStart.toLong()] = AbbrevTable(decls)
        }
        return tables to diags
    }
}
