package compass.dwarf

/** 单个 DIE 形状：tag + 属性 (attr, form) 序列；hasChildren 决定是否有 DIE 子节点。 */
class AbbrevDecl(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val attrs: List<Pair<Int, Int>>,
    val implicitConst: Map<Int, Long>
)

/** .debug_abbrev 集合：表基址偏移 -> (code -> 声明)。 */
class AbbrevSet(val tables: Map<Long, Map<Long, AbbrevDecl>>) {
    fun get(base: Long, code: Long): AbbrevDecl? = tables[base]?.get(code)
}

/**
 * 解析整个 .debug_abbrev：节由若干张表顺序排列，每表以一个 code=0 字节结束。
 * 表起点由 CU 的 debug_abbrev_offset 指定。我们顺序扫描并按表分组。
 */
fun parseAbbrev(data: ByteArray?): Pair<Map<Long, Map<Long, AbbrevDecl>>, List<String>> {
    val errors = mutableListOf<String>()
    val tables = LinkedHashMap<Long, Map<Long, AbbrevDecl>>()
    if (data == null || data.isEmpty()) return tables to errors
    val r = ByteReader(data)
    var tableGuard = 0
    while (r.remaining > 0 && tableGuard++ < 100_000) {
        val tableStart = r.pos.toLong()
        val decls = LinkedHashMap<Long, AbbrevDecl>()
        var codeGuard = 0
        while (r.remaining > 0 && codeGuard++ < 1_000_000) {
            val start = r.pos
            val code = r.readULEB128()
            if (code == 0L) break
            val tag = r.readULEB128().toInt()
            val hasChildren = r.readByte() == 1
            val attrs = ArrayList<Pair<Int, Int>>()
            val implicit = HashMap<Int, Long>()
            var pairGuard = 0
            while (true) {
                if (pairGuard++ > 100_000) { errors += "abbrev at $start: attr pairs too long"; return tables to errors }
                val attr = r.readULEB128().toInt()
                val form = r.readULEB128().toInt()
                if (attr == 0 && form == 0) break
                attrs += attr to form
                if (form == DW_FORM.IMPLICIT_CONST) implicit[attr] = r.readSLEB128()
            }
            decls[code] = AbbrevDecl(code, tag, hasChildren, attrs, implicit)
        }
        if (decls.isNotEmpty()) tables[tableStart] = decls
    }
    return tables to errors
}
