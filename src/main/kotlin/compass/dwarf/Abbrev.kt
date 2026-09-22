package compass.dwarf

/** 一条 abbrev 声明。 */
class AbbrevDecl(
    val code: Long,
    val tag: Long,
    val hasChildren: Boolean,
    val attrs: List<Pair<Long, Long>>, // (attr, form)
)

/** .debug_abbrev 全表，按每个声明区的起始偏移索引。 */
class AbbrevTable(private val decls: Map<Long, AbbrevDecl>, val offset: Long) {
    fun decl(code: Long): AbbrevDecl? = decls[code]
}

object AbbrevParser {
    /**
     * 从给定偏移解析一个 abbrev 声明区，直到 code=0。
     * 同一 .debug_abbrev 段可以包含多个 CU 的声明区，所以不假设从 0 开始、不跨区缓存错位数据。
     */
    fun parse(blob: SectionBlob?, startOffset: Long): AbbrevTable? {
        if (blob == null) return null
        val view = blob.view()
        if (startOffset < 0 || startOffset >= view.size.toLong()) return null
        val r = view.reader(startOffset.toInt())
        val map = linkedMapOf<Long, AbbrevDecl>()
        try {
            while (true) {
                val code = r.uleb128()
                if (code == 0L) break
                val tag = r.uleb128()
                val child = r.u8() == DW.CHILDREN_yes
                val attrs = mutableListOf<Pair<Long, Long>>()
                while (true) {
                    val attr = r.uleb128()
                    val form = r.uleb128()
                    if (attr == 0L && form == 0L) break
                    attrs.add(attr to form)
                    // DW_FORM_implicit_const 额外跟随一个 sleb
                    if (form == DW.FORM_implicit_const.toLong()) r.leb128()
                }
                if (map.containsKey(code)) {
                    // 重复 code 是数据损坏；保留先到者并停止
                    break
                }
                map[code] = AbbrevDecl(code, tag, child, attrs)
            }
        } catch (e: DwarfBoundsException) {
            return AbbrevTable(map, startOffset) // 已解析的仍可用，上层会记录 warning
        }
        return AbbrevTable(map, startOffset)
    }
}
