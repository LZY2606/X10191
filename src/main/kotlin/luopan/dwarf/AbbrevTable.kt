package luopan.dwarf

/** 一条 abbreviation：tag + hasChildren + 属性列表（含 DW_FORM_implicit_const 的立即值）。 */
data class AbbrevAttr(val attr: Int, val form: Int, val implicitConst: Long?)

data class Abbreviation(val code: Long, val tag: Int, val hasChildren: Boolean,
                        val attrs: List<AbbrevAttr>)

class AbbrevTable(private val byCode: Map<Long, Abbreviation>) {
    fun get(code: Long): Abbreviation? = byCode[code]
}

/** .debug_abbrev 解析。每个 CU 有自己的 abbrev 起点。 */
object AbbrevParser {
    fun parse(data: ByteArray?, offset: Long): AbbrevTable {
        if (data == null) return AbbrevTable(emptyMap())
        val r = ByteReader.of(data, true)
        try {
            r.seek(offset.toInt())
        } catch (e: DwarfBoundsException) {
            return AbbrevTable(emptyMap())
        }
        val map = LinkedHashMap<Long, Abbreviation>()
        try {
            while (r.remaining() > 0) {
                val (code, _) = r.uleb128()
                if (code == 0L) {
                    if (map.isNotEmpty()) break
                    continue
                }
                val (tag, _) = r.uleb128()
                val hasChildren = r.u8() == 1
                val attrs = ArrayList<AbbrevAttr>()
                while (true) {
                    val (attr, _) = r.uleb128()
                    val (form, _) = r.uleb128()
                    if (attr == 0L && form ==0L) break
                    var implicit: Long? = null
                    if (form == DwForm.IMPLICIT_CONST.toLong()) implicit = r.sleb128().first
                    attrs += AbbrevAttr(attr.toInt(), form.toInt(), implicit)
                }
                map[code] = Abbreviation(code, tag.toInt(), hasChildren, attrs)
            }
        } catch (e: DwarfBoundsException) {
            // 截断的 abbrev：已成功读出的仍可用
        }
        return AbbrevTable(map)
    }
}
