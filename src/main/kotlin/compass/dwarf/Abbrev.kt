package compass.dwarf

data class AbbrevAttr(val at: Int, val form: Int, val implicitConst: Long? = null)

class AbbrevEntry(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val attrs: List<AbbrevAttr>,
)

/** 解析 .debug_abbrev 中的一张 abbrev 表。 */
object AbbrevParser {
    fun parse(section: ByteArray, offset: Long, limits: Limits): Map<Long, AbbrevEntry> {
        if (offset < 0 || offset >= section.size)
            throw DwarfException("abbrev 偏移越界: ${hexU(offset)} (section=${section.size})")
        val c = Cursor(section, offset.toInt(), section.size)
        val out = LinkedHashMap<Long, AbbrevEntry>()
        var count = 0
        while (true) {
            if (++count > limits.maxAbbrevEntries) throw DwarfException("abbrev 条目超过限制")
            val code = c.uleb()
            if (code == 0L) break
            val tag = c.uleb()
            if (tag > 0xffff) throw DwarfException("abbrev tag 异常: $tag")
            val hasChildren = c.u8() != 0
            val attrs = ArrayList<AbbrevAttr>()
            while (true) {
                if (attrs.size > limits.maxAttrsPerDie) throw DwarfException("abbrev 属性超过限制")
                val at = c.uleb()
                val form = c.uleb()
                if (at == 0L && form == 0L) break
                if (at > 0xffff || form > 0xffff) throw DwarfException("abbrev 属性/表单异常")
                val implicit = if (form.toInt() == Dw.FORM_implicit_const) c.sleb() else null
                attrs.add(AbbrevAttr(at.toInt(), form.toInt(), implicit))
            }
            out[code] = AbbrevEntry(code, tag.toInt(), hasChildren, attrs)
        }
        return out
    }
}
