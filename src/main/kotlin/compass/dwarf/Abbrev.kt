package compass.dwarf

data class AbbrevAttr(val name: Int, val form: Int, val implicitConst: Long?)

data class Abbrev(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

class IssueSink {
    val issues = mutableListOf<Triple<Int?, String, String>>() // (cuIndex?, level, message)
    fun error(cu: Int?, msg: String) { issues.add(Triple(cu, "error", msg)) }
    fun warn(cu: Int?, msg: String) { issues.add(Triple(cu, "warn", msg)) }
}

object AbbrevTable {
    fun parse(data: ByteArray, offset: Long, sink: IssueSink, cuIndex: Int?): Map<Long, Abbrev> {
        if (offset < 0 || offset >= data.size) {
            sink.error(cuIndex, "abbrev 偏移越界: 0x${offset.toString(16)} (表大小 0x${data.size.toString(16)})")
            return emptyMap()
        }
        val r = Reader(data, offset.toInt(), data.size)
        val out = LinkedHashMap<Long, Abbrev>()
        var guard = 0
        while (r.remaining > 0) {
            if (++guard > 100_000) { sink.error(cuIndex, "abbrev 表条目过多，已截断"); break }
            val code = r.uleb()
            if (code == 0L) break
            val tag = r.uleb().toInt()
            val hasChildren = r.u8() != 0
            val attrs = mutableListOf<AbbrevAttr>()
            while (true) {
                if (attrs.size >= Dwarf.MAX_ATTRS_PER_DIE) {
                    sink.error(cuIndex, "abbrev code=$code 属性数超限，已截断")
                    break
                }
                val name = r.uleb().toInt()
                val form = r.uleb().toInt()
                if (name == 0 && form == 0) break
                val implicit = if (form == Dwarf.FORM_IMPLICIT_CONST) r.sleb() else null
                if (form !in Dwarf.KNOWN_FORMS) {
                    sink.warn(cuIndex, "abbrev code=$code 含未知 form 0x${form.toString(16)} (attr 0x${name.toString(16)})，将按零长度隔离")
                }
                attrs.add(AbbrevAttr(name, form, implicit))
            }
            out[code] = Abbrev(code, tag, hasChildren, attrs)
        }
        return out
    }
}
