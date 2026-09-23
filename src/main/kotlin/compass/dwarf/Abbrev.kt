package compass.dwarf

import compass.core.ByteCursor

data class AbbrevAttr(val name: Int, val form: Int)
data class AbbrevDecl(val code: Long, val tag: Int, val hasChildren: Boolean, val attrs: List<AbbrevAttr>)

/** 一个 .debug_abbrev 偏移对应一棵 abbrev 集合；CU 通过 debug_abbrev_offset 引用。 */
class AbbrevTable(val decls: Map<Long, AbbrevDecl>) {
    companion object {
        /**
         * 从 sectionOffset 开始读取一个 abbrev 集合（直到 code==0）。
         * 用 memo 缓存：同一 section 偏移只解析一次。
         */
        fun parseAt(c: ByteCursor, sectionOffset: Long, memo: MutableMap<Long, AbbrevTable?>): AbbrevTable? {
            memo[sectionOffset]?.let { return it }
            return try {
                c.jump(sectionOffset, 0)
                val decls = LinkedHashMap<Long, AbbrevDecl>()
                while (true) {
                    val code = c.uleb128()
                    if (code == 0L) break
                    val tag = c.uleb128().toInt()
                    val hasChildren = c.u8() == 1
                    val attrs = ArrayList<AbbrevAttr>()
                    while (true) {
                        val aname = c.uleb128().toInt()
                        val aform = c.uleb128().toInt()
                        if (aname == 0 && aform == 0) break
                        attrs += AbbrevAttr(aname, aform)
                    }
                    decls[code] = AbbrevDecl(code, tag, hasChildren, attrs)
                }
                AbbrevTable(decls).also { memo[sectionOffset] = it }
            } catch (e: Exception) {
                memo[sectionOffset] = null
                null
            }
        }
    }
}
