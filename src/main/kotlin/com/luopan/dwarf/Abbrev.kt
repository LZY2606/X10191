package com.luopan.dwarf

/** 一条 abbrev 声明。attrs = (attrName, form, implicitConst)。 */
class AbbrevDecl(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val attrs: List<Triple<Int, Int, Long?>>,
)

class AbbrevTable(val decls: Map<Long, AbbrevDecl>)

object AbbrevParser {
    /** 从 .debug_abbrev 的某个偏移解析一张表，到 code=0 结束。 */
    fun parse(section: ByteArray, offset: Int, jumps: JumpBudget): AbbrevTable {
        jumps.jump()
        val b = Binary(section, 0, section.size)
        b.seek(offset)
        val map = LinkedHashMap<Long, AbbrevDecl>()
        while (true) {
            val code = b.uleb()
            if (code == 0L) break
            val tag = b.uleb().toInt()
            val hasChildren = b.u1() == 1
            val attrs = ArrayList<Triple<Int, AttrForm, Long?>>()
            while (true) {
                val name = b.uleb().toInt()
                val form = b.uleb().toInt()
                if (name == 0 && form == 0) break
                val implicit = if (form == DwarfForm.IMPLICIT_CONST) b.sleb() else null
                attrs.add(Triple(name, form, implicit))
            }
            map[code] = AbbrevDecl(code, tag, hasChildren, attrs)
        }
        return AbbrevTable(map)
    }
}

typealias AttrForm = Int
