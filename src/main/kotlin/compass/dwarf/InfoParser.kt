package compass.dwarf

import compass.core.ByteCursor
import compass.core.CursorException

class InfoParser(
    private val sections: DebugSections,
    private val formReader: FormReader,
    private val lineParser: LineProgramParser,
    private val rangeParser: RangeListParser
) {
    private val abbrevMemo = HashMap<Long, AbbrevTable?>()

    fun parseAll(): List<CompUnit> {
        val units = ArrayList<CompUnit>()
        parseSection(".debug_info", units)
        parseSection(".debug_types", units)
        return units
    }

    private fun parseSection(sectionName: String, units: MutableList<CompUnit>) {
        val c = sections.cursor(sectionName) ?: return
        c.pos = 0
        while (c.remaining() > 0) {
            val unitStart = c.pos
            val unit = try {
                parseOne(c, sectionName, unitStart.toLong())
            } catch (e: CursorException) {
                CompUnit(unitStart.toLong(), 0, 0, false, 0, 0, 0, null,
                    "(损坏单元)", "", null, null, null, null, null, null, null,
                    listOf(ParseIssue(ParseIssue.Severity.ERROR, "cu.truncated",
                        "编译单元头/体解析失败: ${e.message}", sectionName, unitStart.toLong())),
                    corrupted = true)
            }
            units += unit
            // 用 unit_length 精确定位下一单元，避免依赖已经错位的游标
            val hdr = if (unit.dwarf64) 12 else 4
            val next = unitStart + hdr + unit.unitLength.toInt()
            if (unit.unitLength <= 0 || next <= c.pos || next > c.limit) {
                if (unit.corrupted) break
                c.pos = if (next in (c.pos + 1)..c.limit) next else c.limit
                if (c.pos >= c.limit) break
            } else {
                c.pos = next
            }
        }
    }

    private fun parseOne(c: ByteCursor, sectionName: String, unitStart: Long): CompUnit {
        val len0 = c.u32()
        val dwarf64 = len0 == 0xffffffffL
        val unitLength = if (dwarf64) c.i64() else len0
        val unitEnd = c.pos - (if (dwarf64) 12 else 4) + unitLength.toInt()
        if (unitEnd > c.limit || unitLength <= 0) throw CursorException("CU 长度非法: $unitLength")

        val version = c.u16()
        var unitType = UnitType5.COMPILE
        var addressSize = 0
        var abbrevOffset: Long
        if (version >= 5) {
            unitType = c.u8()
            addressSize = c.u8()
            abbrevOffset = if (dwarf64) c.i64() else c.u32()
        } else {
            abbrevOffset = if (dwarf64) c.i64() else c.u32()
            addressSize = c.u8()
        }
        var dwoId: Long? = null
        if (sectionName == ".debug_types" || (version >= 5 && (unitType == UnitType5.TYPE || unitType == UnitType5.SPLIT_TYPE))) {
            if (dwarf64) c.i64() else c.u32() // type_signature
            if (dwarf64) c.i64() else c.u32() // type_offset
        }
        if (unitType == UnitType5.SKELETON && version >= 5) {
            dwoId = if (dwarf64) c.i64() else c.u32()
        }

        val issues = ArrayList<ParseIssue>()
        val ctx = FormContext(version, dwarf64, addressSize, unitStart.toLong(), null, null, null, issues)
        val abbrev = AbbrevTable.parseAt(
            sections.cursor(".debug_abbrev") ?: throw CursorException("缺少 .debug_abbrev"),
            abbrevOffset, abbrevMemo
        ) ?: run {
            return CompUnit(unitStart.toLong(), unitLength, version, dwarf64, unitType, addressSize,
                abbrevOffset, null, "(abbrev 不可读)", "", null, null, null, null, null, null, null,
                listOf(ParseIssue(ParseIssue.Severity.ERROR, "cu.abbrev",
                    "abbrev 表 @0x${abbrevOffset.toString(16)} 不可读", ".debug_abbrev", abbrevOffset)),
                corrupted = true)
        }

        var dieCount = 0
        fun parseDieTree(): Die? {
            val off = unitStart + c.pos
            val code = c.uleb128()
            if (code == 0L) return null
            val decl = abbrev.decls[code] ?: throw CursorException("abbrev code $code 未在表中定义 @${off}")
            val attrs = LinkedHashMap<Int, AttrValue>()
            val die = Die(unitStart + c.pos, decl.tag, attrs)
            for (aa in decl.attrs) {
                val v = formReader.read(c, aa.form, ctx)
                attrs[aa.name] = v
                when (aa.name) {
                    Attr.STR_OFFSETS_BASE, Attr.DW_AT_GNU_str_offsets_base -> ctx.strOffsetsBase = (v as? AttrValue.SecOff)?.offset ?: v.asLong()
                    Attr.ADDR_BASE, Attr.DW_AT_GNU_addr_base -> ctx.addrBase = (v as? AttrValue.SecOff)?.offset ?: v.asLong()
                    Attr.RANGES_BASE -> ctx.rangesBase = (v as? AttrValue.SecOff)?.offset ?: v.asLong()
                }
            }
            if (++dieCount > MAX_DIES) throw CursorException("单 CU DIE 数量超过上限 $MAX_DIES")
            if (decl.hasChildren) {
                var depth = 0
                while (true) {
                    if (c.pos >= unitEnd) throw CursorException("DIE children 未闭合")
                    val child = parseDieTree() ?: break
                    child.parent = die
                    die.children += child
                    if (++depth > MAX_CHILDREN) throw CursorException("单 DIE 子节点超过上限")
                }
            }
            return die
        }

        val root: Die?
        var corrupted = false
        try {
            root = parseDieTree()
        } catch (e: CursorException) {
            corrupted = true
            issues += ParseIssue(ParseIssue.Severity.ERROR, "cu.dies",
                "DIE 树解析中断（已隔离，其余 CU 不受影响）: ${e.message}", sectionName, c.pos.toLong())
            // root 无法可靠恢复时，尝试保留 null
            return finalizedUnit(unitStart, unitLength, version, dwarf64, unitType, addressSize,
                abbrevOffset, dwoId, null, ctx, issues, corrupted = true, lineParser, rangeParser)
        }

        return finalizedUnit(unitStart, unitLength, version, dwarf64, unitType, addressSize,
            abbrevOffset, dwoId, root, ctx, issues, corrupted = false, lineParser, rangeParser)
    }

    @Suppress("LongParameterList")
    private fun finalizedUnit(
        unitStart: Int, unitLength: Long, version: Int, dwarf64: Boolean, unitType: Int,
        addressSize: Int, abbrevOffset: Long, dwoIdIn: Long?, root: Die?,
        ctx: FormContext, corrupted: Boolean,
        lineParser: LineProgramParser, rangeParser: RangeListParser
    ): CompUnit {
        var name = ""
        var compDir = ""
        var language: Long? = null
        var stmtList: Long? = null
        var dwoName: String? = null
        var dwoId = dwoIdIn
        root?.attrs?.let { a ->
            name = a[Attr.NAME]?.asString() ?: ""
            compDir = a[Attr.COMP_DIR]?.asString() ?: ""
            language = a[Attr.LANGUAGE]?.asLong()
            stmtList = (a[Attr.STMT_LIST] as? AttrValue.SecOff)?.offset ?: a[Attr.STMT_LIST]?.asLong()
            dwoName = a[Attr.DW_AT_dwo_name]?.asString() ?: a[Attr.DW_AT_GNU_dwo_name]?.asString()
            dwoId = dwoId ?: (a[Attr.DWO_ID]?.asLong() ?: a[Attr.DW_AT_GNU_dwo_id]?.asLong())
        }
        val lp = if (!corrupted && stmtList != null) lineParser.parseAt(stmtList!!) else null
        if (lp?.truncated == true) {
            ctx.issues += ParseIssue(ParseIssue.Severity.WARNING, "cu.line_truncated",
                "CU 关联的 line program 损坏，行号结论可信度下降", ".debug_line", stmtList ?: -1)
        }
        return CompUnit(unitStart.toLong(), unitLength, version, dwarf64, unitType, addressSize,
            abbrevOffset, dwoId, name, compDir, language, root, lp, stmtList,
            ctx.strOffsetsBase, ctx.addrBase, ctx.rangesBase, dwoName, ctx.issues.toList(),
            corrupted || lp?.truncated == true)
    }

    companion object {
        const val MAX_DIES = 500_000
        const val MAX_CHILDREN = 200_000
        const val MAX_DEPTH_HINT = 256
    }
}
