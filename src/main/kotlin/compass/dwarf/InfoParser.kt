package compass.dwarf

/**
 * .debug_info 解析器。
 * 关键安全性质：
 *  - 每个 CU 都有自己的有界 [ByteView]，CU 外的读取立即失败；
 *  - 每个 form 都能精确决定自己占用的字节数，未知 form 立即“毒化”该 CU，
 *    已解析的 DIE 保留，游标不再前进，因此不会在错位状态继续产生伪 DIE；
 *  - ref_addr / ref1..4 全部换算成 .debug_info 全局偏移，查询阶段可直接跳转，
 *    且跳转次数、递归深度都有上限。
 */
class InfoParser(
    private val sectionBytes: Map<String, ByteArray>,
    private val abbrevTables: Map<Long, AbbrevTable>,
    private val lineParser: LineParser
) {
    private val diagnostics = mutableListOf<Diagnostic>()

    fun parse(): List<CompileUnit> {
        val infoBytes = sectionBytes[".debug_info"]
            ?: run {
                diagnostics += Diagnostic("INFO", "info", "无 .debug_info")
                return emptyList()
            }
        val units = mutableListOf<CompileUnit>()
        val c = Cursor(ByteView(infoBytes))
        while (c.remaining > 0) {
            val unitStart = c.pos
            val cu = parseUnit(infoBytes, c, unitStart, units.size)
            units += cu
            val next = (unitStart + cu.length + 12 - (if (cu.is64) 4 else 0)).toInt()
            c.seek(next)
        }
        return units
    }

    fun allDiagnostics(): List<Diagnostic> = diagnostics

    /** 解析 CU 头（DWARF4 与 DWARF5 两种形状）。 */
    private fun parseUnit(info: ByteArray, top: Cursor, start: Int, index: Int): CompileUnit {
        val diags = mutableListOf<Diagnostic>()
        var poisoned = false
        val head = Cursor(ByteView(info, start, minOf(info.size - start, 100)))
        val lengthWord = head.u32()
        val is64 = lengthWord == 0xffffffffL
        val length: Long
        val version: Int
        val unitType: Int
        val addressSize: Int
        val abbrevOffset: Long
        if (is64) {
            length = head.u64()
            version = head.u16()
            unitType = if (version >= 5) head.u8() else 1
            addressSize = head.u8()
            abbrevOffset = head.u64()
        } else {
            length = lengthWord
            version = head.u16()
            if (version >= 5) {
                unitType = head.u8()
                addressSize = head.u8()
                abbrevOffset = head.u32()
            } else {
                unitType = 1
                abbrevOffset = head.u32()
                addressSize = head.u8()
            }
        }
        val headerLen = head.pos
        val total = (if (is64) 12 else 4) + length.toInt()
        if (start + total > info.size || addressSize !in setOf(1, 2, 4, 8) || version !in 2..5) {
            diags += Diagnostic("ERROR", "cu:$index", "CU 头越界或不支持: ver=$version as=$addressSize len=$length")
            val root = Die(start.toLong(), 0, 0, 0)
            return brokenUnit(start, length, is64, version, unitType, addressSize, abbrevOffset,
                root = root, flat = listOf(root), diags = diags, poisoned = true)
        }
        val body = ByteView(info, start + headerLen, total - headerLen)
        val cuStartGlobal = start.toLong()

        val table = abbrevTables[abbrevOffset]
        if (table == null) {
            diags += Diagnostic("ERROR", "cu:$index", "abbrev 偏移 $abbrevOffset 无对应表（可能 section 损坏）")
            return brokenUnit(start, length, is64, version, unitType, addressSize, abbrevOffset,
                root = null, flat = emptyList(), diags = diags, poisoned = true)
        }

        val ctx = UnitCtx(index, version, is64, addressSize, cuStartGlobal, body, table, diags)
        val diesFlat = mutableListOf<Die>()
        var root: Die? = null
        val c = Cursor(body)
        val stack = ArrayDeque<Pair<Die, Int>>() // die -> 该层剩余子节点计数（-1 表示未知）
        var depth = 0
        try {
            while (c.remaining > 0) {
                val dieOff = cuStartGlobal + c.pos
                val code = c.uleb()
                if (code == 0L) {
                    if (stack.isNotEmpty()) stack.removeLast()
                    depth = (depth - 1).coerceAtLeast(0)
                    continue
                }
                val decl = table.get(code)
                if (decl == null) {
                    diags += Diagnostic("ERROR", "cu:$index", "abbrev code=$code 在偏移 $dieOff 未定义，CU 隔离")
                    poisoned = true
                    break
                }
                val die = Die(dieOff, decl.tag, depth, code)
                for ((attr, form, implicit) in decl.spec) {
                    if (attr == 0 && form == 0) break
                    val value = readAttrValue(attr, form, implicit, c, ctx)
                    die.attrs += DAttr(attr, form, value)
                }
                diesFlat += die
                if (root == null) root = die
                if (stack.isNotEmpty()) stack.last().first.children += die
                if (decl.hasChildren) {
                    stack.addLast(die to -1)
                    depth++
                }
            }
        } catch (e: UnknownFormException) {
            diags += Diagnostic("ERROR", "cu:$index", "未知 form=0x${e.form.toString(16)} @die=$${e.offset.toString(16)}，CU 在该点隔离（游标不前进）")
            poisoned = true
        } catch (e: CursorException) {
            diags += Diagnostic("ERROR", "cu:$index", "DIE 流越界: ${e.message}，已解析 ${diesFlat.size} 个 DIE 保留")
            poisoned = true
        }
        diesFlat.forEach { it.cuIndex = index }

        // 第二次扫描：字符串 / addrx / 名称等上下文相关解析
        val resolve = PostResolver(ctx, sectionBytes, diags)
        resolve.setRoot(root)
        resolve.resolveAll(diesFlat)

        val rootDie = root
        val lowPc = rootDie?.num(DW.AT_LOW_PC)
        val rangeResolver = RangeResolver(sectionBytes, diags, ctx, resolve)
        val ranges = rangeResolver.rangesFor(rootDie)
        val dieRanges = LinkedHashMap<Long, List<AddrRange>>()
        for (d in diesFlat) {
            if (d.tag == DW.TAG_SUBPROGRAM || d.tag == DW.TAG_INLINED_SUBROUTINE || d.tag == DW.TAG_LEXICAL_BLOCK) {
                val rr = rangeResolver.rangesFor(d)
                if (rr.isNotEmpty()) dieRanges[d.offset] = rr
            }
        }
        val dwoName = rootDie?.let { resolve.stringAttr(it, DW.AT_DWO_NAME) ?: resolve.stringAttr(it, DW.AT_GNU_DWO_NAME) }
        val dwoId = rootDie?.num(DW.AT_GNU_DWO_ID)
        val name = rootDie?.let { resolve.stringAttr(it, DW.AT_NAME) }
        val compDir = rootDie?.let { resolve.stringAttr(it, DW.AT_COMP_DIR) }
        val producer = rootDie?.let { resolve.stringAttr(it, DW.AT_PRODUCER) }
        val stmtList = rootDie?.num(DW.AT_STMT_LIST)

        var lineProgram: LineProgram? = null
        if (stmtList != null && dwoName == null) {
            lineProgram = lineParser.parse(sectionBytes, stmtList, version, addressSize, index, diags)
        }

        return CompileUnit(
            globalOffset = start.toLong(), length = length, version = version, is64 = is64,
            unitType = unitType, addressSize = addressSize, abbrevOffset = abbrevOffset,
            root = rootDie, diesFlat = diesFlat, ranges = ranges, lineProgram = lineProgram,
            dieRanges = dieRanges,
            dwoName = dwoName, dwoId = dwoId, name = name, compDir = compDir, producer = producer,
            language = rootDie?.num(DW.AT_LANGUAGE), stmtList = stmtList, lowPc = lowPc,
            poisoned = poisoned, diagnostics = diags
        )
    }

    private fun brokenUnit(
        start: Int, length: Long, is64: Boolean, version: Int, unitType: Int, addressSize: Int,
        abbrevOffset: Long, root: Die?, flat: List<Die>, diags: MutableList<Diagnostic>, poisoned: Boolean
    ) = CompileUnit(
        start.toLong(), length, version, is64, unitType, addressSize, abbrevOffset, root, flat,
        emptyList(), null, null, null, null, null, null, null, null, poisoned, diags
    )

    class UnitCtx(
        val cuIndex: Int,
        val version: Int,
        val is64: Boolean,
        val addressSize: Int,
        val cuGlobalStart: Long,
        val body: ByteView,
        val table: AbbrevTable,
        val diags: MutableList<Diagnostic>
    ) {
        val refSize: Int get() = if (is64) 8 else 4
    }

    class UnknownFormException(val form: Int, val offset: Long) : RuntimeException()

    /**
     * 读取单个属性值。返回原始包装类型（Raw.* / Long / Boolean / ByteArray）。
     * FORM_INDIRECT 有跳转次数限制；未知 form 直接抛出，调用方隔离整个 CU。
     */
    private fun readAttrValue(attr: Int, formIn: Int, implicit: Long?, c: Cursor, ctx: UnitCtx, hops: Int = 0): Any? {
        var form = formIn
        if (form == DW.FORM_INDIRECT) {
            if (hops >= 8) throw CursorException("DW_FORM_indirect 跳转过深")
            form = c.uleb().toInt()
            return readAttrValue(attr, form, null, c, ctx, hops + 1)
        }
        return when (form) {
            DW.FORM_ADDR -> readAddr(c, ctx)
            DW.FORM_DATA1, DW.FORM_REF1 -> c.u8().toLong()
            DW.FORM_DATA2, DW.FORM_REF2 -> c.u16().toLong()
            DW.FORM_DATA4, DW.FORM_REF4 -> c.u32()
            DW.FORM_DATA8, DW.FORM_REF8, DW.FORM_REF_SIG8 -> c.u64()
            DW.FORM_SDATA -> c.sleb()
            DW.FORM_UDATA, DW.FORM_REF_UDATA -> c.uleb()
            DW.FORM_STRING -> {
                val s = c.pos
                val v = c.view.cstring(s)
                c.seek(s + v.toByteArray(Charsets.UTF_8).size + 1)
                v
            }
            DW.FORM_STRP -> Raw.StrPtr(readFixed(c, ctx.refSize))
            DW.FORM_LINE_STRP -> Raw.StrPtr(-(readFixed(c, ctx.refSize)) - 1) // 负数标记 .debug_line_str
            DW.FORM_BLOCK1 -> Raw.Blob(c.take(c.u8()))
            DW.FORM_BLOCK2 -> Raw.Blob(c.take(c.u16()))
            DW.FORM_BLOCK4 -> Raw.Blob(c.take(c.u32().toInt()))
            DW.FORM_BLOCK -> Raw.Blob(c.take(c.uleb().toInt()))
            DW.FORM_EXPRLOC -> Raw.Blob(c.take(c.uleb().toInt()))
            DW.FORM_FLAG -> c.u8() != 0
            DW.FORM_FLAG_PRESENT -> true
            DW.FORM_IMPLICIT_CONST -> implicit ?: 0L
            DW.FORM_SEC_OFFSET -> readFixed(c, ctx.refSize)
            DW.FORM_REF_ADDR -> {
                val off = readFixed(c, ctx.refSize)
                Raw.DieRef(off)
            }
            DW.FORM_DATA16 -> Raw.Blob(c.take(16))
            DW.FORM_STRX, DW.FORM_GNU_STRX -> Raw.StrIndex(c.uleb())
            DW.FORM_STRX1 -> Raw.StrIndex(c.u8().toLong())
            DW.FORM_STRX2 -> Raw.StrIndex(c.u16().toLong())
            DW.FORM_STRX3 -> Raw.StrIndex(c.u32())
            DW.FORM_STRX4 -> Raw.StrIndex(c.u64())
            DW.FORM_ADDRX, DW.FORM_GNU_ADDRX -> Raw.AddrIndex(c.uleb())
            DW.FORM_ADDRX1 -> Raw.AddrIndex(c.u8().toLong())
            DW.FORM_ADDRX2 -> Raw.AddrIndex(c.u16().toLong())
            DW.FORM_ADDRX3 -> Raw.AddrIndex(c.u32())
            DW.FORM_ADDRX4 -> Raw.AddrIndex(c.u64())
            DW.FORM_RNGLISTX, DW.FORM_GNU_RANGELISTX -> c.uleb() // 索引值，RangeResolver 用
            else -> throw UnknownFormException(form, ctx.cuGlobalStart + c.pos)
        }
    }

    private fun readAddr(c: Cursor, ctx: UnitCtx): Long = readFixed(c, ctx.addressSize)

    private fun readFixed(c: Cursor, size: Int): Long = when (size) {
        1 -> c.u8().toLong()
        2 -> c.u16().toLong()
        4 -> c.u32()
        8 -> c.u64()
        else -> throw CursorException("非法地址宽度 $size")
    }
}
