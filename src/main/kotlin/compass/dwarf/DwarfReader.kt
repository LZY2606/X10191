package compass.dwarf

import compass.elf.ByteReader
import compass.elf.EndOfDataException
import compass.elf.ElfFile

data class ParsedDwarf(
    val cus: List<CompileUnit>,
    val notices: List<ParseNotice>,
)

/**
 * 纯 Kotlin DWARF4/5 解析器入口。
 *
 * 设计要点：
 *  - 每个 CU 独立隔离：一个 CU 的损坏（截断/未知 form/坏 abbrev）不影响其他 CU；
 *  - 未知 form 直接终止当前 CU（[UnknownFormException]），不猜测字节长度，杜绝游标错位；
 *  - 引用跳转、嵌套深度、变长整数均有上限。
 */
class DwarfReader(private val ctx: DwarfContext, private val fileSha: String) {

    companion object {
        const val MAX_DIE_DEPTH = 256
        const val MAX_REF_HOPS = 32
        const val MAX_CU_COUNT = 65536
    }

    private val notices = mutableListOf<ParseNotice>()

    fun parse(): ParsedDwarf {
        val info = ctx.info ?: return ParsedDwarf(emptyList(), listOf(
            ParseNotice("error", ".debug_info", 0, "section missing")
        ))
        val r = ByteReader(info, ctx.littleEndian)
        val cus = ArrayList<CompileUnit>()
        var guard = 0
        while (r.remaining() > 0) {
            if (cus.size >= MAX_CU_COUNT) {
                notices += ParseNotice("error", ".debug_info", r.pos.toLong(), "CU count limit $MAX_CU_COUNT reached")
                break
            }
            val cuStart = r.pos
            val cu = parseOneCu(r, cuStart, cus.size)
            cus += cu
            // 游标必须移动到 length 声明的精确边界：即便内部解析提前终止也不会错位。
            r.pos = (cuStart + cu.length).coerceAtMost(r.size)
            if (r.pos <= cuStart) break
            guard++
            if (guard > MAX_CU_COUNT) break
        }
        return ParsedDwarf(cus, notices)
    }

    private data class CuHeader(
        val totalLen: Long, val version: Int, val is64: Boolean,
        val unitType: Int, val addressSize: Int, val abbrevOffset: Long, val dwoId: Long?,
    )

    private fun readCuHeader(r: ByteReader, start: Int): CuHeader {
        val lenField = r.u32()
        val is64: Boolean
        val unitLength: Long
        if (lenField == 0xffffffff.toInt()) {
            is64 = true
            unitLength = r.u64()
        } else {
            is64 = false
            if (lenField <= 0) throw EndOfDataException("bad unit_length $lenField at $start")
            unitLength = lenField.toLong() and 0xffffffffL
        }
        val headerOverhead = if (is64) 12L else 4L
        if (unitLength <= 2 || start.toLong() + headerOverhead + unitLength > r.size.toLong()) {
            throw EndOfDataException("unit_length $unitLength at $start exceeds section")
        }
        val version = r.u16()
        if (version !in 2..5) throw EndOfDataException("unsupported DWARF version $version at $start")

        var unitType = Dw.UT_COMPILE
        var addressSize = 0
        var abbrevOffset = 0L
        var dwoId: Long? = null

        if (version >= 5) {
            unitType = r.u8()
            addressSize = r.u8()
            abbrevOffset = FormDecoder.readDwarfOffset(r, is64)
            if (unitType == Dw.UT_SKELETON || unitType == Dw.UT_SPLIT_COMPILE || unitType == Dw.UT_SPLIT_TYPE) {
                dwoId = r.u64()
            }
            if (unitType == Dw.UT_TYPE || unitType == Dw.UT_SPLIT_TYPE) {
                r.u64() // type signature
                FormDecoder.readDwarfOffset(r, is64) // type offset
            }
        } else {
            abbrevOffset = FormDecoder.readDwarfOffset(r, is64)
            addressSize = r.u8()
        }
        return CuHeader(headerOverhead + unitLength, version, is64, unitType, addressSize, abbrevOffset, dwoId)
    }

    private fun parseOneCu(sectionReader: ByteReader, start: Int, index: Int): CompileUnit {
        val cuNotices = mutableListOf<ParseNotice>()
        val dieEnd: Int
        var hdr: CuHeader? = null
        try {
            hdr = readCuHeader(sectionReader, start)
        } catch (e: EndOfDataException) {
            cuNotices += ParseNotice("error", ".debug_info", start.toLong(), "CU header unreadable: ${e.message}")
            // 无法确定长度时，终止整个 section 解析（不能安全跳过）。
            return emptyCu(index, start.toLong(), 1L, cuNotices)
        }
        val h = hdr
        dieEnd = (start + h.totalLen).toInt()

        val dc = CuDecodeContext(
            ctx = ctx, version = h.version, is64 = h.is64, addressSize = h.addressSize,
            strOffsetsBase = 0L, addrBase = 0L, rnglistsBase = 0L,
        )

        val abbrevBytes = if (h.unitType == Dw.UT_SPLIT_COMPILE || h.unitType == Dw.UT_SPLIT_TYPE)
            ctx.abbrevDwo ?: ctx.abbrev else ctx.abbrev
        val (abbrevs, an) = AbbrevParser.parseTable(abbrevBytes, h.abbrevOffset, ctx.littleEndian)
        cuNotices += an

        val dies = ArrayList<DieNode>()
        val root = parseDies(sectionReader, dc, abbrevs, start, dieEnd, index, cuNotices, dies)

        // 根 DIE 决定 str/addr/rnglist 基址与关键属性。
        root?.let { applyRootBases(it, dc) }

        val kind = unitKind(h.unitType, h.version)
        val stmtList = root?.numeric(Dw.AT_STMT_LIST)
        val (files, sequences, lineNotices) = parseLineProgram(dc, stmtList, h, index)
        cuNotices += lineNotices

        // 名称等字符串可能依赖 strOffsetsBase，根 DIE 读取后再回填。
        val compName = root?.attr(Dw.AT_NAME)?.let { materializeString(it, dc, cuNotices) }
        val compDir = root?.attr(Dw.AT_COMP_DIR)?.let { materializeString(it, dc, cuNotices) }

        return CompileUnit(
            index = index,
            fileSha = fileSha,
            sectionOffset = start.toLong(),
            length = h.totalLen,
            version = h.version,
            is64BitDwarf = h.is64,
            dwarfAddressSize = h.addressSize,
            unitKind = kind,
            abbrevOffset = h.abbrevOffset,
            dwoId = h.dwoId,
            compName = compName,
            compDir = compDir,
            stmtListOffset = stmtList,
            strOffsetsBase = dc.strOffsetsBase,
            addrBase = dc.addrBase,
            rnglistsBase = dc.rnglistsBase,
            dies = dies,
            sequences = sequences,
            files = files,
            notices = cuNotices,
        )
    }

    private fun emptyCu(index: Int, off: Long, len: Long, n: List<ParseNotice>) = CompileUnit(
        index = index, fileSha = fileSha, sectionOffset = off, length = len,
        version = 0, is64BitDwarf = false, dwarfAddressSize = 8, unitKind = UnitKind.OTHER,
        abbrevOffset = 0, dwoId = null, compName = null, compDir = null, stmtListOffset = null,
        strOffsetsBase = 0, addrBase = 0, rnglistsBase = 0,
        dies = emptyList(), sequences = emptyList(), files = emptyList(), notices = n,
    )

    private fun unitKind(t: Int, version: Int): UnitKind = when {
        version < 5 -> UnitKind.COMPILE
        t == Dw.UT_COMPILE -> UnitKind.COMPILE
        t == Dw.UT_SKELETON -> UnitKind.SKELETON
        t == Dw.UT_SPLIT_COMPILE -> UnitKind.SPLIT_COMPILE
        t == Dw.UT_PARTIAL -> UnitKind.PARTIAL
        t == Dw.UT_TYPE || t == Dw.UT_SPLIT_TYPE -> UnitKind.TYPE
        else -> UnitKind.OTHER
    }

    private fun applyRootBases(root: DieNode, dc: CuDecodeContext) {
        if (dc.version >= 5) {
            // DWARF5: 基址属性存在则使用，否则默认为 0。
            root.numeric(Dw.AT_STR_OFFSETS_BASE)?.let { dc.strOffsetsBase = it }
            root.numeric(Dw.AT_ADDR_BASE)?.let { dc.addrBase = it }
            root.numeric(Dw.AT_RNGLISTS)?.let { dc.rnglistsBase = it }
        } else {
            root.numeric(Dw.AT_GNU_ADDR_BASE)?.let { dc.addrBase = it }
        }
    }

    private fun materializeString(attr: DieAttr, dc: CuDecodeContext, n: MutableList<ParseNotice>): String? =
        when (val v = attr.value) {
            is FormValue.Str -> v.text
            else -> null
        }

    /**
     * 读 DIE 直到 null entry 回到 depth 0。
     * 任何未知 form / 截断都立即结束当前 CU：长度字段保证外层游标仍精确对齐下一个 CU。
     */
    private fun parseDies(
        r: ByteReader,
        dc: CuDecodeContext,
        abbrevs: Map<Long, AbbrevDecl>,
        cuStart: Int,
        dieEnd: Int,
        cuIndex: Int,
        cuNotices: MutableList<ParseNotice>,
        out: MutableList<DieNode>,
    ): DieNode? {
        var depth = 0
        var root: DieNode? = null
        // 各深度上最近 DIE 的 global offset，用于回填父指针。
        val parentStack = ArrayDeque<Long>()
        try {
            while (r.pos < dieEnd) {
                val dieStart = r.pos
                val code = r.uleb()
                if (code == 0L) {
                    depth -= 1
                    if (parentStack.isNotEmpty()) parentStack.removeLast()
                    if (depth < 0) {
                        if (r.pos != dieEnd) {
                            cuNotices += ParseNotice("warn", ".debug_info", r.pos.toLong(),
                                "extra null entry before CU end")
                        }
                        break
                    }
                    continue
                }
                val decl = abbrevs[code]
                if (decl == null) {
                    cuNotices += ParseNotice("error", ".debug_info", dieStart.toLong(),
                        "abbrev code $code not found in table; stopping CU to keep cursor aligned")
                    break
                }
                if (depth >= MAX_DIE_DEPTH) {
                    cuNotices += ParseNotice("error", ".debug_info", dieStart.toLong(),
                        "DIE depth limit $MAX_DIE_DEPTH exceeded")
                    break
                }
                val globalOff = cuStart.toLong() + dieStart
                val parent = parentStack.lastOrNull()
                val attrs = ArrayList<DieAttr>(decl.attrs.size)
                for ((at, form) in decl.attrs) {
                    val value = try {
                        val implicitConst: Long? = null
                        FormDecoder.read(r, dc, form, implicitConst)
                    } catch (e: UnknownFormException) {
                        cuNotices += ParseNotice("error", ".debug_info", r.pos.toLong(),
                            "${describeAttr(at)} uses unsupported form 0x${e.form.toString(16)}; CU parse stopped to prevent cursor drift")
                        // 已读 DIE 仍保留，但无法继续安全读取后续属性/兄弟节点。
                        out += DieNode(cuIndex, globalOff, decl.tag, depth, parent, attrs)
                        if (root == null) root = out.last()
                        return root
                    } catch (e: EndOfDataException) {
                        cuNotices += ParseNotice("error", ".debug_info", r.pos.toLong(),
                            "attribute ${describeAttr(at)} truncated: ${e.message}; CU parse stopped")
                        out += DieNode(cuIndex, globalOff, decl.tag, depth, parent, attrs)
                        if (root == null) root = out.last()
                        return root
                    }
                    attrs += DieAttr(at, form, value)
                }
                val node = DieNode(cuIndex, globalOff, decl.tag, depth, parent, attrs)
                out += node
                if (root == null) root = node
                if (decl.hasChildren) {
                    depth += 1
                    parentStack.addLast(globalOff)
                }
            }
        } catch (e: EndOfDataException) {
            cuNotices += ParseNotice("error", ".debug_info", r.pos.toLong(), "DIE tree truncated: ${e.message}")
        }
        return root
    }

    private fun describeAttr(at: Int): String = "DW_AT_$at"

    private fun parseLineProgram(
        dc: CuDecodeContext,
        stmtList: Long?,
        h: CuHeader,
        cuIndex: Int,
    ): Triple<List<FileEntry>, List<LineSequence>, List<ParseNotice>> {
        if (stmtList == null) return Triple(emptyList(), emptyList(), emptyList())
        val lineBytes = ctx.line ?: return Triple(emptyList(), emptyList(), listOf(
            ParseNotice("warn", ".debug_line", stmtList, "DW_AT_stmt_list present but section missing")
        ))
        return LineProgramParser(dc, h).parse(lineBytes, stmtList, cuIndex)
    }
}

/** 从已解析 ELF 构造上下文（主二进制）。 */
fun ElfFile.dwarfContext(): DwarfContext = DwarfContext(
    info = section(".debug_info")?.bytes,
    abbrev = section(".debug_abbrev")?.bytes,
    line = section(".debug_line")?.bytes,
    str = section(".debug_str")?.bytes,
    lineStr = section(".debug_line_str")?.bytes,
    ranges = section(".debug_ranges")?.bytes,
    rnglists = section(".debug_rnglists")?.bytes,
    addr = section(".debug_addr")?.bytes,
    strOffsets = section(".debug_str_offsets")?.bytes,
    abbrevDwo = section(".debug_abbrev.dwo")?.bytes,
    infoDwo = section(".debug_info.dwo")?.bytes,
    lineDwo = section(".debug_line.dwo")?.bytes,
    strDwo = section(".debug_str.dwo")?.bytes,
    lineStrDwo = section(".debug_line_str.dwo")?.bytes,
    rnglistsDwo = section(".debug_rnglists.dwo")?.bytes,
    strOffsetsDwo = section(".debug_str_offsets.dwo")?.bytes,
    littleEndian = littleEndian,
)
