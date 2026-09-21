package compass.dwarf

import compass.BinReader

/**
 * .debug_info 解析：CU header、DIE 树、关键属性、地址范围。
 * 单个 CU 损坏（含未知 form、越界引用）时隔离该 CU，其他 CU 继续。
 */
class InfoParser(private val d: SectionData, private val useDwo: Boolean = false) {

    private val abbrevCache = HashMap<Long, AbbrevTable>()
    private val errors = mutableListOf<String>()

    fun parseAll(): List<CompilationUnit> {
        val info = (if (useDwo) d.debugInfoDwo else d.debugInfo)
            ?: return emptyList()
        val units = mutableListOf<CompilationUnit>()
        var off = 0
        var idx = 0
        while (off < info.size) {
            if (units.size > 10_000) { errors.add("CU 数量超过 10000，停止"); break }
            val r0 = BinReader(info, off)
            val unitLen = r0.u4().toLong() and 0xffffffffL
            val dwarf64: Boolean
            val nextOff: Int
            if (unitLen == 0xffffffffL) {
                dwarf64 = true
                val len = r0.u8()
                nextOff = (off + 12L + len).toInt()
            } else if (unitLen == 0L) {
                break
            } else {
                dwarf64 = false
                nextOff = (off + 4L + unitLen).toInt()
            }
            if (nextOff > info.size || nextOff <= off) {
                errors.add("CU@0x${off.toString(16)} 长度非法，停止解析后续 CU")
                break
            }
            val cu = runCatching { parseUnit(info, off.toLong(), dwarf64, nextOff, idx) }
                .getOrElse { e ->
                    val msg = "CU@0x${off.toString(16)} 解析失败已隔离: ${e.message}"
                    brokenUnit(off.toLong(), info, dwarf64, nextOff, msg)
                }
            units.add(cu)
            idx++
            off = nextOff
        }
        return units
    }

    fun globalErrors(): List<String> = errors.toList()

    private fun brokenUnit(off: Long, info: ByteArray, dwarf64: Boolean, nextOff: Int, msg: String): CompilationUnit {
        val r = BinReader(info, off + (if (dwarf64) 12 else 4))
        val version = if (r.pos + 2 <= info.size) r.u2() else 0
        return CompilationUnit(
            offset = off, version = version, dwarf64 = dwarf64,
            abbrevOffset = 0, addressSize = 8,
            compDir = null, name = "<损坏的 CU>", language = null, root = null,
            lineProgram = null, rangeListBase = 0, strOffsetsBase = 0, locListsBase = 0,
            isSkeleton = false, dwoName = null, dwoId = null,
            errors = listOf(msg), warnings = emptyList()
        )
    }

    private fun parseUnit(info: ByteArray, off: Long, dwarf64: Boolean, nextOff: Int, idx: Int): CompilationUnit {
        val r = BinReader(info, off + (if (dwarf64) 12 else 4))
        val version = r.u2()
        if (version !in 2..5) throw DwarfParseError("CU version=$version 不受支持")

        var abbrevOff = 0L
        var addressSize = 8
        var unitType = 0
        var unitId = 0L
        if (version >= 5) {
            unitType = r.u1()
            addressSize = r.u1()
            abbrevOff = if (dwarf64) r.u8() else r.u4().toLong() and 0xffffffffL
            unitId = if (dwarf64) r.u8() else r.u4().toLong() and 0xffffffffL
        } else {
            abbrevOff = if (dwarf64) r.u8() else r.u4().toLong() and 0xffffffffL
            addressSize = r.u1()
        }

        val abbrevSection = if (useDwo) d.debugAbbrevDwo else d.debugAbbrev
            ?: throw DwarfParseError("缺少 .debug_abbrev")
        val table = abbrevCache.getOrPut(abbrevOff) {
            AbbrevParser.parseTable(abbrevSection, abbrevOff)
        }

        val cuErrors = mutableListOf<String>()
        val cuWarnings = mutableListOf<String>()
        val dieStart = r.pos
        var strOffsetsBase = 0L
        var addrBase = 0L
        var rngListsBase = 0L
        var gnuRangesBase = 0L

        // 第一遍：解析 root DIE（compile_unit），收集 CU 级 base
        val root = parseDieTree(r, nextOff, table, off, dwarf64, version, addressSize, cuErrors) { attr, val0 ->
            when (attr) {
                DW_AT_str_offsets_base, DW_AT_strx_base_hint -> strOffsetsBase = numOf(val0)
                DW_AT_addr_base, DW_AT_GNU_addr_base -> addrBase = numOf(val0)
                DW_AT_rnglists_base -> rngListsBase = numOf(val0)
                DW_AT_GNU_ranges_base -> gnuRangesBase = numOf(val0)
            }
        }

        val name = root?.name()
        val compDir = (root?.attrs?.get(DW_AT_comp_dir) as? AttrValue.Str)?.value
        val language = (root?.attrs?.get(DW_AT_language) as? AttrValue.Num)?.value
        val stmtList = (root?.attrs?.get(DW_AT_stmt_list) as? AttrValue.SecOffset)?.offset
        val dwoName = (root?.attrs?.get(DW_AT_dwo_name) as? AttrValue.Str)?.value
            ?: (root?.attrs?.get(DW_AT_GNU_dwo_name) as? AttrValue.Str)?.value
        val dwoId = (root?.attrs?.get(DW_AT_GNU_dwo_id) as? AttrValue.Num)?.value
        val isSkeleton = root?.tag == DW_TAG_skeleton_unit ||
            (dwoName != null && (unitType == 4 || version < 5))

        // 计算每个 DIE 的范围
        val baseForRanges = if (version < 5) gnuRangesBase else rngListsBase
        assignRanges(root, off, dwarf64, version, addressSize, baseForRanges, useDwo, cuWarnings)

        val line = stmtList?.let { sl ->
            runCatching {
                LineProgramParser.parse(
                    d.withLineSectionFor(useDwo), sl, version, addressSize
                )
            }.getOrElse { e ->
                cuErrors.add("行号程序解析失败（CU 其余信息仍可信）: ${e.message}")
                null
            }
        }

        if (isSkeleton && !d.isSplit) {
            cuWarnings.add("skeleton CU 引用 .dwo「$dwoName」但未导入：函数范围、行表仍可信；dwo 内联/类型细节不可用")
        }

        return CompilationUnit(
            offset = off, version = version, dwarf64 = dwarf64,
            abbrevOffset = abbrevOff, addressSize = addressSize,
            compDir = compDir, name = name, language = language,
            root = root, lineProgram = line,
            rangeListBase = baseForRanges,
            strOffsetsBase = strOffsetsBase, locListsBase = 0,
            isSkeleton = isSkeleton, dwoName = dwoName, dwoId = dwoId,
            errors = cuErrors.toList(), warnings = cuWarnings.toList()
        )
    }

    private fun numOf(v: AttrValue): Long = when (v) {
        is AttrValue.Num -> v.value
        is AttrValue.Addr -> v.value
        is AttrValue.SecOffset -> v.offset
        is AttrValue.RangesRef -> v.offset
        else -> 0L
    }

    private fun parseDieTree(
        r: BinReader, end: Int, table: AbbrevTable, cuOffset: Long,
        dwarf64: Boolean, version: Int, addressSize: Int,
        cuErrors: MutableList<String>,
        onCuAttr: (Int, AttrValue) -> Unit
    ): DwarfDie? {
        var depth = 0
        var root: DwarfDie? = null
        val stack = ArrayDeque<DwarfDie>()
        var dieCount = 0

        while (r.pos < end) {
            if (++dieCount > 500_000) throw DwarfParseError("DIE 数量过多")
            val dieOff = cuOffset + (r.pos - (cuOffset.toInt()))
            val code = r.uleb128().toLong()
            if (code == 0L) {
                if (stack.isNotEmpty()) stack.removeLast() else break
                depth--
                if (depth < 0) break
                continue
            }
            val decl = table.decls[code]
                ?: throw DwarfParseError("abbrev code=$code 在表 0x${table.offset.toString(16)} 中不存在，CU 已损坏")
            val attrs = LinkedHashMap<Int, AttrValue>()
            var abstractOrigin: Long? = null
            var specification: Long? = null
            var callFile: Int? = null
            var callLine: Int? = null
            var inlineCode: Int? = null
            val fctx = FormCtx(
                data = d, version = version, dwarf64 = dwarf64,
                addressSize = addressSize,
                refAddrSize = if (version <= 3) addressSize else if (dwarf64) 8 else 4,
                cuOffset = cuOffset, strOffsetsBase = 0L,
                addrBase = 0L, rngListsBase = 0L, useDwo = useDwo
            )
            for ((attr, form, implicit) in decl.specs) {
                val v = readForm(r, form, implicit, fctx)
                when (attr) {
                    DW_AT_abstract_origin -> abstractOrigin = (v as? AttrValue.Ref)?.offset
                    DW_AT_specification -> specification = (v as? AttrValue.Ref)?.offset
                    DW_AT_call_file -> callFile = (v as? AttrValue.Num)?.value?.toInt()
                    DW_AT_call_line -> callLine = (v as? AttrValue.Num)?.value?.toInt()
                    DW_AT_inline -> inlineCode = (v as? AttrValue.Num)?.value?.toInt()
                }
                attrs[attr] = v
                if (stack.isEmpty()) onCuAttr(attr, v)
            }
            val die = DwarfDie(
                offset = dieOff, tag = decl.tag, tagName = tagName(decl.tag),
                attrs = attrs, abstractOrigin = abstractOrigin,
                specification = specification, callFile = callFile,
                callLine = callLine, inlineCode = inlineCode
            )
            if (root == null) root = die
            stack.lastOrNull()?.children?.add(die)
            if (decl.hasChildren) { stack.addLast(die); depth++ }
        }
        return root
    }

    private fun assignRanges(
        die: DwarfDie?, cuOffset: Long, dwarf64: Boolean, version: Int,
        addressSize: Int, rangesBase: Long, dwo: Boolean,
        warnings: MutableList<String>
    ) {
        if (die == null) return
        val ranges = mutableListOf<AddrRange>()
        val low = die.attrs[DW_AT_low_pc]
        val high = die.attrs[DW_AT_high_pc]
        if (low is AttrValue.Addr) {
            when (high) {
                is AttrValue.Addr -> ranges.add(AddrRange(low.value, high.value))
                is AttrValue.Num -> ranges.add(AddrRange(low.value, low.value + high.value))
                null -> ranges.add(AddrRange(low.value, low.value)) // 只有 low_pc：零长度起点
                else -> {}
            }
        }
        val rangesAttr = die.attrs[DW_AT_ranges]
        when (rangesAttr) {
            is AttrValue.SecOffset -> {
                val resolved = if (version <= 4) {
                    val section = if (dwo) d.debugRnglistsDwo ?: d.debugRanges else d.debugRanges
                    RangeLists.readV4(
                        section,
                        rangesAttr.offset + rangesBase,
                        dieLowPcForBase(die, cuOffset), addressSize
                    )
                } else {
                    RangeLists.readV5(
                        if (dwo) d.debugRnglistsDwo else d.debugRnglists,
                        rangesAttr.offset, rangesBase, addressSize
                    )
                }
                ranges.addAll(resolved)
            }
            else -> {}
        }
        die.ranges = ranges
        for (c in die.children) assignRanges(c, cuOffset, dwarf64, version, addressSize, rangesBase, dwo, warnings)
    }

    private fun dieLowPcForBase(die: DwarfDie, cuOffset: Long): Long = 0L

}
