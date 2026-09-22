package compass.dwarf

import compass.elf.BinaryParseException
import compass.elf.Reader
import java.nio.ByteOrder

/**
 * 解析 .debug_info 中的 CU 与 DIE 树。
 *
 * 防护策略：
 *  - 单个 CU 内 DIE/abbrev 数量受限；
 *  - 每个 form 都有确定长度；未知 form 抛 [UnknownFormException]，
 *    当前 CU 被标记 degraded 后整体隔离（不产生半成品伪 DIE），其它 CU 继续解析；
 *  - 跨 CU 引用（ref_addr/ref4/ref8）在引用解析阶段检查越界。
 */
class CuParser(
    private val debugInfo: ByteArray?,
    private val debugAbbrev: ByteArray?,
    private val debugStr: ByteArray?,
    private val debugRanges: ByteArray?,
    private val debugRngLists: ByteArray?,
    private val endian: ByteOrder
) {
    private val rangeParser = RangeListParser(debugRanges, debugRngLists, endian)

    private fun strAt(off: Long): String? {
        if (debugStr == null) return null
        if (off < 0 || off >= debugStr.size) throw BinaryParseException(".debug_str 偏移越界 0x${off.toString(16)}")
        var end = off.toInt()
        while (end < debugStr.size && debugStr[end].toInt() != 0) end++
        return String(debugStr, off.toInt(), end - off.toInt(), Charsets.UTF_8)
    }

    fun parseAll(): List<CompilationUnit> {
        if (debugInfo == null) return emptyList()
        val cus = ArrayList<CompilationUnit>()
        var off = 0L
        var cuGuard = 0
        while (off < debugInfo.size) {
            if (++cuGuard > 100_000) throw BinaryParseException("CU 数量超限")
            val cu = try {
                parseOne(off)
            } catch (e: BinaryParseException) {
                // CU 头都读不出来：无法定位下一个 CU，必须终止整个 section。
                throw e
            }
            cus.add(cu)
            off += cu.length + headerLengthSize(cu.is64Bit)
            if (cu.length <= 0) break
        }
        return cus
    }

    private fun headerLengthSize(is64: Boolean): Int = if (is64) 12 else 4

    private fun parseOne(unitOffset: Long): CompilationUnit {
        val r = Reader(debugInfo!!, endian)
        r.seek(unitOffset.toInt())
        val unitStart = r.pos
        val length = r.initialLength()
        val is64 = r.dwarf64
        val afterLen = r.pos
        val unitEnd = (afterLen.toLong() + length).toInt()
        if (unitEnd > debugInfo.size) throw BinaryParseException(".debug_info unit 长度越界 @0x${unitOffset.toString(16)}")

        val version = r.u2()
        var unitType: Int? = null
        var addressSize = 4
        var abbrevOffset: Long
        if (version >= 5) {
            unitType = r.u1()
            addressSize = r.u1()
            abbrevOffset = if (is64) r.u8() else r.u4long()
        } else {
            abbrevOffset = if (is64) r.u8() else r.u4long()
            addressSize = r.u1()
        }
        r.addressSize = addressSize
        val warnings = ArrayList<String>()
        val split = unitType == 5 /* DW_UT_split */
        if (version < 2 || version > 5) warnings.add("未验证的 DWARF 版本 $version，按 $version 规则尽力解析")

        val abbrev = try {
            AbbrevParser.parseTable(debugAbbrev, abbrevOffset, endian)
        } catch (e: BinaryParseException) {
            return degraded(unitOffset, length, version, unitType, is64, addressSize, abbrevOffset,
                warnings + "abbrev 表解析失败：${e.message}")
        }

        data class RawDie(
            val offset: Long,
            val tag: Int,
            val parent: Long?,
            val children: MutableList<Long>,
            val attrs: MutableMap<Int, FormValue>
        )

        val dies = LinkedHashMap<Long, RawDie>()
        val depthStack = ArrayDeque<Long>()
        var degradedReason: String? = null
        var dieGuard = 0

        fun readFormValue(form: Int, reader: Reader): FormValue {
            val posBefore = reader.pos
            val v = when (form) {
                FORM.addr -> AddrVal(reader.addr())
                FORM.block -> BytesVal(reader.bytes(reader.uleb().toInt()))
                FORM.block1 -> BytesVal(reader.bytes(reader.u1()))
                FORM.block2 -> BytesVal(reader.bytes(reader.u2()))
                FORM.block4 -> BytesVal(reader.bytes(reader.u4()))
                FORM.data1 -> IntVal(reader.u1().toLong())
                FORM.data2 -> IntVal(reader.u2().toLong())
                FORM.data4 -> IntVal(reader.u4long())
                FORM.data8 -> IntVal(reader.u8())
                FORM.sdata -> IntVal(reader.sleb())
                FORM.udata -> IntVal(reader.uleb())
                FORM.flag -> FlagVal(reader.u1() != 0)
                FORM.flag_present -> FlagVal(true)
                FORM.string -> StrVal(reader.cString())
                FORM.strp -> {
                    val so = if (is64) reader.u8() else reader.u4long()
                    StrVal(strAt(so) ?: "<strp 0x${so.toString(16)} 缺失>")
                }
                FORM.line_strp -> SecOffsetVal(if (is64) reader.u8() else reader.u4long())
                FORM.sec_offset -> SecOffsetVal(if (is64) reader.u8() else reader.u4long())
                FORM.ref_addr -> RefVal(if (is64) reader.u8() else reader.u4long())
                FORM.ref1 -> RefVal(reader.u1().toLong())
                FORM.ref2 -> RefVal(reader.u2().toLong())
                FORM.ref4 -> RefVal(reader.u4long())
                FORM.ref8 -> RefVal(reader.u8())
                FORM.ref_udata -> RefVal(reader.uleb())
                FORM.exprloc -> BytesVal(reader.bytes(reader.uleb().toInt()))
                FORM.data16 -> BytesVal(reader.bytes(16))
                FORM.strx1 -> StrxVal(reader.u1().toLong())
                FORM.strx2 -> StrxVal(reader.u2().toLong())
                FORM.strx3 -> StrxVal((reader.u1() or (reader.u1() shl 8) or (reader.u1() shl 16)).toLong())
                FORM.strx4 -> StrxVal(reader.u4long())
                FORM.strx -> StrxVal(reader.uleb())
                FORM.addrx1 -> AddrxVal(reader.u1().toLong())
                FORM.addrx2 -> AddrxVal(reader.u2().toLong())
                FORM.addrx3 -> AddrxVal((reader.u1() or (reader.u1() shl 8) or (reader.u1() shl 16)).toLong())
                FORM.addrx4 -> AddrxVal(reader.u4long())
                FORM.addrx -> AddrxVal(reader.uleb())
                FORM.rnglistx -> RngListxVal(reader.uleb())
                else -> {
                    // 无法知道长度，不能继续；标记 CU 隔离。
                    throw UnknownFormException(form)
                }
            }
            return v
        }

        try {
            while (r.pos < unitEnd) {
                if (++dieGuard > 500_000) throw BinaryParseException("CU @0x${unitOffset.toString(16)} DIE 数量超限")
                val dieStart = unitOffset + (r.pos - afterLen)
                val code = r.uleb()
                if (code == 0L) {
                    depthStack.removeLastOrNull()
                    continue
                }
                val decl = abbrev[code] ?: throw BinaryParseException("CU @0x${unitOffset.toString(16)} 引用了不存在的 abbrev code=$code")
                val parent = depthStack.lastOrNull()
                val raw = RawDie(dieStart.toLong(), decl.tag, parent, mutableListOf(), LinkedHashMap())
                for ((at, form) in decl.attrs) {
                    val fv = readFormValue(form, r)
                    // DW_FORM_indirect 由外层 form 决定，这里不支持，保持游标安全
                    raw.attrs[at] = fv
                }
                dies[dieStart.toLong()] = raw
                parent?.let { dies[it]?.children?.add(dieStart.toLong()) }
                if (decl.hasChildren) depthStack.addLast(dieStart.toLong())
            }
        } catch (e: UnknownFormException) {
            degradedReason = e.message ?: "未知 form"
        } catch (e: BinaryParseException) {
            degradedReason = e.message ?: "DIE 解析错误"
        }

        if (degradedReason != null) {
            warnings.add("CU 已隔离：$degradedReason（该 CU 的行号仍由 .debug_line 独立提供）")
            val rootName = dies.values.firstOrNull()?.attrs?.get(DW.AT_name)?.let { it as? StrVal }?.s
            return CompilationUnit(
                offset = unitOffset, length = length, dwarfVersion = version, unitType = unitType,
                is64Bit = is64, addressSize = addressSize, abbrevOffset = abbrevOffset,
                name = rootName, compDir = null, dwoName = null, dwoId = null, stmtListOffset = null,
                dies = emptyMap(), rootOffset = -1, split = split, warnings = warnings, degraded = true
            )
        }

        // 属性提升为模型，并解析范围
        fun str(v: FormValue?): String? = when (v) {
            is StrVal -> v.s
            is StrxVal -> "<strx${v.index}>"
            else -> null
        }

        val rootRaw = dies.values.firstOrNull()
        val models = LinkedHashMap<Long, DieNode>()
        for ((off2, raw) in dies) {
            val a = raw.attrs
            val lowPc = (a[DW.AT_low_pc] as? AddrVal)?.a ?: (a[DW.AT_low_pc] as? AddrxVal)?.let { null }
            val highConst = (a[DW.AT_high_pc] as? IntVal)?.v
            val highAddr = (a[DW.AT_high_pc] as? AddrVal)?.a
            val rangesOff = (a[DW.AT_ranges] as? SecOffsetVal)?.o
            val rangesX = (a[DW.AT_ranges] as? RngListxVal)?.index
            val ranges = ArrayList<DieRange>()
            when {
                rangesOff != null -> {
                    try {
                        ranges += if (version >= 5) rangeParser.parseDwarf5(rangesOff)
                        else rangeParser.parseDwarf4(rangesOff, is64, addressSize, lowPc ?: 0L)
                    } catch (e: BinaryParseException) {
                        warnings.add("DIE @0x${off2.toString(16)} 的范围列表不可读：${e.message}")
                    }
                }
                lowPc != null && (highAddr != null || highConst != null) -> {
                    val hi = highAddr ?: (lowPc + (highConst ?: 0L))
                    ranges.add(DieRange(lowPc, hi))
                }
                lowPc != null -> ranges.add(DieRange(lowPc, lowPc)) // 零长度占位
            }
            models[off2] = DieNode(
                offset = off2, tag = raw.tag, parentOffset = raw.parent,
                childrenOffsets = raw.children.toList(),
                name = str(a[DW.AT_name]) ?: (a[DW.AT_linkage_name] as? StrVal)?.s,
                lowPc = lowPc, highPcConst = highConst, highPcAddr = highAddr,
                rangesOffset = rangesOff, rangesX = rangesX,
                abstractOrigin = (a[DW.AT_abstract_origin] as? RefVal)?.r
                    ?: (a[DW.AT_specification] as? RefVal)?.r
                    ?: (a[DW.AT_origin] as? RefVal)?.r,
                specification = (a[DW.AT_specification] as? RefVal)?.r,
                callFile = (a[DW.AT_call_file] as? IntVal)?.v?.toInt(),
                callLine = (a[DW.AT_call_line] as? IntVal)?.v?.toInt(),
                ranges = ranges,
                isDeclaration = (a[DW.AT_declaration] as? FlagVal)?.f == true
            )
        }

        val rootAttrs = rootRaw?.attrs
        return CompilationUnit(
            offset = unitOffset, length = length, dwarfVersion = version, unitType = unitType,
            is64Bit = is64, addressSize = addressSize, abbrevOffset = abbrevOffset,
            name = str(rootAttrs?.get(DW.AT_name)),
            compDir = str(rootAttrs?.get(DW.AT_comp_dir)),
            dwoName = str(rootAttrs?.get(DW.AT_dwo_name)),
            dwoId = (rootAttrs?.get(DW.AT_dwo_id) as? IntVal)?.v,
            stmtListOffset = (rootAttrs?.get(DW.AT_stmt_list) as? SecOffsetVal)?.o,
            dies = models, rootOffset = rootRaw?.offset ?: -1, split = split,
            warnings = warnings, degraded = false
        )
    }

    private fun degraded(
        unitOffset: Long, length: Long, version: Int, unitType: Int?, is64: Boolean,
        addressSize: Int, abbrevOffset: Long, extra: List<String>
    ) = CompilationUnit(
        offset = unitOffset, length = length, dwarfVersion = version, unitType = unitType,
        is64Bit = is64, addressSize = addressSize, abbrevOffset = abbrevOffset,
        name = null, compDir = null, dwoName = null, dwoId = null, stmtListOffset = null,
        dies = emptyMap(), rootOffset = -1, split = false,
        warnings = listOf("CU 已隔离：abbrev 不可用") + extra, degraded = true
    )
}

sealed class FormValue
data class AddrVal(val a: Long) : FormValue()
data class IntVal(val v: Long) : FormValue()
data class StrVal(val s: String) : FormValue()
data class FlagVal(val f: Boolean) : FormValue()
data class BytesVal(val b: ByteArray) : FormValue()
data class SecOffsetVal(val o: Long) : FormValue()
data class RefVal(val r: Long) : FormValue()
data class StrxVal(val index: Long) : FormValue()
data class AddrxVal(val index: Long) : FormValue()
data class RngListxVal(val index: Long) : FormValue()
