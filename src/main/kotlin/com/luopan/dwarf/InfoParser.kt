package com.luopan.dwarf

import com.luopan.dwarf.DwarfAttr as A
import com.luopan.dwarf.DwarfTag as T

/** 一份 .debug_info（或 .debug_info.dwo）的解析结果。 */
class InfoParseResult(
    val units: List<CompileUnit>,
    val diagnostics: List<Diagnostic>,
)

object InfoParser {
    private const val MAX_DIE_DEPTH = 64

    fun parse(
        sections: DwarfSections,
        useDwo: Boolean,
        jumps: JumpBudget = JumpBudget(),
    ): InfoParseResult {
        val info = (if (useDwo) sections.infoDwo else sections.info)
            ?: return InfoParseResult(emptyList(), listOf(
                Diagnostic("ERROR", "section", if (useDwo) ".debug_info.dwo missing" else ".debug_info missing")))
        val abbrevSec = (if (useDwo) (sections.abbrevDwo ?: sections.abbrev) else sections.abbrev)
            ?: return InfoParseResult(emptyList(), listOf(Diagnostic("ERROR", "section", ".debug_abbrev missing")))

        val diag = mutableListOf<Diagnostic>()
        val units = mutableListOf<CompileUnit>()
        val abbrevCache = HashMap<Int, AbbrevTable>()
        val b = Binary(info, 0, info.size)

        try {
            while (b.available() > 0) {
                val unitStart = b.pos
                try {
                    val lengthField = b.u4().toLong() and 0xffffffffL
                    val dwarf64: Boolean
                    val unitLen: Int
                    when {
                        lengthField < 0xfffffff0L -> { dwarf64 = false; unitLen = lengthField.toInt() }
                        lengthField == 0xffffffffL -> { dwarf64 = true; unitLen = b.u8().toInt() }
                        else -> throw DwarfReadException("reserved 32-bit unit length 0x%x".format(lengthField))
                    }
                    val lenBytes = if (dwarf64) 12 else 4
                    val unitEnd = unitStart + lenBytes + unitLen
                    if (unitEnd > b.end) throw DwarfReadException("CU length $unitLen overruns .debug_info")

                    val version = b.u2()
                    if (version !in 2..5) throw DwarfReadException("unsupported DWARF version $version")
                    val offsetSize = if (dwarf64) 8 else 4

                    var unitType = DwarfUnitType.COMPILE
                    var addressSize = 0
                    var abbrevOffset: Int
                    if (version >= 5) {
                        unitType = b.u1()
                        addressSize = b.u1()
                        abbrevOffset = b.uint(offsetSize).toInt()
                        if (unitType == DwarfUnitType.TYPE || unitType == DwarfUnitType.SPLIT_TYPE) {
                            b.u8() // type signature
                            b.uint(offsetSize) // type offset
                        }
                        if (unitType == DwarfUnitType.SPLIT_COMPILE) b.u8() // dwo id
                    } else {
                        abbrevOffset = b.uint(offsetSize).toInt()
                        addressSize = b.u1()
                    }
                    if (addressSize !in 1..8) throw DwarfReadException("bad address_size $addressSize")

                    val abbrev = abbrevCache.getOrPut(abbrevOffset) {
                        AbbrevParser.parse(abbrevSec, abbrevOffset, jumps)
                    }

                    // ---- 第一遍：结构扫描 + 不解析 strx/addrx/strp，安全拿到 CU DIE 基址 ----
                    data class RawDie(
                        val code: Long, val tag: Int, val hasChildren: Boolean,
                        val parent: Int, val depth: Int, val offset: Int,
                        val attrs: List<Pair<Int, AttrVal>>,
                    )
                    val raws = ArrayList<RawDie>()
                    val parentStack = IntArray(MAX_DIE_DEPTH + 2) { -1 }
                    var depth = 0
                    while (b.pos < unitEnd) {
                        val diePos = b.pos
                        val code = b.uleb()
                        if (code == 0L) {
                            if (depth == 0) break
                            depth--
                            continue
                        }
                        if (depth > MAX_DIE_DEPTH)
                            throw DwarfReadException("DIE nesting too deep (> $MAX_DIE_DEPTH)")
                        val decl = abbrev.decls[code]
                            ?: throw DwarfReadException("abbrev code $code not found at offset $diePos")
                        val rawCtx = UnitContext(
                            version, addressSize, offsetSize, dwarf64, unitStart,
                            null, null, sections, useDwo, jumps, resolve = false,
                        )
                        val attrs = ArrayList<Pair<Int, AttrVal>>(decl.attrs.size)
                        for ((attrName, form, implicit) in decl.attrs) {
                            attrs.add(attrName to FormDecoder.read(b, form, rawCtx, implicit))
                        }
                        val parent = if (depth == 0) -1 else parentStack[depth - 1]
                        raws.add(RawDie(code, decl.tag, decl.hasChildren, parent, depth, diePos, attrs))
                        parentStack[depth] = raws.size - 1
                        if (decl.hasChildren) depth++
                    }
                    val rootRaw = raws.firstOrNull()
                        ?: throw DwarfReadException("CU at $unitStart has no root DIE")
                    val rootAttrs0 = rootRaw.attrs.toMap()
                    fun rawConst(m: Map<Int, AttrVal>, attr: Int) =
                        (m[attr] as? AttrVal.Const)?.v
                    val strBase = rawConst(rootAttrs0, A.STR_OFFSETS_BASE)
                        ?: rawConst(rootAttrs0, A.GNU_STR_OFFSETS_BASE)
                    val addrBase = rawConst(rootAttrs0, A.ADDR_BASE)
                        ?: rawConst(rootAttrs0, A.GNU_ADDR_BASE)

                    // ---- 第二遍：在已知基址下把 Strx/Addrx/Strp/LineStrp 转成最终值 ----
                    val finalCtx = UnitContext(
                        version, addressSize, offsetSize, dwarf64, unitStart,
                        strBase, addrBase, sections, useDwo, jumps, resolve = true,
                    )
                    val dies = raws.mapIndexed { idx, rd ->
                        val finalAttrs = LinkedHashMap<Int, AttrVal>()
                        for ((name, v) in rd.attrs) {
                            finalAttrs[name] = when (v) {
                                is AttrVal.Strx -> FormDecoder.run {
                                    val data = (if (useDwo) sections.strOffsetsDwo else sections.strOffsets)
                                        ?: throw DwarfReadException("DW_FORM_strx without .debug_str_offsets")
                                    val base = strBase ?: throw DwarfReadException("DW_FORM_strx without base")
                                    val sb = Binary(data, 0, data.size).also {
                                        it.seek((base + v.index.toLong() * offsetSize).toInt())
                                    }
                                    AttrVal.Str(FormDecoder.cstringAt(
                                        ((if (useDwo) sections.strDwo else sections.str)
                                            ?: throw DwarfReadException("DW_FORM_strp without .debug_str")),
                                        sb.uint(offsetSize).toInt()))
                                }
                                is AttrVal.Addrx -> {
                                    val data = sections.addr
                                        ?: throw DwarfReadException("DW_FORM_addrx without .debug_addr")
                                    val base = addrBase ?: 0L
                                    val ab = Binary(data, 0, data.size).also {
                                        it.seek((base + v.index.toLong() * addressSize).toInt())
                                    }
                                    AttrVal.Addr(ab.uint(addressSize))
                                }
                                is AttrVal.Strp -> AttrVal.Str(FormDecoder.cstringAt(
                                    (if (useDwo) sections.strDwo else sections.str)
                                        ?: throw DwarfReadException("DW_FORM_strp without .debug_str"), v.offset))
                                is AttrVal.LineStrp -> {
                                    val data = (if (useDwo) sections.lineStrDwo else sections.lineStr)
                                        ?: throw DwarfReadException("DW_FORM_line_strp without .debug_line_str")
                                    AttrVal.Str(FormDecoder.cstringAt(data, v.offset))
                                }
                                else -> v
                            }
                        }
                        Die(idx, rd.offset, rd.tag, T.name(rd.tag), rd.parent, rd.depth, finalAttrs)
                    }
                    val root = dies[0]
                    fun strAttr(d: Die, attr: Int): String? = (d.attr(attr) as? AttrVal.Str)?.v

                    val cuName = strAttr(root, A.NAME) ?: "<unnamed@0x${"%x".format(unitStart)}>"
                    val compDir = strAttr(root, A.COMP_DIR)
                    val cuBase = when (val lp = root.attr(A.LOW_PC)) {
                        is AttrVal.Addr -> lp.v
                        is AttrVal.Const -> lp.v
                        else -> 0L
                    }
                    val stmtList = (root.attr(A.STMT_LIST) as? AttrVal.SecOffset)?.offset
                    val dwoIdAttr = rawConst(rootAttrs0, A.DWO_ID) ?: rawConst(rootAttrs0, A.GNU_DWO_ID)
                    val dwoName = strAttr(root, A.DWO_NAME) ?: strAttr(root, A.GNU_DWO_NAME)
                    val language = rawConst(rootAttrs0, A.LANGUAGE)
                    val producer = strAttr(root, A.PRODUCER)
                    val isSkeleton = (version >= 5 && unitType == DwarfUnitType.SKELETON) ||
                        (version < 5 && dwoIdAttr != null)
                    val isSplit = (version >= 5 && (unitType == DwarfUnitType.SPLIT_COMPILE ||
                        unitType == DwarfUnitType.SPLIT_TYPE)) || useDwo

                    val ranges = RangeResolver.collect(
                        dies, sections, version, addressSize, offsetSize, dwarf64,
                        cuBase, addrBase ?: 0L, useDwo, jumps, diag, cuName,
                    )

                    b.seek(unitEnd)
                    units.add(
                        CompileUnit(
                            cuName, compDir, version, DwarfUnitType.name(unitType), dwarf64,
                            addressSize, offsetSize, unitStart, unitEnd - unitStart, abbrevOffset,
                            cuBase, stmtList, dwoIdAttr, dwoName, isSkeleton, isSplit,
                            strBase, addrBase, dies, ranges, language, producer,
                        )
                    )
                } catch (ex: DwarfReadException) {
                    // 长度前缀本身可能被污染，无法可信定位下一单元：终止整个流，不再产出伪 CU
                    diag.add(Diagnostic("ERROR", "section",
                        ".debug_info desync at offset $unitStart, remaining units not trusted: ${ex.message}"))
                    break
                }
            }
        } catch (ex: Exception) {
            if (ex is DwarfReadException)
                diag.add(Diagnostic("ERROR", "section", ".debug_info parse aborted: ${ex.message}"))
            else throw ex
        }
        return InfoParseResult(units, diag)
    }
}
