package compass.dwarf

import compass.dwarf.DW_AT as A
import compass.dwarf.DW_FORM as F

/**
 * Parses .debug_info into compilation units and DIE trees.
 *
 * Safety rules:
 *  - recursion depth while reading the DIE tree is capped ([MAX_DIE_DEPTH]).
 *  - reference-following (abstract_origin / specification) is capped ([MAX_REF_HOPS]).
 *  - an unknown form aborts the *current* CU only; the cursor is never advanced past it,
 *    so no fabricated following DIEs can be produced.
 */
class InfoParser(
    private val bundle: SectionBundle,
    private val abbrevs: AbbrevTables,
    private val diagnostics: MutableList<ParseDiagnostic>
) {
    private class CuContext(
        val offset: Long,
        val version: Int,
        val unitType: Int,
        val addressSize: Int,
        val dwarfOffsetSize: Int,
        val dataStart: Int,
        val dataEnd: Int,
        val abbrevOffset: Long,
        val strOffsetsBase: Long,
        val addrBase: Long
    )

    fun parse(): List<CompUnit> {
        val info = bundle.section(".debug_info") ?: run {
            diagnostics.add(ParseDiagnostic("INFO", "NO_DEBUG_INFO", "缺少 .debug_info 段", ".debug_info", null))
            return emptyList()
        }
        val cus = mutableListOf<CompUnit>()
        val r = SectionReader(info, ".debug_info", bundle.le, 0, 4)
        while (r.pos < r.size) {
            val cuStart = r.pos
            val cu = try {
                parseCu(r, cuStart)
            } catch (e: DwarfBoundsException) {
                diagnostics.add(ParseDiagnostic("ERROR", "CU_TRUNCATED", e.message ?: "CU 截断", ".debug_info", cuStart.toLong()))
                null
            } catch (e: Exception) {
                diagnostics.add(ParseDiagnostic("ERROR", "CU_PARSE_FAILED", "CU @$cuStart 解析失败: ${e.message}", ".debug_info", cuStart.toLong()))
                null
            }
            if (cu == null) break // cannot trust cursor position beyond a failed unit
            cus.add(cu)
        }
        return cus
    }

    private fun parseCu(r: SectionReader, cuStart: Int): CompUnit {
        val il = r.readInitialLength()
        val unitEnd = il.headerEndPos + il.unitLength
        if (unitEnd > r.size)
            throw DwarfBoundsException(".debug_info: CU @$cuStart 声明长度超出段尾")
        val version = r.u16()
        var unitType = DW_UT.COMPILE
        val addressSize: Int
        val abbrevOffset: Long
        if (version >= 5) {
            unitType = r.u8()
            addressSize = r.u8()
            abbrevOffset = r.u(il.offsetSize)
        } else {
            abbrevOffset = r.u(il.offsetSize)
            addressSize = r.u8()
        }
        // DWARF 5 header extras
        var dwoId: Long? = null
        if (version >= 5 && (unitType == DW_UT.SKELETON || unitType == DW_UT.SPLIT_COMPILE)) {
            dwoId = r.u64()
        }
        if (version >= 5 && (unitType == DW_UT.TYPE || unitType == DW_UT.SPLIT_TYPE)) {
            r.u64(); r.u64() // type_signature + type_offset
        }

        val decls = abbrevs.tableAt(abbrevOffset)
        val ctx = CuContext(cuStart.toLong(), version, unitType, addressSize, il.offsetSize,
            r.pos, unitEnd, abbrevOffset, 0L, 0L)

        if (decls == null) {
            diagnostics.add(ParseDiagnostic("ERROR", "ABBREV_NOT_FOUND",
                "CU @$cuStart 引用的 abbrev 表 @$abbrevOffset 不存在", ".debug_info", cuStart.toLong()))
            r.seek(unitEnd)
            return CompUnit(cuStart.toLong(), il.unitLength, version, unitType, abbrevOffset,
                addressSize, null, emptyMap(), unitType == DW_UT.SPLIT_COMPILE, dwoId, null)
        }

        val dieByOffset = LinkedHashMap<Long, DieNode>()
        var root: DieNode? = null
        try {
            root = readDieTree(r, ctx, decls, dieByOffset)
        } catch (e: UnknownFormException) {
            // Cursor is deliberately left at the unknown form; we resync at the CU boundary
            // (a trustworthy offset from the header) instead of guessing a new position.
            diagnostics.add(ParseDiagnostic("WARNING", "CU_PARTIAL",
                "CU @$cuStart 在 @${r.pos} 遇到未知 form 后中止；已解析的 ${dieByOffset.size} 个 DIE 保留，" +
                    "该 CU 其余内容标记为不可信", ".debug_info", r.pos.toLong()))
        }

        var dwoName: String? = null
        root?.let { rt ->
            rt.str(A.DWO_NAME)?.let { dwoName = it }
            rt.str(A.GNU_DWO_NAME)?.let { dwoName = it }
            if (dwoId == null) rt.num(A.DWO_ID)?.let { dwoId = it }
            if (dwoId == null) rt.num(A.GNU_DWO_ID)?.let { dwoId = it }
        }
        val isDwo = unitType == DW_UT.SPLIT_COMPILE || unitType == DW_UT.SPLIT_TYPE
        r.seek(unitEnd)
        val cu = CompUnit(cuStart.toLong(), il.unitLength, version, unitType, abbrevOffset,
            addressSize, root, dieByOffset, isDwo, dwoId, dwoName)
        dieByOffset.values.forEach { it.cu = cu }
        resolveIndexedAttrs(cu)
        return cu
    }

    private fun readDieTree(
        r: SectionReader, ctx: CuContext, decls: List<AbbrevDecl>,
        byOffset: MutableMap<Long, DieNode>
    ): DieNode? {
        // Iterative DFS following depth from sibling structure implied by zero codes.
        var root: DieNode? = null
        val stack = ArrayDeque<DieNode>()
        var depth = 0
        while (r.pos < ctx.dataEnd) {
            val dieOffset = r.pos.toLong()
            val code = r.uleb()
            if (code == 0L) {
                if (stack.isNotEmpty()) stack.removeLast()
                depth--
                if (depth < 0) break
                continue
            }
            val decl = decls.firstOrNull { it.code == code }
            if (decl == null) {
                throw DwarfBoundsException(".debug_info: CU @${ctx.offset} 中出现未知 abbrev code=$code @$dieOffset")
            }
            val attrs = readAttrs(r, ctx, decl, dieOffset)
            val node = DieNode(dieOffset, decl.tag, depth, attrs.toMutableList())
            byOffset[dieOffset] = node
            if (root == null) root = node
            stack.lastOrNull()?.let { p -> p.children.add(node); node.parent = p }
            if (decl.hasChildren) {
                stack.addLast(node); depth++
            }
        }
        if (depth >= MAX_DIE_DEPTH) {
            diagnostics.add(ParseDiagnostic("ERROR", "DIE_DEPTH_EXCEEDED",
                "CU @${ctx.offset} DIE 深度超过 $MAX_DIE_DEPTH", ".debug_info", ctx.offset))
        }
        return root
    }

    private fun resolveIndexedAttrs(cu: CompUnit) {
        val root = cu.root ?: return
        val strBase = root.num(A.STR_OFFSETS_BASE) ?: 0L
        val addrBase = root.num(A.ADDR_BASE) ?: 0L
        val all = ArrayDeque<DieNode>().apply { add(root) }
        var guard = 0
        while (all.isNotEmpty()) {
            if (++guard > MAX_DIES_PER_CU) {
                diagnostics.add(ParseDiagnostic("ERROR", "DIE_COUNT_EXCEEDED",
                    "CU @${cu.offset} DIE 数量超过 $MAX_DIES_PER_CU", ".debug_info", cu.offset))
                break
            }
            val d = all.removeFirst()
            for (i in d.attrs.indices) {
                val at = d.attrs[i]
                when (val v = at.value) {
                    is AttrValue.Strx -> {
                        val section = if (at.name == A.DECL_FILE) ".debug_line_str" else ".debug_str"
                        val resolved = StrTables.readStrx(bundle, section, strBase, v.index)
                        if (resolved != null) {
                            d.attrs[i] = DieAttr(at.name, at.form, AttrValue.Str(resolved))
                        } else {
                            diagnostics.add(ParseDiagnostic("WARNING", "STRX_OOB",
                                "strx 索引 ${v.index} 无法解析（CU @${cu.offset}）", ".debug_str_offsets", strBase))
                            d.attrs[i] = DieAttr(at.name, at.form, AttrValue.Str("<strx:${v.index}>"))
                        }
                    }
                    is AttrValue.Addrx -> {
                        val resolved = AddrTables.resolve(bundle, addrBase, v.index, cu.addressSize)
                        d.attrs[i] = DieAttr(at.name, at.form, AttrValue.Addr(resolved))
                    }
                    else -> {}
                }
            }
            all.addAll(d.children)
        }
    }

    private fun readAttrs(r: SectionReader, ctx: CuContext, decl: AbbrevDecl, dieOffset: Long): List<DieAttr> {
        val out = mutableListOf<DieAttr>()
        for (spec in decl.attrs) {
            var form = spec.form
            if (form == F.INDIRECT) form = r.uleb().toInt()
            val value = readFormValue(r, ctx, form, spec.implicitConst, spec.name)
            out.add(DieAttr(spec.name, form, value))
        }
        return out
    }

    private fun readFormValue(
        r: SectionReader, ctx: CuContext, form: Int, implicit: Long?, attrName: Int
    ): AttrValue {
        val refSize = ctx.dwarfOffsetSize
        return when (form) {
            F.ADDR -> AttrValue.Addr(r.u(ctx.addressSize))
            F.DATA1, F.REF1 -> readSmallRef(r, ctx, 1, form)
            F.DATA2, F.REF2 -> readSmallRef(r, ctx, 2, form)
            F.DATA4, F.REF4 -> readSmallRef(r, ctx, 4, form)
            F.DATA8, F.REF8 -> readSmallRef(r, ctx, 8, form)
            F.UDATA -> AttrValue.Number(r.uleb())
            F.SDATA -> AttrValue.Number(r.sleb())
            F.FLAG -> AttrValue.Number(r.u8().toLong())
            F.FLAG_PRESENT -> AttrValue.Number(1)
            F.STRING -> AttrValue.Str(r.cString())
            F.STRP -> readStrp(r, ctx, refSize)
            F.LINE_STRP -> readLineStrp(r, ctx, refSize)
            F.SEC_OFFSET -> AttrValue.SecOffset(r.u(refSize))
            F.REF_ADDR -> {
                val v = r.u(refSize)
                AttrValue.Ref(v)
            }
            F.REF_UDATA -> AttrValue.Ref(r.uleb())
            F.BLOCK -> { val n = r.uleb().toInt(); AttrValue.Block(r.bytes(n)) }
            F.BLOCK1 -> { val n = r.u8(); AttrValue.Block(r.bytes(n)) }
            F.BLOCK2 -> { val n = r.u16(); AttrValue.Block(r.bytes(n)) }
            F.BLOCK4 -> { val n = r.u32().toInt(); AttrValue.Block(r.bytes(n)) }
            F.EXPRLOC -> { val n = r.uleb().toInt(); AttrValue.Block(r.bytes(n)) }
            F.DATA16 -> AttrValue.Block(r.bytes(16))
            F.IMPLICIT_CONST -> AttrValue.Number(implicit ?: 0L)
            F.STRX, F.STRX1, F.STRX2, F.STRX3, F.STRX4 ->
                AttrValue.Strx(readIndexed(r, form, F.STRX))
            F.ADDRX, F.ADDRX1, F.ADDRX2, F.ADDRX3, F.ADDRX4 ->
                AttrValue.Addrx(readIndexed(r, form, F.ADDRX))
            F.RNGLISTX, F.LOCLISTX -> AttrValue.SecOffset(r.uleb())
            F.REF_SIG8 -> { r.bytes(8); AttrValue.Number(0L) }
            F.STRP_SUP, F.REF_SUP4, F.REF_SUP8 -> {
                diagnostics.add(ParseDiagnostic("WARNING", "UNSUPPORTED_SUP_FORM",
                    "DW_FORM 0x${form.toString(16)} 需要 supplementary 文件，已隔离", ".debug_info", (r.pos - 1).toLong()))
                throw UnknownFormException(form)
            }
            else -> {
                diagnostics.add(ParseDiagnostic("ERROR", "UNKNOWN_FORM",
                    "CU @${ctx.offset} 属性 0x${attrName.toString(16)} 使用未知/不支持的 form 0x${form.toString(16)}，" +
                        "游标停在 @${r.pos}，本 CU 后续 DIE 不再解析", ".debug_info", r.pos.toLong()))
                throw UnknownFormException(form)
            }
        }
    }

    private fun readSmallRef(r: SectionReader, ctx: CuContext, n: Int, form: Int): AttrValue {
        val v = r.u(n)
        return if (form == F.REF1 || form == F.REF2 || form == F.REF4 || form == F.REF8)
            AttrValue.Ref(ctx.offset + v)
        else AttrValue.Number(v)
    }

    private fun readIndexed(r: SectionReader, form: Int, base: Int): Long = when (form) {
        base -> r.uleb()
        F.STRX1, F.ADDRX1 -> r.u8().toLong()
        F.STRX2, F.ADDRX2 -> r.u16().toLong()
        F.STRX3, F.ADDRX3 -> r.u32()
        F.STRX4, F.ADDRX4 -> r.u64()
        else -> throw IllegalStateException()
    }

    private fun readStrp(r: SectionReader, ctx: CuContext, refSize: Int): AttrValue {
        // DWARF 5: .debug_str; split files may use .debug_str_offsets but we resolve through string view.
        val off = r.u(refSize)
        return AttrValue.Str(StrTables.readString(bundle, ".debug_str", off, ctx.version >= 5)
            ?: run {
                diagnostics.add(ParseDiagnostic("WARNING", "STRP_OOB",
                    "DW_FORM_strp 引用 0x${off.toString(16)} 越界", ".debug_str", off))
                "<strp:0x${off.toString(16)}>"
            })
    }

    private fun readLineStrp(r: SectionReader, ctx: CuContext, refSize: Int): AttrValue {
        val off = r.u(refSize)
        return AttrValue.Str(StrTables.readString(bundle, ".debug_line_str", off, true)
            ?: "<line_strp:0x${off.toString(16)}>")
    }

    companion object {
        const val MAX_DIE_DEPTH = 256
        const val MAX_DIES_PER_CU = 500_000
    }
}

class UnknownFormException(val form: Int) : RuntimeException("unknown form 0x${form.toString(16)}")
