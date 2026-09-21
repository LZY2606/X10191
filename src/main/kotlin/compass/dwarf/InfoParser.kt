package compass.dwarf

import compass.elf.ByteReader
import compass.elf.ParseException

/**
 * Parses .debug_info / .debug_info.dwo. A corrupt unit is reported as an issue
 * and aborts that unit only; unknown forms throw before any cursor advance is
 * trusted, so they cannot produce fabricated sibling DIEs.
 */
class InfoParser(private val sections: DebugSections, private val useSplit: Boolean) {
    private val info: SectionView? = if (useSplit) sections.infoDwo else sections.info
    private val abbrevTable: AbbrevTable? =
        (if (useSplit) sections.abbrevDwo else sections.abbrev)?.let { AbbrevTable(it.slice()) }

    fun parseAll(): Pair<List<CompilationUnit>, List<SectionIssue>> {
        val units = ArrayList<CompilationUnit>()
        val issues = ArrayList<SectionIssue>()
        val sec = info ?: return units to issues
        var guard = 0
        var rel = 0
        while (rel < sec.len) {
            if (++guard > Limits.MAX_UNITS) {
                issues.add(SectionIssue(name(), rel.toLong(), "CU 数量超上限")); break
            }
            try {
                val r = ByteReader(sec.data, sec.off + rel)
                val ul = readUnitLength(r)
                val cu = parseUnit(r, ul, rel.toLong())
                units.add(cu)
                val lenField = if (ul.dwarf64) 12 else 4
                rel = (ul.headerStart - sec.off) + lenField + ul.length.toInt()
            } catch (e: ParseException) {
                issues.add(SectionIssue(name(), rel.toLong(), e.message ?: "解析失败"))
                break
            }
        }
        return units to issues
    }

    private fun name() = if (useSplit) ".debug_info.dwo" else ".debug_info"

    private fun parseUnit(r: ByteReader, ul: UnitLength, unitStart: Long): CompilationUnit {
        val unitIssues = ArrayList<String>()
        val ci = CuInfo(dwarf64 = ul.dwarf64)
        ci.version = r.u16(true, "CU version")
        if (ci.version !in 2..5) throw ParseException("不支持的 DWARF 版本: ${ci.version}")

        var dwoId: Long? = null
        if (ci.version >= 5) {
            ci.unitType = r.u8("unit_type")
            ci.addressSize = r.u8("address_size")
            ci.abbrevOffset = r.u64Compat(ul.dwarf64, "abbrev_offset")
            dwoId = r.u64(true, "dwo_id")
            ci.isSplit = ci.unitType == DW_UT_split_compile
        } else {
            ci.abbrevOffset = r.u64Compat(ul.dwarf64, "abbrev_offset")
            ci.addressSize = r.u8("address_size")
        }

        val decls = (abbrevTable ?: throw ParseException("缺少 .debug_abbrev")).setAt(ci.abbrevOffset)
        val unitEnd = ul.afterLength + ul.length.toInt()
        val root = parseTree(r, decls, ci, unitEnd, 0, unitStart, unitIssues)
            ?: throw ParseException("CU 缺少根 DIE")

        ci.strOffsetsBase = root.num(DW_AT_str_offsets_base) ?: 0L
        ci.addrBase = root.num(DW_AT_addr_base) ?: root.num(DW_AT_GNU_addr_base) ?: 0L
        ci.rnglistsBase = root.num(DW_AT_rnglists_base) ?: 0L

        val cu = CompilationUnit(
            offset = unitStart, length = ul.length, version = ci.version,
            dwarf64 = ul.dwarf64, isSplit = ci.isSplit, unitType = ci.unitType,
            abbrevOffset = ci.abbrevOffset, addressSize = ci.addressSize,
            segmentSize = ci.segmentSize, dwoId = dwoId,
            dwoName = root.str(DW_AT_dwo_name) ?: root.str(DW_AT_GNU_dwo_name),
            compDir = root.str(DW_AT_comp_dir), name = root.str(DW_AT_name),
            root = root, lineProgram = null, ranges = emptyList(), issues = unitIssues,
            strOffsetsBase = ci.strOffsetsBase, addrBase = ci.addrBase,
            rnglistsBase = ci.rnglistsBase
        )
        bind(root, cu)
        return cu
    }

    private fun bind(die: Die, cu: CompilationUnit) {
        die.cu = cu
        for (c in die.children) bind(c, cu)
    }

    private fun parseTree(
        r: ByteReader, decls: Map<Long, AbbrevDecl>, ci: CuInfo,
        unitEnd: Int, depth: Int, unitStart: Long, issues: MutableList<String>
    ): Die? {
        if (depth > Limits.MAX_DIE_DEPTH) throw ParseException("DIE 嵌套过深")
        val rel = globalToRel(r.pos)
        val code = Leb.uleb(r, "abbrev code")
        if (code == 0L) return null
        val decl = decls[code] ?: throw ParseException("abbrev code=$code 未定义 @CU$unitStart+$rel")

        val attrs = LinkedHashMap<Int, Attr>()
        for (a in decl.attrs) attrs[a.name] = Attr(a.name, a.form, decodeAttr(r, a, ci))

        val children = ArrayList<Die>()
        if (decl.hasChildren) {
            var guard = 0
            while (r.pos < unitEnd && guard < Limits.MAX_DIES_PER_CU) {
                guard++
                val mark = r.pos
                if (Leb.uleb(r, "child code peek") == 0L) break
                r.pos = mark
                children.add(parseTree(r, decls, ci, unitEnd, depth + 1, unitStart, issues) ?: break)
            }
        }
        return Die(rel, decl.tag, attrs, children)
    }

    private fun globalToRel(global: Int): Long {
        val base = info!!.off
        return (global - base).toLong()
    }

    private fun decodeAttr(r: ByteReader, a: AbbrevAttr, ci: CuInfo): AttrValue {
        var form = a.form
        if (form == DW_FORM_implicit_const) return AttrValue.Num(a.implicitConst)
        if (form == DW_FORM_indirect) form = Leb.uleb(r, "indirect form").toInt()
        return when (form) {
            DW_FORM_addr -> AttrValue.Num(r.readAddr(ci.addressSize))
            DW_FORM_data1, DW_FORM_flag -> AttrValue.Num(r.u8().toLong())
            DW_FORM_data2 -> AttrValue.Num(r.u16(true).toLong())
            DW_FORM_data4 -> AttrValue.Num(r.u32(true))
            DW_FORM_data8, DW_FORM_ref_sig8 -> AttrValue.Num(r.u64(true))
            DW_FORM_sdata -> AttrValue.Num(Leb.sleb(r))
            DW_FORM_udata -> AttrValue.Num(Leb.uleb(r))
            DW_FORM_flag_present -> AttrValue.Num(1)
            DW_FORM_data16 -> { r.bytes(16); AttrValue.Num(0) }
            DW_FORM_string -> AttrValue.Str(readInline(r))
            DW_FORM_strp -> AttrValue.Str(sections.resolveString(r.u64Compat(ci.dwarf64).toInt()) ?: "")
            DW_FORM_line_strp -> AttrValue.Str(sections.resolveLineString(r.u64Compat(ci.dwarf64).toInt()) ?: "")
            DW_FORM_sec_offset -> AttrValue.SecOffset(r.u64Compat(ci.dwarf64))
            DW_FORM_exprloc -> { val n = Leb.uleb(r).toInt(); r.bytes(n); AttrValue.Num(0) }
            DW_FORM_block1 -> { r.bytes(r.u8()); AttrValue.Num(0) }
            DW_FORM_block2 -> { r.bytes(r.u16(true)); AttrValue.Num(0) }
            DW_FORM_block4 -> { r.bytes(r.u32(true).toInt()); AttrValue.Num(0) }
            DW_FORM_block -> { r.bytes(Leb.uleb(r).toInt()); AttrValue.Num(0) }
            DW_FORM_ref1 -> AttrValue.Ref(r.u8().toLong())
            DW_FORM_ref2 -> AttrValue.Ref(r.u16(true).toLong())
            DW_FORM_ref4 -> AttrValue.Ref(r.u32(true))
            DW_FORM_ref8 -> AttrValue.Ref(r.u64(true))
            DW_FORM_ref_udata, DW_FORM_ref_addr -> AttrValue.Ref(Leb.uleb(r))
            DW_FORM_strx1 -> AttrValue.Str(strx(ci, r.u8().toLong()) ?: "")
            DW_FORM_strx2 -> AttrValue.Str(strx(ci, r.u16(true).toLong()) ?: "")
            DW_FORM_strx3 -> AttrValue.Str(strx(ci, ((r.u8() or (r.u8() shl 8) or (r.u8() shl 16)) and 0xffffff).toLong()) ?: "")
            DW_FORM_strx4 -> AttrValue.Str(strx(ci, r.u32(true)) ?: "")
            DW_FORM_strx -> AttrValue.Str(strx(ci, Leb.uleb(r)) ?: "")
            DW_FORM_addrx1 -> AttrValue.AddrIndex(r.u8().toLong())
            DW_FORM_addrx2 -> AttrValue.AddrIndex(r.u16(true).toLong())
            DW_FORM_addrx3 -> AttrValue.AddrIndex(((r.u8() or (r.u8() shl 8) or (r.u8() shl 16)) and 0xffffff).toLong())
            DW_FORM_addrx4 -> AttrValue.AddrIndex(r.u32(true))
            DW_FORM_addrx -> AttrValue.AddrIndex(Leb.uleb(r))
            DW_FORM_rnglistx -> AttrValue.RngIndex(Leb.uleb(r))
            else -> throw ParseException("未知 DW_FORM=0x${form.toString(16)}, 隔离该 unit")
        }
    }

    private fun strx(ci: CuInfo, index: Long): String? {
        val sec = sections.strOffsetsFor(ci.isSplit)
            ?: throw ParseException("strx 缺少 .debug_str_offsets")
        val es = if (ci.dwarf64) 8 else 4
        val p = ci.strOffsetsBase + index * es
        if (p < 0 || p + es > sec.len) throw ParseException("strx 越界 idx=$index")
        val r = ByteReader(sec.data, sec.off + p.toInt())
        return sections.resolveString(r.u64Compat(ci.dwarf64).toInt())
    }

    private fun readInline(r: ByteReader): String {
        val start = r.pos
        while (r.pos < r.size && r.data[r.pos] != 0.toByte()) r.pos++
        val s = String(r.data, start, r.pos - start, Charsets.UTF_8)
        if (r.pos < r.size) r.pos++
        return s
    }
}
