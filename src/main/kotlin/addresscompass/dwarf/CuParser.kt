package addresscompass.dwarf

import addresscompass.model.AddrRange
import addresscompass.model.AttrVal
import addresscompass.model.CompileUnit
import addresscompass.model.DIE
import addresscompass.model.FormValue
import addresscompass.model.ParseIssue
import addresscompass.model.Severity
import addresscompass.model.Trust
import java.nio.ByteOrder

class CuParseAbort(message: String) : RuntimeException(message)

class CuBuilder(
    val sections: DebugSections,
    val endian: ByteOrder,
    val issues: MutableList<ParseIssue>,
    val isSplitFile: Boolean,
)

object CuParser {
    private const val MAX_DIE_DEPTH = 64
    private const val MAX_DIE_COUNT = 1 shl 22
    private const val MAX_REF_HOPS = 16

    /** Parse every unit header + DIE tree in .debug_info (or .debug_info.dwo). */
    fun parseAll(ctx: CuBuilder): List<CompileUnit> {
        val info = if (ctx.isSplitFile) ctx.sections.infoDwo else ctx.sections.info
        val out = mutableListOf<CompileUnit>()
        if (info == null || info.isEmpty()) return out
        var id = 0
        var pos = 0
        while (pos < info.size) {
            val unitStart = pos
            val cu = try {
                parseOne(ctx, info, pos, id++)
            } catch (e: SectionTruncatedException) {
                ctx.issues += ParseIssue(Severity.ERROR, ".debug_info", pos.toLong(), e.message ?: "truncated CU", true)
                break
            }
            out += cu
            pos = (unitStart + headerAndBodyLength(info, unitStart, ctx.endian)).toInt()
            if (pos <= unitStart) break
        }
        return out
    }

    private fun headerAndBodyLength(info: ByteArray, start: Int, endian: ByteOrder): Long {
        val r = ByteReader(info, start, info.size, endian)
        val w = r.u32()
        return if (w == 0xffffffffL) 12 + r.u64() else 4 + w
    }

    private fun parseOne(ctx: CuBuilder, info: ByteArray, start: Int, id: Int): CompileUnit {
        val r = ByteReader(info, endian = ctx.endian)
        r.seek(start)
        val lengthWord = r.u32()
        val dwarf64 = lengthWord == 0xffffffffL
        val bodyLen = if (dwarf64) r.u64() else lengthWord
        val unitEnd = (if (dwarf64) start + 12 else start + 4) + bodyLen
        if (unitEnd > info.size) throw SectionTruncatedException("CU at 0x${start.toString(16)} overruns .debug_info")
        val b = r.sliceReader(start + (if (dwarf64) 12 else 4), bodyLen.toInt())

        val version = b.u16()
        var unitType = Dwarf.UT_COMPILE
        var addressSize = 8
        var abbrevOffset: Long
        if (version >= 5) {
            unitType = b.u8()
            addressSize = b.u8()
            abbrevOffset = b.sizedInt(if (dwarf64) 8 else 4)
            if (unitType == Dwarf.UT_TYPE || unitType == Dwarf.UT_SPLIT_TYPE) {
                b.sizedInt(if (dwarf64) 8 else 4) // type_signature
                b.sizedInt(if (dwarf64) 8 else 4) // type_offset
            }
        } else {
            abbrevOffset = b.sizedInt(if (dwarf64) 8 else 4)
            addressSize = b.u8()
        }

        val cuIssues = mutableListOf<ParseIssue>()
        val abbrevSection = if (ctx.isSplitFile) ctx.sections.abbrevDwo ?: ctx.sections.abbrev else ctx.sections.abbrev
        val table = AbbrevParser.parseTable(abbrevSection, abbrevOffset, ctx.endian)
        cuIssues += table.issues

        var root: DIE? = null
        var trust = Trust.FULL
        try {
            root = parseDies(ctx, b, table, cuIssues, addressSize, version, dwarf64)
        } catch (e: CuParseAbort) {
            trust = Trust.UNRELIABLE
            cuIssues += ParseIssue(Severity.ERROR, ".debug_info", start.toLong(), e.message ?: "CU abandoned", true)
        } catch (e: SectionTruncatedException) {
            trust = Trust.UNRELIABLE
            cuIssues += ParseIssue(Severity.ERROR, ".debug_info", start.toLong(), e.message ?: "truncated DIE stream", true)
        }

        if (root == null) {
            trust = Trust.UNRELIABLE
        }

        val name = root?.string()
        val compDir = (root?.attr(Dwarf.DW_AT_comp_dir)?.value as? FormValue.Str)?.s
        val stmt = root?.udata(Dwarf.DW_AT_stmt_list)
        val lowPc = (root?.attr(Dwarf.DW_AT_low_pc)?.value as? FormValue.AddrV)?.v
        val dwoId = root?.udata(Dwarf.DW_AT_GNU_dwo_id) ?: root?.udata(Dwarf.DW_AT_dwo_id)
        val dwoName = ((root?.attr(Dwarf.DW_AT_dwo_name)?.value as? FormValue.Str)?.s
            ?: (root?.attr(Dwarf.DW_AT_GNU_dwo_name)?.value as? FormValue.Str)?.s)
        val isSkeleton = version >= 5 && unitType == Dwarf.UT_SKELETON ||
            (version == 4 && dwoName != null)
        val isSplit = ctx.isSplitFile || (version >= 5 && unitType == Dwarf.UT_SPLIT_COMPILE)
        val rnglistsBase = root?.udata(Dwarf.DW_AT_rnglists_base) ?: root?.udata(Dwarf.DW_AT_GNU_ranges_base)
        val addrBase = root?.udata(Dwarf.DW_AT_addr_base) ?: rnglistsBase
        val strBase = root?.udata(Dwarf.DW_AT_str_offsets_base)

        return CompileUnit(
            id = id, sectionOffset = start.toLong(), unitLength = bodyLen, version = version,
            dwarf64 = dwarf64, unitType = unitType, addressSize = addressSize, abbrevOffset = abbrevOffset,
            root = root, name = name, compDir = compDir, stmtListOffset = stmt, lowPc = lowPc,
            dwoId = dwoId, dwoName = dwoName, isSkeleton = isSkeleton, isSplit = isSplit,
            rnglistsBase = rnglistsBase, addrBase = addrBase, strOffsetsBase = strBase,
            issues = cuIssues, trust = trust,
        )
    }

    private fun parseDies(
        ctx: CuBuilder, b: ByteReader, table: AbbrevTable,
        cuIssues: MutableList<ParseIssue>, addressSize: Int, version: Int, dwarf64: Boolean,
    ): DIE? {
        val layout = FormLayout(version, dwarf64, addressSize, ctx.isSplitFile)
        var root: DIE? = null
        var current: DIE? = null
        var depth = 0
        var count = 0
        while (b.remaining > 0) {
            val dieOffset = b.absoluteOffsetInSection()
            val code = b.uleb()
            if (code == 0L) {
                if (depth == 0) break
                depth--
                current = current?.parent
                continue
            }
            if (++count > MAX_DIE_COUNT) throw CuParseAbort("DIE count limit exceeded")
            val decl = table.byCode(code)
                ?: throw CuParseAbort("abbrev code $code not found in table (corrupt .debug_abbrev)")
            val attrs = ArrayList<AttrVal>(decl.attrs.size)
            for (spec in decl.attrs) {
                val value = try {
                    readAttr(ctx, b, spec, layout, cuIssues)
                } catch (e: UnknownFormException) {
                    throw CuParseAbort("${e.message} at DIE 0x${dieOffset.toString(16)}; CU abandoned to keep cursor aligned")
                }
                attrs += AttrVal(spec.attr, spec.form, value)
            }
            val die = DIE(dieOffset, decl.tag, decl.hasChildren, attrs, depth)
            if (depth == 0) root = die else current?.children?.add(die)
            die.parent = current
            if (decl.hasChildren) {
                depth++
                if (depth > MAX_DIE_DEPTH) throw CuParseAbort("DIE nesting exceeds $MAX_DIE_DEPTH")
                current = die
            }
        }
        return root
    }

    private fun readAttr(
        ctx: CuBuilder, b: ByteReader, spec: AbbrevAttrSpec, layout: FormLayout,
        cuIssues: MutableList<ParseIssue>,
    ): FormValue {
        val form = spec.form
        if (form == Dwarf.DW_FORM_implicit_const) {
            return FormValue.Sdata(spec.implicitConst ?: 0L)
        }
        val raw = FormReader.read(b, form, layout)
        return when {
            raw is FormValue.SecOffset && (form == Dwarf.DW_FORM_strp || form == Dwarf.DW_FORM_line_strp) -> {
                val target = if (form == Dwarf.DW_FORM_line_strp)
                    ctx.sections.lineStr ?: ctx.sections.lineStrDwo
                else ctx.sections.str ?: ctx.sections.strDwo
                try {
                    FormValue.Str(ByteReader(target ?: ByteArray(0), endian = ctx.endian).stringAt(raw.v.toInt()))
                } catch (e: RuntimeException) {
                    cuIssues += ParseIssue(Severity.WARNING, ".debug_str", raw.v, "strp unreadable: ${e.message}", true)
                    FormValue.Str("<?>")
                }
            }
            else -> raw
        }
    }
}
