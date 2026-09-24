package com.luopan.dwarf

/**
 * 解析所需的全部 section 字节（ELF 解析 + 重定位后）。
 * 允许缺失：相关能力降级并产生诊断，而不是整体失败。
 */
class DwarfSections(
    val info: ByteArray? = null,
    val abbrev: ByteArray? = null,
    val line: ByteArray? = null,
    val ranges: ByteArray? = null,
    val rnglists: ByteArray? = null,
    val str: ByteArray? = null,
    val lineStr: ByteArray? = null,
    val strOffsets: ByteArray? = null,
    val addr: ByteArray? = null,
    val loc: ByteArray? = null,
    val loclists: ByteArray? = null,
    val abbrevDwo: ByteArray? = null,
    val infoDwo: ByteArray? = null,
    val strDwo: ByteArray? = null,
    val strOffsetsDwo: ByteArray? = null,
    val lineDwo: ByteArray? = null,
    val lineStrDwo: ByteArray? = null,
) {
    companion object {
        private val INFO_NAMES = listOf(".debug_info", ".zdebug_info", "__debug_info")
        private val ABBR_NAMES = listOf(".debug_abbrev", ".zdebug_abbrev")
        private val ABBR_DWO_NAMES = listOf(".debug_abbrev.dwo", ".debug_abbrev_dwo")
        private val INFO_DWO_NAMES = listOf(".debug_info.dwo", ".debug_info_dwo")

        fun from(map: Map<String, ByteArray>): DwarfSections {
            fun first(names: List<String>) = names.firstNotNullOfOrNull { map[it] }
            return DwarfSections(
                info = first(INFO_NAMES),
                abbrev = first(ABBR_NAMES),
                line = map[".debug_line"],
                ranges = map[".debug_ranges"],
                rnglists = map[".debug_rnglists"],
                str = map[".debug_str"],
                lineStr = map[".debug_line_str"],
                strOffsets = map[".debug_str_offsets"],
                addr = map[".debug_addr"],
                loc = map[".debug_loc"],
                loclists = map[".debug_loclists"],
                abbrevDwo = first(ABBR_DWO_NAMES),
                infoDwo = first(INFO_DWO_NAMES),
                strDwo = map[".debug_str.dwo"] ?: map[".debug_str_offsets.dwo"]?.let { null },
                strOffsetsDwo = map[".debug_str_offsets.dwo"],
                lineDwo = map[".debug_line.dwo"],
                lineStrDwo = map[".debug_line_str.dwo"],
            )
        }
    }
}

/** 单个 CU 解码 form 所需的上下文。 */
class UnitContext(
    val version: Int,
    val addressSize: Int,
    val offsetSize: Int,
    val dwarf64: Boolean,
    val cuSectionOffset: Int,
    val strOffsetsBase: Long?,
    val addrBase: Long?,
    val sections: DwarfSections,
    val strSectionIsDwo: Boolean = false,
    val jumps: JumpBudget,
    val resolve: Boolean = true,
)

object FormDecoder {
    fun read(b: Binary, form: Int, ctx: UnitContext, implicit: Long?): AttrVal {
        val sec = ctx.sections
        return when (form) {
            DwarfForm.ADDR -> AttrVal.Addr(b.uint(ctx.addressSize))
            DwarfForm.DATA1 -> AttrVal.Const(b.u1().toLong())
            DwarfForm.DATA2 -> AttrVal.Const(b.u2().toLong())
            DwarfForm.DATA4 -> AttrVal.Const(b.u4().toLong() and 0xffffffffL)
            DwarfForm.DATA8 -> AttrVal.Const(b.u8())
            DwarfForm.DATA_SDATA -> AttrVal.Const(b.sleb())
            DwarfForm.DATA_UDATA -> AttrVal.Const(b.uleb())
            DwarfForm.IMPLICIT_CONST -> AttrVal.Const(implicit ?: 0L)
            DwarfForm.STRING -> AttrVal.Str(b.cstring())
            DwarfForm.STRP -> {
                val off = b.uint(ctx.offsetSize).toInt()
                if (ctx.resolve) AttrVal.Str(readStringAt(sec, ctx.strSectionIsDwo, off))
                else AttrVal.Strp(off)
            }
            DwarfForm.LINE_STRP -> {
                val off = b.uint(ctx.offsetSize).toInt()
                if (!ctx.resolve) AttrVal.LineStrp(off)
                else {
                    val data = (if (ctx.strSectionIsDwo) sec.lineStrDwo else sec.lineStr)
                        ?: throw DwarfReadException("DW_FORM_line_strp without .debug_line_str")
                    AttrVal.Str(cstringAt(data, off))
                }
            }
            DwarfForm.REF1 -> AttrVal.Ref(b.u1(), global = false)
            DwarfForm.REF2 -> AttrVal.Ref(b.u2(), global = false)
            DwarfForm.REF4 -> AttrVal.Ref(b.u4(), global = ctx.version <= 3)
            DwarfForm.REF8 -> AttrVal.Ref(b.u8().toInt(), global = true)
            DwarfForm.REF_UDATA -> AttrVal.Ref(b.uleb().toInt(), global = true)
            DwarfForm.REF_SIG8 -> AttrVal.Sig(b.u8())
            DwarfForm.FLAG -> AttrVal.Flag(b.u1() != 0)
            DwarfForm.FLAG_PRESENT -> AttrVal.Flag(true)
            DwarfForm.SEC_OFFSET -> AttrVal.SecOffset(b.uint(ctx.offsetSize))
            DwarfForm.EXPRLOC -> { val n = b.uleb().toInt(); AttrVal.Expr(b.readBytes(n)) }
            DwarfForm.BLOCK -> { val n = b.uleb().toInt(); AttrVal.Expr(b.readBytes(n)) }
            DwarfForm.BLOCK1 -> { val n = b.u1(); AttrVal.Expr(b.readBytes(n)) }
            DwarfForm.BLOCK2 -> { val n = b.u2(); AttrVal.Expr(b.readBytes(n)) }
            DwarfForm.BLOCK4 -> { val n = b.u4(); AttrVal.Expr(b.readBytes(n)) }
            DwarfForm.BLOCK8 -> { val n = b.u8().toInt(); AttrVal.Expr(b.readBytes(n)) }
            DwarfForm.STRX, DwarfForm.GNU_STR_INDEX -> strx(b.uleb().toInt(), ctx)
            DwarfForm.STRX1 -> strx(b.u1(), ctx)
            DwarfForm.STRX2 -> strx(b.u2(), ctx)
            DwarfForm.STRX3 -> strx(b.uleb().toInt(), ctx)
            DwarfForm.STRX4 -> strx(b.u4(), ctx)
            DwarfForm.ADDRX, DwarfForm.GNU_ADDR_INDEX -> addrx(b.uleb().toInt(), ctx)
            DwarfForm.ADDRX1 -> addrx(b.u1(), ctx)
            DwarfForm.ADDRX2 -> addrx(b.u2(), ctx)
            DwarfForm.ADDRX3 -> addrx(b.uleb().toInt(), ctx)
            DwarfForm.ADDRX4 -> addrx(b.u4(), ctx)
            DwarfForm.INDIRECT -> {
                val actual = b.uleb().toInt()
                if (actual == DwarfForm.INDIRECT) throw DwarfReadException("nested DW_FORM_indirect")
                read(b, actual, ctx, null)
            }
            else -> throw DwarfReadException("unknown DWARF form 0x%x".format(form))
        }
    }

    private fun strx(index: Int, ctx: UnitContext): AttrVal {
        if (!ctx.resolve) return AttrVal.Strx(index)
        val base = ctx.strOffsetsBase
            ?: throw DwarfReadException("DW_FORM_strx without str_offsets_base")
        val data = (if (ctx.strSectionIsDwo) ctx.sections.strOffsetsDwo else ctx.sections.strOffsets)
            ?: throw DwarfReadException("DW_FORM_strx without .debug_str_offsets")
        val off = (base + index.toLong() * ctx.offsetSize).toInt()
        val sb = Binary(data, 0, data.size)
        sb.seek(off)
        val strOff = sb.uint(ctx.offsetSize).toInt()
        return AttrVal.Str(readStringAt(ctx.sections, ctx.strSectionIsDwo, strOff))
    }

    private fun addrx(index: Int, ctx: UnitContext): AttrVal {
        if (!ctx.resolve) return AttrVal.Addrx(index)
        val base = ctx.addrBase ?: 0L
        val data = ctx.sections.addr
            ?: throw DwarfReadException("DW_FORM_addrx without .debug_addr")
        val off = (base + index.toLong() * ctx.addressSize).toInt()
        val ab = Binary(data, 0, data.size)
        ab.seek(off)
        return AttrVal.Addr(ab.uint(ctx.addressSize))
    }

    private fun readStringAt(sec: DwarfSections, dwo: Boolean, off: Int): String {
        val data = (if (dwo) sec.strDwo else sec.str)
            ?: throw DwarfReadException("string offset without .debug_str")
        return cstringAt(data, off)
    }

    fun cstringAt(data: ByteArray, off: Int): String {
        if (off < 0 || off >= data.size) throw DwarfReadException("string offset 0x%x out of bounds".format(off))
        return Binary(data, off, data.size - off).cstring()
    }
}
