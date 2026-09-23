package compass.dwarf

/**
 * Context needed to decode a DWARF form value. Unknown forms throw
 * [UnknownFormException]; callers isolate the whole CU instead of letting
 * the cursor drift into fabricated data.
 */
class FormContext(
    val sections: Sections,
    val version: Int,
    val addressSize: Int,
    val cuIs64: Boolean,
    val cuStart: Long,
    val addrBase: Long,
    val strBase: Long,
    val rngListsBase: Long,
    val addrTable: AddrTableView?,
    val strOffsets: StrOffsetsView?,
)

class FormReader(private val r: Reader, private val ctx: FormContext) {

    /** Read one attribute; returns the decoded value (string/long/bytes/unit offset). */
    fun read(attr: Int, form: Int, implicitConst: Long?): Any? {
        val resolved = if (form == DW.FORM_indirect) {
            val f = r.uleb128().toInt()
            if (f == DW.FORM_indirect || f == 0) throw UnknownFormException(f, "illegal DW_FORM_indirect nesting: 0x${f.toString(16)}")
            f
        } else form

        return when (resolved) {
            DW.FORM_addr -> readAddr()
            DW.FORM_data1, DW.FORM_ref1, DW.FORM_strx1, DW.FORM_addrx1 -> r.u8().toLong()
            DW.FORM_data2, DW.FORM_ref2, DW.FORM_strx2, DW.FORM_addrx2 -> r.u16().toLong()
            DW.FORM_data4 -> r.s32().toLong()
            DW.FORM_ref4 -> r.u32()
            DW.FORM_data8, DW.FORM_ref8, DW.FORM_ref_sig8 -> r.u64()
            DW.FORM_sdata -> r.sleb128()
            DW.FORM_udata, DW.FORM_ref_udata, DW.FORM_strx, DW.FORM_addrx -> r.uleb128()
            DW.FORM_sec_offset -> readOffset()
            DW.FORM_string -> r.zeroString()
            DW.FORM_strp -> {
                val off = readStrPtrWidth()
                ctx.sections.strAt(".debug_str", off)
            }
            DW.FORM_line_strp -> {
                val off = readStrPtrWidth()
                ctx.sections.strAt(".debug_line_str", off)
            }
            DW.FORM_strp_sup, DW.FORM_GNU_strp_alt -> {
                readStrPtrWidth() // lives in supplementary object we don't have
                "<supplementary string unavailable>"
            }
            DW.FORM_flag -> r.u8() != 0
            DW.FORM_flag_present -> true
            DW.FORM_exprloc, DW.FORM_block -> { val n = r.uleb128().toIntExact(); r.bytes(n) }
            DW.FORM_block1 -> { val n = r.u8(); r.bytes(n) }
            DW.FORM_block2 -> { val n = r.u16(); r.bytes(n) }
            DW.FORM_block4 -> { val n = r.u32().toIntExact(); r.bytes(n) }
            DW.FORM_data16 -> r.bytes(16)
            DW.FORM_ref_addr -> readOffset()
            DW.FORM_ref_sup4 -> r.u32()
            DW.FORM_ref_sup8 -> r.u64()
            DW.FORM_implicit_const -> implicitConst
                ?: throw UnknownFormException(resolved, "implicit_const without abbrev value")
            DW.FORM_GNU_addr_index, DW.FORM_GNU_str_index -> {
                val index = r.uleb128()
                if (resolved == DW.FORM_GNU_addr_index) readAddrIndex(index)
                else readStrIndex(index)
            }
            DW.FORM_rnglistx, DW.FORM_loclistx -> r.uleb128()
            else -> throw UnknownFormException(resolved, "unsupported form ${DW.formName(resolved)}")
        }
    }

    private fun readAddr(): Long = when (ctx.addressSize) {
        1 -> r.u8().toLong() and 0xff
        2 -> r.u16().toLong() and 0xffff
        4 -> r.u32()
        8 -> r.u64()
        else -> throw ParseError("unsupported address size ${ctx.addressSize}")
    }

    private fun readOffset(): Long = if (ctx.cuIs64) r.u64() else r.u32()
    private fun readStrPtrWidth(): Long = if (ctx.version >= 5) {
        if (ctx.cuIs64) r.u64() else r.u32()
    } else r.u32() // GNU split also uses 4-byte offsets here

    fun readAddrIndex(index: Long): Long {
        val view = ctx.addrTable ?: throw ParseError("addr index used but .debug_addr unavailable")
        return view.get(ctx.addrBase, index)
    }

    fun readStrIndex(index: Long): String {
        val view = ctx.strOffsets ?: throw ParseError("str index used but .debug_str_offsets unavailable")
        val off = view.get(ctx.strBase, index)
        return ctx.sections.strAt(".debug_str", off)
    }
}

private fun Long.toIntExact(): Int {
    if (this < 0 || this > Int.MAX_VALUE) throw ParseError("length overflow: $this")
    return toInt()
}
