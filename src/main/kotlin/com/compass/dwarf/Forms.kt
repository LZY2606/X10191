package com.compass.dwarf

/** Resolves string attributes against .debug_str / .debug_line_str / str_offsets. */
class StringTables(private val sections: SectionSet) {
    private val debugStr = sections.bytes(".debug_str")
    private val lineStr = sections.bytes(".debug_line_str")

    fun resolve(v: AttrValue?, ctx: CuContext): String? = when (v) {
        null -> null
        is AttrValue.Str -> v.v
        is AttrValue.StrRef -> readCString(if (v.lineStr) lineStr else debugStr, v.offset)
        is AttrValue.Strx -> {
            val off = strxOffset(ctx, v.index) ?: return null
            readCString(debugStr, off)
        }
        else -> null
    }

    private fun strxOffset(ctx: CuContext, index: Int): Long? {
        val base = ctx.strOffsetsBase ?: run {
            ctx // no base: index 0 in DWARF5 implies CU-local base 0 for some producers
            return strOffsetAt(0L, index, ctx)
        }
        return strOffsetAt(base, index, ctx)
    }

    private fun strOffsetAt(base: Long, index: Int, ctx: CuContext): Long? {
        val dwoName = if (ctx.isDwo) ".debug_str_offsets.dwo" else ".debug_str_offsets"
        val data = sections.bytes(if (sections.has(dwoName)) dwoName else ".debug_str_offsets")
        if (data.isEmpty()) return null
        try {
            val b = Buf(data)
            if (ctx.version >= 5) {
                // base points at the unit_length prefix; entries begin after
                // length(4/12) + header body (2+2+4 = 8 in 32-bit form).
                b.seek(base.toInt())
                val first = b.u32()
                val dwarf64 = first == 0xffff_ffffL
                if (dwarf64) b.u64()
                b.u16(); b.u16(); b.u32() // version, padding, count
                val entrySize = ctx.addressSize
                b.seek(b.pos + index * entrySize)
                return if (entrySize == 8) b.u64() else b.u32()
            } else {
                b.seek(base.toInt() + index * ctx.addressSize)
                return if (ctx.addressSize == 8) b.u64() else b.u32()
            }
        } catch (e: ParseException) {
            return null
        }
    }

    private fun readCString(data: ByteArray, off: Long): String? {
        if (data.isEmpty() || off < 0 || off >= data.size) return null
        return try { Buf(data).cstringAt(off.toInt()) } catch (e: ParseException) { null }
    }
}

object FormReader {
    fun read(strings: StringTables, ctx: CuContext, buf: Buf, formIn: Long, implicit: Long,
             issues: MutableList<ParseIssue>): AttrValue {
        var form = formIn
        if (form == DW_FORM_indirect.toLong()) form = buf.uleb().toLong()
        return when (form) {
            DW_FORM_addr.toLong() -> AttrValue.Addr(buf.unsigned(ctx.addressSize).toLong())
            DW_FORM_data1.toLong() -> AttrValue.Num(buf.u8().toLong())
            DW_FORM_data2.toLong() -> AttrValue.Num(buf.u16().toLong())
            DW_FORM_data4.toLong() -> AttrValue.Num(buf.u32())
            DW_FORM_data8.toLong() -> AttrValue.Num(buf.u64())
            DW_FORM_sdata.toLong() -> AttrValue.Num(buf.sleb())
            DW_FORM_udata.toLong() -> AttrValue.Num(buf.uleb().toLong())
            DW_FORM_flag.toLong() -> AttrValue.Num(buf.u8().toLong())
            DW_FORM_flag_present.toLong() -> AttrValue.Num(1L)
            DW_FORM_implicit_const.toLong() -> AttrValue.Num(implicit)
            DW_FORM_string.toLong() -> AttrValue.Str(buf.cstring())
            DW_FORM_strp.toLong() -> AttrValue.StrRef(if (ctx.dwarf64) buf.u64() else buf.u32(), false)
            DW_FORM_line_strp.toLong() -> AttrValue.StrRef(if (ctx.dwarf64) buf.u64() else buf.u32(), true)
            DW_FORM_strx.toLong() -> AttrValue.Strx(buf.uleb().toInt())
            DW_FORM_strx1.toLong() -> AttrValue.Strx(buf.u8())
            DW_FORM_strx2.toLong() -> AttrValue.Strx(buf.u16())
            DW_FORM_strx3.toLong() -> AttrValue.Strx(buf.u8() or (buf.u8() shl 8) or (buf.u8() shl 16))
            DW_FORM_strx4.toLong() -> AttrValue.Strx(buf.u32().toInt())
            DW_FORM_addrx.toLong() -> readAddrx(ctx, buf.uleb().toInt())
            DW_FORM_addrx1.toLong() -> readAddrx(ctx, buf.u8())
            DW_FORM_addrx2.toLong() -> readAddrx(ctx, buf.u16())
            DW_FORM_addrx3.toLong() -> readAddrx(ctx, buf.u8() or (buf.u8() shl 8) or (buf.u8() shl 16))
            DW_FORM_addrx4.toLong() -> readAddrx(ctx, buf.u32().toInt())
            DW_FORM_ref1.toLong() -> AttrValue.Ref(ctx.cuStart + buf.u8(), FormClass.REF)
            DW_FORM_ref2.toLong() -> AttrValue.Ref(ctx.cuStart + buf.u16(), FormClass.REF)
            DW_FORM_ref4.toLong() -> AttrValue.Ref(ctx.cuStart + buf.u32().toInt(), FormClass.REF)
            DW_FORM_ref8.toLong() -> AttrValue.Ref(buf.u64().toInt(), FormClass.REF)
            DW_FORM_ref_udata.toLong() -> AttrValue.Ref(ctx.cuStart + buf.uleb().toInt(), FormClass.REF)
            DW_FORM_ref_addr.toLong() -> {
                val size = if (ctx.dwarf64 || ctx.version >= 5) ctx.addressSize else 4
                AttrValue.Ref(buf.unsigned(size).toInt(), FormClass.REF)
            }
            DW_FORM_sec_offset.toLong() -> AttrValue.SecOffset(if (ctx.dwarf64) buf.u64() else buf.u32(), FormClass.UNKNOWN)
            DW_FORM_data16.toLong() -> AttrValue.Block(buf.bytes(16))
            DW_FORM_block1.toLong() -> AttrValue.Block(buf.bytes(buf.u8()))
            DW_FORM_block2.toLong() -> AttrValue.Block(buf.bytes(buf.u16()))
            DW_FORM_block4.toLong() -> AttrValue.Block(buf.bytes(buf.u32().toInt()))
            DW_FORM_block.toLong() -> AttrValue.Block(buf.bytes(buf.uleb().toInt()))
            DW_FORM_exprloc.toLong() -> AttrValue.Block(buf.bytes(buf.uleb().toInt()))
            DW_FORM_rnglistx.toLong() -> AttrValue.SecOffset(buf.uleb().toLong(), FormClass.RNGLIST)
            DW_FORM_loclistx.toLong() -> AttrValue.SecOffset(buf.uleb().toLong(), FormClass.LOCLIST)
            DW_FORM_ref_sig8.toLong() -> AttrValue.SecOffset(buf.u64(), FormClass.REF)
            else -> {
                issues += ParseIssue("form", "unknown/unsupported DW_FORM 0x${form.toString(16)}; CU DIE parse isolated", "error")
                throw ParseException("unsupported form 0x${form.toString(16)}")
            }
        }
    }

    private fun readAddrx(ctx: CuContext, index: Int): AttrValue.Addr {
        val data = ctx.sections.bytes(if (ctx.isDwo) ".debug_addr.dwo" else ".debug_addr")
        val base = ctx.addrBase ?: 0L
        if (data.isEmpty()) throw ParseException("DW_FORM_addrx with no .debug_addr section")
        val b = Buf(data)
        val pos = base.toInt() + index * ctx.addressSize
        b.seek(pos)
        return AttrValue.Addr(b.unsigned(ctx.addressSize).toLong())
    }

    
}
