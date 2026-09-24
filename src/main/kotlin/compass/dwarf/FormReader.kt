package compass.dwarf

import compass.binary.ByteReader
import compass.binary.ParseException
import compass.binary.sleb128
import compass.binary.uleb128

/**
 * Decodes one attribute form at the current cursor. Forms referencing other
 * sections (.debug_str, .debug_addr...) are either resolved immediately or
 * deferred via Pending* values; an unknown form throws UnknownForm so the
 * calling CU can be isolated exactly at a DIE boundary (cursor never desyncs).
 */
class UnknownFormException(val form: Int) : RuntimeException("unknown DWARF form 0x${form.toString(16)}")

class FormContext(
    val unit: CompUnit,
    val sections: DwarfSections,
    /** Offset of the current CU header inside .debug_info — used by ref forms. */
    val cuHeaderOffset: Long,
    val infoSectionName: String,
)

object FormReader {
    private const val MAX_LEB = 16

    @Suppress("UNUSED_PARAMETER")
    fun read(form: Int, implicitConst: Long, r: ByteReader, ctx: FormContext): AttrValue {
        val f = if (form == DW.FORM.indirect) r.uleb().toInt() else form
        return when (f) {
            DW.FORM.addr -> AttrValue.Addr(readAddr(r, ctx.unit.addressSize))

            DW.FORM.data1, DW.FORM.flag -> AttrValue.Const(r.u1().toLong())
            DW.FORM.data2 -> AttrValue.Const(r.u2().toLong())
            DW.FORM.data4 -> AttrValue.Const(r.u4().toLong() and 0xffffffffL)
            DW.FORM.data8 -> AttrValue.Const(r.u8())
            DW.FORM.udata, DW.FORM.ref_udata -> AttrValue.Const(uleb128(r, MAX_LEB, false))
            DW.FORM.sdata -> AttrValue.Const(sleb128(r, MAX_LEB))
            DW.FORM.flag_present -> AttrValue.Const(implicitConst or 1L)
            DW.FORM.implicit_const -> AttrValue.Const(implicitConst)

            DW.FORM.string -> AttrValue.Str(r.zeroString())
            DW.FORM.strp -> readStringFrom(r, ctx.sections, ".debug_str", ctx.unit, useLineStr = false)
            DW.FORM.line_strp -> readStringFrom(r, ctx.sections, ".debug_line_str", ctx.unit, useLineStr = true)
            DW.FORM.strp_sup -> readStringFrom(r, ctx.sections, ".debug_str", ctx.unit, false)
            DW.FORM.strx, DW.FORM.GNU_str_index ->
                AttrValue.PendingStrIndex(uleb128(r, MAX_LEB, false).toInt())
            DW.FORM.strx1 -> AttrValue.PendingStrIndex(r.u1())
            DW.FORM.strx2 -> AttrValue.PendingStrIndex(r.u2())
            DW.FORM.strx3 -> AttrValue.PendingStrIndex(read3(r))
            DW.FORM.strx4 -> AttrValue.PendingStrIndex(r.u4())

            DW.FORM.addrx, DW.FORM.GNU_addr_index ->
                AttrValue.PendingAddrIndex(uleb128(r, MAX_LEB, false).toInt())
            DW.FORM.addrx1 -> AttrValue.PendingAddrIndex(r.u1())
            DW.FORM.addrx2 -> AttrValue.PendingAddrIndex(r.u2())
            DW.FORM.addrx3 -> AttrValue.PendingAddrIndex(read3(r))
            DW.FORM.addrx4 -> AttrValue.PendingAddrIndex(r.u4())

            // ref1/2/4/8 are offsets relative to the start of the CU header;
            // ref_addr is an offset from the start of the .debug_info section.
            DW.FORM.ref1 -> AttrValue.Ref(ctx.cuHeaderOffset + r.u1().toLong())
            DW.FORM.ref2 -> AttrValue.Ref(ctx.cuHeaderOffset + r.u2().toLong())
            DW.FORM.ref4 -> AttrValue.Ref(ctx.cuHeaderOffset + (r.u4().toLong() and 0xffffffffL))
            DW.FORM.ref8 -> AttrValue.Ref(ctx.cuHeaderOffset + r.u8())
            DW.FORM.ref_addr -> {
                val raw = if (ctx.unit.is64BitDwarf) r.u8()
                else (r.u4().toLong() and 0xffffffffL)
                AttrValue.Ref(raw)
            }

            DW.FORM.sec_offset, DW.FORM.ref_sup8 -> AttrValue.SectionOffset(
                ctx.infoSectionName,
                if (ctx.unit.is64BitDwarf) r.u8() else (r.u4().toLong() and 0xffffffffL),
            )

            DW.FORM.rnglistx, DW.FORM.loclistx ->
                AttrValue.SectionOffset("__indexed__", uleb128(r, MAX_LEB, false))

            DW.FORM.block1 -> AttrValue.Bytes(r.bytes(r.u1()))
            DW.FORM.block2 -> AttrValue.Bytes(r.bytes(r.u2()))
            DW.FORM.block4 -> AttrValue.Bytes(r.bytes(r.u4()))
            DW.FORM.block -> AttrValue.Bytes(r.bytes(uleb128(r, MAX_LEB, false).toInt()))
            DW.FORM.exprloc -> AttrValue.Bytes(r.bytes(uleb128(r, MAX_LEB, false).toInt()))
            DW.FORM.data16 -> AttrValue.Bytes(r.bytes(16))

            // Type-unit signature references need .debug_types support to resolve; keep the
            // raw bytes consumed so the cursor stays aligned but do not invent a target.
            DW.FORM.ref_sig8 -> AttrValue.Bytes(r.bytes(8))

            else -> throw UnknownFormException(f)
        }
    }

    private fun read3(r: ByteReader): Int {
        if (r.remaining() < 3) throw ParseException("u3 past end")
        var v = 0
        for (i in 0 until 3) v = v or ((r.u1()) shl (i * 8))
        return v
    }

    private fun readAddr(r: ByteReader, addressSize: Int): Long = when (addressSize) {
        1 -> r.u1().toLong()
        2 -> r.u2().toLong() and 0xffffL
        4 -> r.u4().toLong() and 0xffffffffL
        8 -> r.u8()
        else -> throw ParseException("unsupported address size $addressSize")
    }

    private fun readStringFrom(
        r: ByteReader,
        sections: DwarfSections,
        preferred: String,
        unit: CompUnit,
        useLineStr: Boolean,
    ): AttrValue.Str {
        val off = if (unit.is64BitDwarf) r.u8() else (r.u4().toLong() and 0xffffffffL)
        val candidates = if (useLineStr) listOf(".debug_line_str", ".debug_line_str.dwo")
        else listOf(preferred, ".debug_str.dwo")
        for (name in candidates) {
            val sec = sections.bytes(name) ?: continue
            if (off >= 0 && off < sec.size) return AttrValue.Str(ByteReader(sec).cStringAt(off.toInt()))
        }
        throw ParseException("string offset 0x${off.toString(16)} references missing/corrupt string section")
    }
}
