package compass.dwarf

import compass.elf.Reader
import compass.model.Endian

/** A raw attribute value resolved to a typed primitive. */
sealed class FormValue {
    data class Address(val v: Long) : FormValue()
    data class Constant(val v: Long) : FormValue()
    data class Text(val v: String) : FormValue()
    data class Offset(val v: Long) : FormValue() // section offset (ranges/strp/line...)
    data class Reference(val globalOffset: Long) : FormValue()
    data class Flag(val v: Boolean) : FormValue()
    data class Expr(val bytes: ByteArray) : FormValue()
    data class Block(val bytes: ByteArray) : FormValue()
    data class AddrIndex(val index: Long) : FormValue()
    data class StrIndex(val index: Long) : FormValue()
    data class RngListIndex(val index: Long) : FormValue()
}

/** Context required to read forms for a specific CU. */
class FormContext(
    val endian: Endian,
    val version: Int,
    val dwarf64: Boolean,
    val addrSize: Int,
    val cuOffset: Long,                 // offset of unit header (length field) in .debug_info
    val abbrevs: AbbrevTables,
    val sections: DebugSections,
    val strOffsetsBase: Long,           // DWARF5 .debug_str_offsets base
    val addrBase: Long,                 // .debug_addr base
    val isSplit: Boolean,
    val warnings: MutableList<String>,
) {
    fun copy(addrSize: Int): FormContext =
        FormContext(endian, version, dwarf64, addrSize, cuOffset, abbrevs, sections,
            strOffsetsBase, addrBase, isSplit, warnings)
}

object Forms {

    fun read(formIn: Int, implicitConst: Long, r: Reader, ctx: FormContext): FormValue {
        var form = formIn
        if (form == DW.FORM_indirect) form = r.uleb128().toInt()
        return when (form) {
            DW.FORM_addr -> FormValue.Address(readAddr(r, ctx.addrSize))
            DW.FORM_data1 -> FormValue.Constant(r.u8().toLong())
            DW.FORM_data2 -> FormValue.Constant(r.u16().toLong() and 0xffff)
            DW.FORM_data4 -> FormValue.Constant(r.u32())
            DW.FORM_data8 -> FormValue.Constant(r.u64())
            DW.FORM_sdata -> FormValue.Constant(r.sleb128())
            DW.FORM_udata -> FormValue.Constant(r.uleb128())
            DW.FORM_implicit_const -> FormValue.Constant(implicitConst)
            DW.FORM_flag -> FormValue.Flag(r.u8() != 0)
            DW.FORM_flag_present -> FormValue.Flag(true)
            DW.FORM_string -> FormValue.Text(r.cStringAt(r.pos).also { r.skip(it.toByteArray().size + 1) })
            DW.FORM_strp -> {
                val off = readSectionPtr(r, ctx)
                val str = ctx.sections.require(".debug_str").let { if (it.isEmpty()) "" else Reader(it, ctx.endian).cStringAt(off.toInt()) }
                FormValue.Text(str)
            }
            DW.FORM_line_strp -> {
                val off = readSectionPtr(r, ctx)
                val sec = ctx.sections.require(".debug_line_str")
                FormValue.Text(if (sec.isEmpty() || off < 0 || off >= sec.size) "" else Reader(sec, ctx.endian).cStringAt(off.toInt()))
            }
            DW.FORM_sec_offset -> FormValue.Offset(readSectionPtr(r, ctx))
            DW.FORM_exprloc -> {
                val len = r.uleb128().toInt(); FormValue.Expr(r.bytes(len))
            }
            DW.FORM_block -> { val len = r.uleb128().toInt(); FormValue.Block(r.bytes(len)) }
            DW.FORM_block1 -> { val len = r.u8(); FormValue.Block(r.bytes(len)) }
            DW.FORM_block2 -> { val len = r.u16(); FormValue.Block(r.bytes(len)) }
            DW.FORM_block4 -> { val len = r.u32().toInt(); FormValue.Block(r.bytes(len)) }

            DW.FORM_ref1 -> FormValue.Reference(ctx.cuOffset + r.u8())
            DW.FORM_ref2 -> FormValue.Reference(ctx.cuOffset + r.u16())
            DW.FORM_ref4 -> FormValue.Reference(ctx.cuOffset + r.u32())
            DW.FORM_ref8 -> FormValue.Reference(ctx.cuOffset + r.u64())
            DW.FORM_ref_udata -> FormValue.Reference(ctx.cuOffset + r.uleb128())
            DW.FORM_ref_addr -> {
                val off = readSectionPtr(r, ctx)
                FormValue.Reference(off)
            }
            DW.FORM_ref_sig8 -> { r.bytes(8); FormValue.Constant(0) } // type units unsupported; consume
            DW.FORM_data16 -> FormValue.Block(r.bytes(16))

            // DWARF5 / GNU indexed strings
            DW.FORM_strx, DW.FORM_GNU_str_index -> FormValue.StrIndex(r.uleb128())
            DW.FORM_strx1 -> FormValue.StrIndex(r.u8().toLong() and 0xff)
            DW.FORM_strx2 -> FormValue.StrIndex(r.u16().toLong() and 0xffff)
            DW.FORM_strx3 -> FormValue.StrIndex(r.u32().coerceAtMost(Int.MAX_VALUE.toLong()))
            DW.FORM_strx4 -> FormValue.StrIndex(r.u32())

            DW.FORM_addrx, DW.FORM_GNU_addr_index -> FormValue.AddrIndex(r.uleb128())
            DW.FORM_addrx1 -> FormValue.AddrIndex(r.u8().toLong() and 0xff)
            DW.FORM_addrx2 -> FormValue.AddrIndex(r.u16().toLong() and 0xffff)
            DW.FORM_addrx3 -> FormValue.AddrIndex(r.u32())
            DW.FORM_addrx4 -> FormValue.AddrIndex(r.u32())

            DW.FORM_rnglistx, DW.FORM_GNU_rnglistx -> FormValue.RngListIndex(r.uleb128())

            else -> throw UnknownFormException(form)
        }
    }

    fun readAddr(r: Reader, addrSize: Int): Long = when (addrSize) {
        1 -> r.u8().toLong() and 0xff
        2 -> r.u16().toLong() and 0xffff
        4 -> r.u32()
        8 -> r.u64()
        else -> throw IllegalArgumentException("unsupported address size $addrSize")
    }

    fun readSectionPtr(r: Reader, ctx: FormContext): Long =
        if (ctx.dwarf64) r.u64() else r.u32()
}
