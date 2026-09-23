@file:JvmName("DwarfFormReader")
package compass.dwarf

import compass.binary.ByteReader
import compass.binary.DwarfCorruptException

/**
 * Reads one attribute according to its form. An unrecognized form throws immediately;
 * callers stop decoding the owning CU at that point so the cursor cannot drift and
 * invent subsequent DIEs.
 */
internal fun readForm(reader: ByteReader, form: Int, ctx: DwarfParser.ParseContext, entry: AbbrevEntry?): AttrValue {
    when (form) {
        DW.FORM_addr -> return AttrValue.Addr(reader.word(ctx.addressSize))

        DW.FORM_data1 -> return AttrValue.Constant(reader.u8().toLong(), 1)
        DW.FORM_data2 -> return AttrValue.Constant(reader.u16().toLong(), 2)
        DW.FORM_data4 -> return AttrValue.Constant(reader.u32(), 4)
        DW.FORM_data8 -> return AttrValue.Constant(reader.u64(), 8)
        DW.FORM_data16 -> {
            reader.bytes(16)
            return AttrValue.Constant(0, 16)
        }
        DW.FORM_udata -> return AttrValue.Constant(reader.uleb(), 0)
        DW.FORM_sdata -> return AttrValue.Constant(reader.sleb(), 0)
        DW.FORM_implicit_const ->
            return AttrValue.Constant(entry?.implicitConst ?: error("implicit_const without abbrev"), 0)

        DW.FORM_flag -> return AttrValue.Flag(reader.u8() != 0)
        DW.FORM_flag_present -> return AttrValue.FlagTrue

        DW.FORM_string -> return AttrValue.Str(reader.cstring(ctx.unitEnd.toInt()))

        DW.FORM_strp -> {
            val off = reader.word(if (ctx.dwarf64) 8 else 4)
            return AttrValue.StrRef(off, false)
        }
        DW.FORM_line_strp -> {
            val off = reader.word(if (ctx.dwarf64) 8 else 4)
            return AttrValue.StrRef(off, true)
        }

        DW.FORM_strx, DW.FORM_GNU_str_index -> return AttrValue.StrIndex(reader.uleb())
        DW.FORM_strx1 -> return AttrValue.StrIndex(reader.u8().toLong())
        DW.FORM_strx2 -> return AttrValue.StrIndex(reader.u16().toLong())
        DW.FORM_strx3 -> {
            reader.ensure(3)
            var v = 0L
            for (i in 0 until 3) v = v or ((reader.u8().toLong()) shl (i * 8))
            return AttrValue.StrIndex(v)
        }
        DW.FORM_strx4 -> return AttrValue.StrIndex(reader.u32())

        DW.FORM_addrx, DW.FORM_GNU_addr_index -> return AttrValue.AddrIndex(reader.uleb())
        DW.FORM_addrx1 -> return AttrValue.AddrIndex(reader.u8().toLong())
        DW.FORM_addrx2 -> return AttrValue.AddrIndex(reader.u16().toLong())
        DW.FORM_addrx3 -> {
            reader.ensure(3)
            var v = 0L
            for (i in 0 until 3) v = v or ((reader.u8().toLong()) shl (i * 8))
            return AttrValue.AddrIndex(v)
        }
        DW.FORM_addrx4 -> return AttrValue.AddrIndex(reader.u32())

        DW.FORM_block1 -> return AttrValue.Block(reader.bytes(reader.u8()))
        DW.FORM_block2 -> return AttrValue.Block(reader.bytes(reader.u16()))
        DW.FORM_block4 -> return AttrValue.Block(reader.bytes(reader.u32().toInt()))
        DW.FORM_block -> return AttrValue.Block(reader.bytes(reader.uleb().toInt()))
        DW.FORM_exprloc -> return AttrValue.Block(reader.bytes(reader.uleb().toInt()))

        DW.FORM_sec_offset -> return AttrValue.SecOffset(if (ctx.dwarf64) reader.u64() else reader.u32())
        DW.FORM_rnglistx, DW.FORM_loclistx ->
            return AttrValue.RngListRef(0, indexed = true, index = reader.uleb())

        DW.FORM_ref1 -> return AttrValue.Reference(null, true, reader.u8().toLong())
        DW.FORM_ref2 -> return AttrValue.Reference(null, true, reader.u16().toLong())
        DW.FORM_ref4 -> return AttrValue.Reference(null, true, reader.u32())
        DW.FORM_ref8 -> return AttrValue.Reference(null, true, reader.u64())
        DW.FORM_ref_udata -> return AttrValue.Reference(null, true, reader.uleb())
        DW.FORM_ref_addr -> {
            val size = if (ctx.dwarf64) 8 else 4
            return AttrValue.Reference(reader.word(size), false, 0)
        }
        DW.FORM_ref_sup4 -> {
            reader.u32()
            return AttrValue.Reference(null, false, -1)
        }
        DW.FORM_ref_sup8 -> {
            reader.u64()
            return AttrValue.Reference(null, false, -1)
        }
        DW.FORM_GNU_ref_alt -> {
            reader.u32() // offset into alt (dwo) info; handled as unresolved here
            return AttrValue.Reference(null, false, -1)
        }
        DW.FORM_GNU_strp_alt -> {
            reader.u32()
            return AttrValue.StrRef(-1, false)
        }

        DW.FORM_indirect -> {
            val realForm = reader.uleb().toInt()
            if (realForm == DW.FORM_indirect) throw DwarfCorruptException("nested DW_FORM_indirect")
            return readForm(reader, realForm, ctx, entry)
        }
    }
    throw DwarfCorruptException("unknown DWARF form 0x${form.toString(16)}")
}
