package compass.dwarf

/** A decoded attribute value. Offsets into string/addr tables are resolved later. */
sealed class AttrValue {
    data class Addr(val v: Long) : AttrValue()
    data class UInt(val v: Long) : AttrValue()
    data class SInt(val v: Long) : AttrValue()
    data class Str(val s: String) : AttrValue()
    /** Offset into .debug_str */
    data class Strp(val offset: Long) : AttrValue()
    /** Offset into .debug_line_str */
    data class LineStrp(val offset: Long) : AttrValue()
    /** Index into .debug_str_offsets (needs str_offsets_base) */
    data class Strx(val index: Long) : AttrValue()
    /** Index into .debug_addr (needs addr_base) */
    data class Addrx(val index: Long) : AttrValue()
    data class Ref(val offset: Long) : AttrValue()
    data class Flag(val v: Boolean) : AttrValue()
    data class Block(val bytes: ByteArray) : AttrValue()
    /** Offset into a section such as .debug_ranges / .debug_rnglists */
    data class SecOffset(val v: Long) : AttrValue()
    /** Index into .debug_rnglists offsets table */
    data class Rnglistx(val index: Long) : AttrValue()
}

data class FormContext(
    val addrSize: Int,
    val isDwarf64: Boolean,
    val version: Int
)

object Forms {
    private fun readSized(r: Reader, n: Int): Long = when (n) {
        1 -> r.u8().toLong()
        2 -> r.u16().toLong()
        3 -> {
            val b = r.bytes(3)
            if (r.littleEndian) {
                (b[0].toLong() and 0xFF) or ((b[1].toLong() and 0xFF) shl 8) or ((b[2].toLong() and 0xFF) shl 16)
            } else {
                ((b[0].toLong() and 0xFF) shl 16) or ((b[1].toLong() and 0xFF) shl 8) or (b[2].toLong() and 0xFF)
            }
        }
        4 -> r.u32()
        8 -> r.u64()
        else -> throw DwarfParseException("unsupported size $n")
    }

    fun read(r: Reader, form: Int, ctx: FormContext, attrName: String, depth: Int = 0): AttrValue {
        if (depth > 4) throw LimitExceededException("FORM_indirect recursion too deep")
        return when (form) {
            Dw.FORM_addr -> AttrValue.Addr(readSized(r, ctx.addrSize))
            Dw.FORM_addrx -> AttrValue.Addrx(r.uleb())
            Dw.FORM_addrx1 -> AttrValue.Addrx(r.u8().toLong())
            Dw.FORM_addrx2 -> AttrValue.Addrx(r.u16().toLong())
            Dw.FORM_addrx3 -> AttrValue.Addrx(readSized(r, 3))
            Dw.FORM_addrx4 -> AttrValue.Addrx(r.u32())
            Dw.FORM_block1 -> AttrValue.Block(r.bytes(r.u8()))
            Dw.FORM_block2 -> AttrValue.Block(r.bytes(r.u16()))
            Dw.FORM_block4 -> AttrValue.Block(r.bytes(r.u32().toInt()))
            Dw.FORM_block, Dw.FORM_exprloc -> AttrValue.Block(r.bytes(r.uleb().toInt()))
            Dw.FORM_data1 -> AttrValue.UInt(r.u8().toLong())
            Dw.FORM_data2 -> AttrValue.UInt(r.u16().toLong())
            Dw.FORM_data4 -> AttrValue.UInt(r.u32())
            Dw.FORM_data8 -> AttrValue.UInt(r.u64())
            Dw.FORM_data16 -> AttrValue.Block(r.bytes(16))
            Dw.FORM_udata -> AttrValue.UInt(r.uleb())
            Dw.FORM_sdata -> AttrValue.SInt(r.sleb())
            Dw.FORM_string -> AttrValue.Str(r.cstring())
            Dw.FORM_strp -> AttrValue.Strp(readSized(r, if (ctx.isDwarf64) 8 else 4))
            Dw.FORM_line_strp -> AttrValue.LineStrp(readSized(r, if (ctx.isDwarf64) 8 else 4))
            Dw.FORM_strp_sup -> AttrValue.Strp(readSized(r, if (ctx.isDwarf64) 8 else 4))
            Dw.FORM_strx -> AttrValue.Strx(r.uleb())
            Dw.FORM_strx1 -> AttrValue.Strx(r.u8().toLong())
            Dw.FORM_strx2 -> AttrValue.Strx(r.u16().toLong())
            Dw.FORM_strx3 -> AttrValue.Strx(readSized(r, 3))
            Dw.FORM_strx4 -> AttrValue.Strx(r.u32())
            Dw.FORM_flag -> AttrValue.Flag(r.u8() != 0)
            Dw.FORM_flag_present -> AttrValue.Flag(true)
            Dw.FORM_ref1 -> AttrValue.Ref(r.u8().toLong())
            Dw.FORM_ref2 -> AttrValue.Ref(r.u16().toLong())
            Dw.FORM_ref4 -> AttrValue.Ref(r.u32())
            Dw.FORM_ref8 -> AttrValue.Ref(r.u64())
            Dw.FORM_ref_udata -> AttrValue.Ref(r.uleb())
            Dw.FORM_ref_addr -> AttrValue.Ref(
                readSized(r, if (ctx.version <= 2) ctx.addrSize else if (ctx.isDwarf64) 8 else 4)
            )
            Dw.FORM_ref_sig8 -> AttrValue.Ref(r.u64())
            Dw.FORM_ref_sup4 -> AttrValue.Ref(r.u32())
            Dw.FORM_ref_sup8 -> AttrValue.Ref(r.u64())
            Dw.FORM_sec_offset -> AttrValue.SecOffset(readSized(r, if (ctx.isDwarf64) 8 else 4))
            Dw.FORM_rnglistx -> AttrValue.Rnglistx(r.uleb())
            Dw.FORM_loclistx -> AttrValue.UInt(r.uleb())
            Dw.FORM_implicit_const -> AttrValue.SInt(0) // placeholder; real value from abbrev
            Dw.FORM_indirect -> {
                val actual = r.uleb().toInt()
                read(r, actual, ctx, attrName, depth + 1)
            }
            else -> throw UnknownFormException(form, attrName)
        }
    }
}
