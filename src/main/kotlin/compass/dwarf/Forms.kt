package compass.dwarf

/** Decoded attribute value. Offsets into string/addr tables are resolved later by the CU parser. */
sealed class AttrValue {
    data class Addr(val value: Long) : AttrValue()
    data class Data(val value: Long) : AttrValue()
    data class SData(val value: Long) : AttrValue()
    data class Str(val value: String) : AttrValue()
    data class StrOffset(val offset: Long, val lineStr: Boolean) : AttrValue()
    data class StrIndex(val index: Long) : AttrValue()
    data class AddrIndex(val index: Long) : AttrValue()
    data class Ref(val offset: Long) : AttrValue()
    data class Flag(val value: Boolean) : AttrValue()
    data class SecOffset(val value: Long) : AttrValue()
    data class Block(val data: ByteArray) : AttrValue()
}

class FormDecoder(
    val version: Int,
    val addrSize: Int,
    val dwarf64: Boolean,
    val bigEndian: Boolean = false,
) {
    private fun Reader.addr(): Long = when (addrSize) {
        4 -> u32()
        8 -> u64()
        else -> throw DwarfException("unsupported address size $addrSize")
    }

    private fun Reader.refAddr(): Long {
        // DWARF2/3: address-sized; DWARF4+: offset-size
        return if (version <= 3) addr() else if (dwarf64) u64() else u32()
    }

    fun read(r: Reader, formIn: Int): AttrValue {
        var form = formIn
        if (form == Dw.FORM_indirect) form = r.uleb128().toInt()
        return when (form) {
            Dw.FORM_addr -> AttrValue.Addr(r.addr())
            Dw.FORM_data1 -> AttrValue.Data(r.u8().toLong())
            Dw.FORM_data2 -> AttrValue.Data(r.u16().toLong())
            Dw.FORM_data4 -> AttrValue.Data(r.u32())
            Dw.FORM_data8 -> AttrValue.Data(r.u64())
            Dw.FORM_data16 -> AttrValue.Block(r.bytes(16))
            Dw.FORM_udata -> AttrValue.Data(r.uleb128())
            Dw.FORM_sdata -> AttrValue.SData(r.sleb128())
            Dw.FORM_string -> AttrValue.Str(r.cstring())
            Dw.FORM_strp -> AttrValue.StrOffset(if (dwarf64) r.u64() else r.u32(), lineStr = false)
            Dw.FORM_line_strp -> AttrValue.StrOffset(if (dwarf64) r.u64() else r.u32(), lineStr = true)
            Dw.FORM_strp_sup -> AttrValue.StrOffset(if (dwarf64) r.u64() else r.u32(), lineStr = false)
            Dw.FORM_strx, Dw.FORM_GNU_str_index -> AttrValue.StrIndex(r.uleb128())
            Dw.FORM_strx1 -> AttrValue.StrIndex(r.u8().toLong())
            Dw.FORM_strx2 -> AttrValue.StrIndex(r.u16().toLong())
            Dw.FORM_strx3 -> { val b = r.bytes(3); AttrValue.StrIndex(((b[0].toInt() and 0xFF) or ((b[1].toInt() and 0xFF) shl 8) or ((b[2].toInt() and 0xFF) shl 16)).toLong()) }
            Dw.FORM_strx4 -> AttrValue.StrIndex(r.u32())
            Dw.FORM_addrx, Dw.FORM_GNU_addr_index -> AttrValue.AddrIndex(r.uleb128())
            Dw.FORM_addrx1 -> AttrValue.AddrIndex(r.u8().toLong())
            Dw.FORM_addrx2 -> AttrValue.AddrIndex(r.u16().toLong())
            Dw.FORM_addrx3 -> { val b = r.bytes(3); AttrValue.AddrIndex(((b[0].toInt() and 0xFF) or ((b[1].toInt() and 0xFF) shl 8) or ((b[2].toInt() and 0xFF) shl 16)).toLong()) }
            Dw.FORM_addrx4 -> AttrValue.AddrIndex(r.u32())
            Dw.FORM_flag -> AttrValue.Flag(r.u8() != 0)
            Dw.FORM_flag_present -> AttrValue.Flag(true)
            Dw.FORM_ref1 -> AttrValue.Ref(r.u8().toLong())
            Dw.FORM_ref2 -> AttrValue.Ref(r.u16().toLong())
            Dw.FORM_ref4 -> AttrValue.Ref(r.u32())
            Dw.FORM_ref8 -> AttrValue.Ref(r.u64())
            Dw.FORM_ref_udata -> AttrValue.Ref(r.uleb128())
            Dw.FORM_ref_addr -> AttrValue.Ref(r.refAddr())
            Dw.FORM_ref_sig8 -> AttrValue.Ref(r.u64())
            Dw.FORM_ref_sup4 -> AttrValue.Ref(r.u32())
            Dw.FORM_ref_sup8 -> AttrValue.Ref(r.u64())
            Dw.FORM_sec_offset -> AttrValue.SecOffset(if (dwarf64) r.u64() else r.u32())
            Dw.FORM_rnglistx, Dw.FORM_loclistx -> AttrValue.Data(r.uleb128())
            Dw.FORM_exprloc, Dw.FORM_block -> AttrValue.Block(r.bytes(r.uleb128().toInt()))
            Dw.FORM_block1 -> AttrValue.Block(r.bytes(r.u8()))
            Dw.FORM_block2 -> AttrValue.Block(r.bytes(r.u16()))
            Dw.FORM_block4 -> AttrValue.Block(r.bytes(r.u32().toInt()))
            Dw.FORM_implicit_const -> AttrValue.SData(0) // value supplied by abbrev spec
            Dw.FORM_GNU_strp_alt -> AttrValue.StrOffset(if (dwarf64) r.u64() else r.u32(), lineStr = false)
            else -> throw UnknownFormException(form)
        }
    }
}
