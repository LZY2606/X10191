package addresscompass.dwarf

import addresscompass.model.FormValue

class UnknownFormException(val form: Int, message: String) : RuntimeException(message)

/** Static layout facts of a compilation unit needed to decode forms. */
data class FormLayout(
    val version: Int,
    val dwarf64: Boolean,
    val addressSize: Int,
    val isSplit: Boolean,
) {
    val refAddrSize: Int get() = if (version >= 5 || dwarf64) 8 else 4
    val secOffsetSize: Int get() = if (dwarf64) 8 else 4
}

object FormReader {
    /**
     * Reads one attribute value. An unknown form throws [UnknownFormException]: the caller must
     * abandon the current CU rather than guessing how many bytes were consumed, which would
     * desynchronize the cursor and fabricate later DIEs.
     */
    fun read(r: ByteReader, form0: Int, layout: FormLayout, indirectDepth: Int = 0): FormValue {
        if (indirectDepth > 8) throw UnknownFormException(form0, "DW_FORM_indirect chain too deep")
        var form = form0
        if (form == Dwarf.DW_FORM_indirect) {
            form = r.uleb().toInt()
            if (form == Dwarf.DW_FORM_indirect) return read(r, form, layout, indirectDepth + 1)
        }
        return when (form) {
            Dwarf.DW_FORM_addr -> FormValue.AddrV(r.sizedInt(layout.addressSize))
            Dwarf.DW_FORM_addrx, Dwarf.DW_FORM_GNU_addr_index -> FormValue.Indexed(r.uleb())
            Dwarf.DW_FORM_addrx1 -> FormValue.Indexed(r.u8().toLong())
            Dwarf.DW_FORM_addrx2 -> FormValue.Indexed(r.u16().toLong())
            Dwarf.DW_FORM_addrx3 -> FormValue.Indexed((r.u8().toLong() shl 16) or r.u16().toLong())
            Dwarf.DW_FORM_addrx4 -> FormValue.Indexed(r.u32())

            Dwarf.DW_FORM_strx, Dwarf.DW_FORM_GNU_str_index -> FormValue.Indexed(r.uleb())
            Dwarf.DW_FORM_strx1 -> FormValue.Indexed(r.u8().toLong())
            Dwarf.DW_FORM_strx2 -> FormValue.Indexed(r.u16().toLong())
            Dwarf.DW_FORM_strx3 -> FormValue.Indexed((r.u8().toLong() shl 16) or r.u16().toLong())
            Dwarf.DW_FORM_strx4 -> FormValue.Indexed(r.u32())
            Dwarf.DW_FORM_rnglistx -> FormValue.Indexed(r.uleb())

            Dwarf.DW_FORM_data1, Dwarf.DW_FORM_ref1 -> FormValue.Udata(r.u8().toLong())
            Dwarf.DW_FORM_data2, Dwarf.DW_FORM_ref2 -> FormValue.Udata(r.u16().toLong())
            Dwarf.DW_FORM_data4, Dwarf.DW_FORM_ref4 -> FormValue.Udata(r.u32())
            Dwarf.DW_FORM_data8, Dwarf.DW_FORM_ref8 -> FormValue.Udata(r.u64())
            Dwarf.DW_FORM_udata, Dwarf.DW_FORM_ref_udata -> FormValue.Udata(r.uleb())
            Dwarf.DW_FORM_sdata -> FormValue.Sdata(r.sleb())

            Dwarf.DW_FORM_flag -> FormValue.Flag(r.u8() != 0)
            Dwarf.DW_FORM_flag_present -> FormValue.Flag(true)

            Dwarf.DW_FORM_string -> FormValue.Str(r.readNULString(1 shl 20))

            Dwarf.DW_FORM_sec_offset -> FormValue.SecOffset(r.sizedInt(layout.secOffsetSize))
            Dwarf.DW_FORM_strp, Dwarf.DW_FORM_line_strp ->
                FormValue.SecOffset(r.sizedInt(if (versionedStrSize(layout)) layout.secOffsetSize else 4))
            Dwarf.DW_FORM_ref_addr -> FormValue.SecOffset(r.sizedInt(layout.refAddrSize))

            Dwarf.DW_FORM_ref_sup4 -> FormValue.External(r.u32())
            Dwarf.DW_FORM_ref_sup8 -> FormValue.External(r.u64())
            Dwarf.DW_FORM_strp_sup, Dwarf.DW_FORM_GNU_strp_alt ->
                FormValue.External(r.sizedInt(layout.secOffsetSize))
            Dwarf.DW_FORM_GNU_ref_alt -> FormValue.External(r.sizedInt(layout.secOffsetSize))

            Dwarf.DW_FORM_block1 -> FormValue.Block(r.bytes(r.u8()))
            Dwarf.DW_FORM_block2 -> FormValue.Block(r.bytes(r.u16()))
            Dwarf.DW_FORM_block4 -> FormValue.Block(r.bytes(r.u32().toInt()))
            Dwarf.DW_FORM_block, Dwarf.DW_FORM_exprloc -> FormValue.Block(r.bytes(r.uleb().toInt()))
            Dwarf.DW_FORM_data16 -> FormValue.Block(r.bytes(16))

            else -> throw UnknownFormException(form, "unknown DW_FORM 0x${form.toString(16)}")
        }
    }

    private fun versionedStrSize(layout: FormLayout): Boolean =
        layout.version >= 5 || layout.dwarf64 || layout.isSplit
}
