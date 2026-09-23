package compass.dwarf

import compass.elf.ByteReader
import compass.elf.EndOfDataException

/**
 * 按 DWARF 版本严格决定每种 form 的字节长度。
 * 遇到未知 form 抛 [UnknownFormException]：调用方立即终结当前 CU，
 * 绝不“猜长度”后继续——那会造成游标错位并产生伪 DIE。
 */
object FormDecoder {

    fun read(r: ByteReader, dc: CuDecodeContext, formIn: Int, implicitConst: Long? = null): FormValue {
        var form = formIn
        if (form == Dw.FORM_INDIRECT) {
            form = r.uleb().toInt()
            if (form == Dw.FORM_INDIRECT) throw UnknownFormException(form, "nested DW_FORM_indirect")
        }
        return when (form) {
            Dw.FORM_FLAG_PRESENT -> FormValue.Number(1L)
            Dw.FORM_ADDR -> FormValue.Addr(dc.readAddress(r))
            Dw.FORM_DATA1, Dw.FORM_REF1, Dw.FORM_STRX1, Dw.FORM_ADDRX1 ->
                smallIndex(r, dc, form, r.u8().toLong())
            Dw.FORM_DATA2, Dw.FORM_REF2, Dw.FORM_STRX2, Dw.FORM_ADDRX2 ->
                smallIndex(r, dc, form, r.u16().toLong())
            Dw.FORM_DATA4, Dw.FORM_REF4, Dw.FORM_REF_SUP4, Dw.FORM_STRX4, Dw.FORM_ADDRX4 ->
                smallIndex(r, dc, form, r.u32asLong())
            Dw.FORM_DATA8, Dw.FORM_REF8, Dw.FORM_REF_SIG8, Dw.FORM_REF_SUP8 ->
                longForm(r, dc, form)
            Dw.FORM_DATA16 -> FormValue.Block(r.take(16))
            Dw.FORM_SDATA -> FormValue.Number(r.sleb())
            Dw.FORM_UDATA, Dw.FORM_REF_UDATA, Dw.FORM_STRX, Dw.FORM_ADDRX,
            Dw.FORM_LOCLISTX, Dw.FORM_RNGLISTX,
            Dw.FORM_GNU_ADDR_INDEX, Dw.FORM_GNU_STR_INDEX, Dw.FORM_GNU_REF_ALT ->
                ulebForm(r, dc, form)
            Dw.FORM_STRING -> FormValue.Str(r.cString())
            Dw.FORM_STRP, Dw.FORM_LINE_STRP -> {
                val off = readDwarfOffset(r, dc.is64)
                FormValue.Str(dc.readStrp(off, line = form == Dw.FORM_LINE_STRP))
            }
            Dw.FORM_SEC_OFFSET -> FormValue.Number(readDwarfOffset(r, dc.is64))
            Dw.FORM_BLOCK1 -> FormValue.Block(r.take(r.u8()))
            Dw.FORM_BLOCK2 -> FormValue.Block(r.take(r.u16()))
            Dw.FORM_BLOCK4 -> FormValue.Block(r.take(r.u32()))
            Dw.FORM_BLOCK -> FormValue.Block(r.take(r.uleb().toInt()))
            Dw.FORM_EXPRLOC -> FormValue.Block(readExprLoc(r))
            Dw.FORM_FLAG -> FormValue.Number(r.u8().toLong())
            Dw.FORM_IMPLICIT_CONST -> FormValue.Number(implicitConst ?: 0L)
            // 需要外部补充文件/额外 section 的 form：字节长度已知，正常消费并隔离为 Problem。
            Dw.FORM_STRP_SUP, Dw.FORM_GNU_STRP_ALT -> {
                val off = readDwarfOffset(r, dc.is64)
                FormValue.Problem(form, "requires supplementary/alt object (offset=$off)")
            }
            else -> throw UnknownFormException(form, "unknown form 0x${form.toString(16)}")
        }
    }

    private fun smallIndex(r: ByteReader, dc: CuDecodeContext, form: Int, raw: Long): FormValue = when (form) {
        Dw.FORM_STRX1, Dw.FORM_STRX2, Dw.FORM_STRX4 -> FormValue.Str(dc.readStrx(raw))
        Dw.FORM_ADDRX1, Dw.FORM_ADDRX2, Dw.FORM_ADDRX4 -> FormValue.Addr(dc.readAddrx(raw))
        Dw.FORM_REF1 -> FormValue.Ref(raw)
        Dw.FORM_REF2 -> FormValue.Ref(raw)
        Dw.FORM_REF4 -> FormValue.Ref(raw)
        Dw.FORM_REF_SUP4 -> FormValue.Problem(form, "DW_FORM_ref_sup4 needs supplementary object")
        else -> FormValue.Number(raw)
    }

    private fun ulebForm(r: ByteReader, dc: CuDecodeContext, form: Int): FormValue {
        val raw = r.uleb()
        return when (form) {
            Dw.FORM_STRX -> FormValue.Str(dc.readStrx(raw))
            Dw.FORM_ADDRX -> FormValue.Addr(dc.readAddrx(raw))
            Dw.FORM_RNGLISTX, Dw.FORM_LOCLISTX -> FormValue.Number(raw)
            Dw.FORM_GNU_ADDR_INDEX ->
                FormValue.Problem(form, "GNU addr_index needs .debug_addr.dwo/.debug_gnu_addr; value isolated (index=$raw)")
            Dw.FORM_GNU_STR_INDEX ->
                FormValue.Problem(form, "GNU str_index needs .debug_str_offsets.dwo; value isolated (index=$raw)")
            Dw.FORM_GNU_REF_ALT ->
                FormValue.Problem(form, "GNU ref_alt needs alternate debuginfo; offset consumed")
            else -> FormValue.Number(raw) // ref_udata / udata
        }
    }

    private fun longForm(r: ByteReader, dc: CuDecodeContext, form: Int): FormValue = when (form) {
        Dw.FORM_REF_SIG8 -> FormValue.Sig(r.u64())
        Dw.FORM_REF_SUP8 -> FormValue.Problem(form, "DW_FORM_ref_sup8 needs supplementary object")
        else -> {
            val off = if (dc.is64) r.u64() else r.u32asLong()
            FormValue.Number(off)
        }
    }

    private fun readExprLoc(r: ByteReader): ByteArray {
        // DWARF4: uleb length; DWARF5: 1/2/4 字节长度前缀由 section 决定（这里 DIE 内为 uleb）。
        val len = r.uleb().toInt()
        return r.take(len)
    }

    fun readDwarfOffset(r: ByteReader, is64: Boolean): Long =
        if (is64) r.u64() else r.u32asLong()
}
