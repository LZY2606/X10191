package luopan.dwarf

/**
 * 读取一个 DW_FORM 的值。
 * 未知 form 抛 UnsupportedFormException —— 调用方在 DIE 级别隔离：
 * 游标不能错位，因此不支持的 form 一律让该 DIE（必要时整个 CU）失败，
 * 而不是猜长度继续向后读。
 */
sealed class FormValue {
    data class Address(val v: Long) : FormValue()
    data class Num(val v: Long) : FormValue()
    data class StrRef(val section: String, val offset: Long) : FormValue()
    data class InString(val v: String) : FormValue()
    data class Block(val v: ByteArray) : FormValue()
    data class ExprLoc(val v: ByteArray) : FormValue()
    data class SecOffset(val v: Long) : FormValue()
    data class Ref(val v: Long) : FormValue()
    data class RefSig(val v: Long) : FormValue()
    data class Strx(val idx: Long) : FormValue()
    data class Addrx(val idx: Long) : FormValue()
    data class Rnglistx(val idx: Long) : FormValue()
    data class ImplicitConst(val v: Long) : FormValue()
}

class FormReader(
    private val r: ByteReader,
    private val addressSize: Int,
    private val dwarf64: Boolean,
    private val implicitConst: Long?
) {
    fun read(form0: Int): FormValue {
        var form = form0
        // DW_FORM_indirect：实际 form 在 uleb128 里
        if (form == DwForm.INDIRECT) {
            form = r.uleb128().first.toInt()
        }
        return when (form) {
            DwForm.ADDR -> FormValue.Address(r.readFixed(addressSize))
            DwForm.DATA1, DwForm.REF1, DwForm.STRX1, DwForm.ADDRX1, DwForm.RNGLISTX1 ->
                FormValue.Num(r.u8().toLong())
            DwForm.DATA2, DwForm.REF2, DwForm.STRX2, DwForm.ADDRX2 ->
                FormValue.Num(r.u16().toLong())
            DwForm.DATA4, DwForm.REF4, DwForm.STRX4, DwForm.ADDRX4, DwForm.REF_SUP4 ->
                FormValue.Num(r.u32())
            DwForm.DATA8, DwForm.REF8, DwForm.REF_SUP8 ->
                FormValue.Num(r.u64())
            DwForm.UDATA, DwForm.REF_UDATA, DwForm.STRX, DwForm.ADDRX, DwForm.RNGLISTX ->
                FormValue.Num(r.uleb128().first)
            DwForm.SDATA -> FormValue.Num(r.sleb128().first)
            DwForm.FLAG -> FormValue.Num(r.u8().toLong())
            DwForm.FLAG_PRESENT -> FormValue.Num(1)
            DwForm.STRING -> FormValue.InString(r.nullTerminatedString())
            DwForm.STRP -> if (dwarf64) FormValue.StrRef(".debug_str", r.u64())
                          else FormValue.StrRef(".debug_str", r.u32())
            DwForm.LINE_STRP -> if (dwarf64) FormValue.StrRef(".debug_line_str", r.u64())
                                else FormValue.StrRef(".debug_line_str", r.u32())
            DwForm.REF_ADDR -> if (dwarf64) FormValue.Ref(r.u64()) else FormValue.Ref(r.u32())
            DwForm.SEC_OFFSET -> FormValue.SecOffset(if (dwarf64) r.u64() else r.u32())
            DwForm.BLOCK1 -> FormValue.Block(r.bytes(r.u8()))
            DwForm.BLOCK2 -> FormValue.Block(r.bytes(r.u16()))
            DwForm.BLOCK4 -> FormValue.Block(r.bytes(r.u32().toInt()))
            DwForm.BLOCK -> FormValue.Block(r.bytes(r.uleb128().first.toInt()))
            DwForm.EXPRLOC -> FormValue.ExprLoc(r.bytes(r.uleb128().first.toInt()))
            DwForm.IMPLICIT_CONST -> FormValue.ImplicitConst(implicitConst ?: 0)
            DwForm.REF_SIG8 -> FormValue.RefSig(r.u64())
            DwForm.GNU_REF_ALT -> FormValue.Ref(if (dwarf64) r.u64() else r.u32())
            DwForm.GNU_STRP_ALT -> FormValue.StrRef(".gnu_debugaltlink", if (dwarf64) r.u64() else r.u32())
            else -> throw UnsupportedFormException(form)
        }
    }
}
