package linecompass.dwarf

/** Per-CU decoding context passed to attribute readers. */
class CuContext(
    val version: Int,
    val is64bit: Boolean,
    val addressSize: Int,
    val offsetSize: Int,
    val unitStart: Int,
    val strBase: Int,
    val addrBase: Long,
    val sections: SectionBundle,
)

/**
 * Decodes one DW_FORM value. Unknown forms throw UnknownFormException: the
 * DIE-tree driver catches it, quarantines that CU's DIE tree and stops
 * reading at the exact failure point, so the cursor never desynchronises and
 * later structures (line programs, other CUs) are still parsed.
 */
class UnknownFormException(val form: Int, offset: Int) :
    RuntimeException("unknown/unsupported DW_FORM 0x${form.toString(16)} at offset $offset")

object FormReader {
    fun read(r: BoundedReader, form0: Int, implicit: Long?, ctx: CuContext): DwarfValue {
        var form = form0
        if (form == Form.INDIRECT) {
            form = r.uleb().toInt()
            if (form == 0) throw UnknownFormException(0, r.pos)
        }
        when (form) {
            Form.ADDR -> return DwarfValue(form, if (ctx.addressSize == 4) r.u32() else r.u64())
            Form.DATA1, Form.FLAG, Form.STRX1, Form.ADDRX1, Form.LOCLISTX1, Form.RNGLISTX1, Form.REF1 -> {
                val v = r.u8().toLong()
                return indexValue(r, form, v, ctx)
            }
            Form.DATA2, Form.STRX2, Form.ADDRX2, Form.LOCLISTX2, Form.RNGLISTX2, Form.REF2 -> {
                val v = r.u16().toLong()
                return indexValue(r, form, v, ctx)
            }
            Form.DATA4, Form.STRX4, Form.ADDRX4, Form.LOCLISTX4, Form.RNGLISTX4 -> {
                val v = r.u32()
                return indexValue(r, form, v, ctx)
            }
            Form.DATA8, Form.REF8, Form.REF_SIG8 -> return DwarfValue(form, r.u64())
            Form.UDATA, Form.STRX, Form.ADDRX, Form.LOCLISTX, Form.RNGLISTX,
            Form.REF_UDATA -> {
                val v = r.uleb()
                return indexValue(r, form, v, ctx)
            }
            Form.SDATA -> return DwarfValue(form, r.sleb())
            Form.STRING -> return DwarfValue(form, r.cString())
            Form.STRP -> {
                val off = readOffset(r, ctx.offsetSize)
                return DwarfValue(form, ctx.sections.stringAt(off.toInt()))
            }
            Form.LINE_STRP -> {
                val off = readOffset(r, ctx.offsetSize)
                return DwarfValue(form, ctx.sections.lineStringAt(off.toInt()))
            }
            Form.REF4 -> {
                val off = r.u32()
                return DwarfValue(form, off)
            }
            Form.REF_ADDR -> {
                val off = readOffset(r, ctx.offsetSize)
                return DwarfValue(form, off)
            }
            Form.SEC_OFFSET -> {
                val off = readOffset(r, ctx.offsetSize)
                return DwarfValue(form, off)
            }
            Form.EXPRLOC, Form.BLOCK -> {
                val len = r.uleb().toInt()
                return DwarfValue(form, r.bytes(len))
            }
            Form.BLOCK1 -> return DwarfValue(form, r.bytes(r.u8()))
            Form.BLOCK2 -> return DwarfValue(form, r.bytes(r.u16()))
            Form.BLOCK4 -> return DwarfValue(form, r.bytes(r.u32().toInt()))
            Form.DATA16 -> return DwarfValue(form, r.bytes(16))
            Form.FLAG_PRESENT -> return DwarfValue(form, 1L)
            Form.IMPLICIT_CONST -> return DwarfValue(form, implicit ?: 0L)
            else -> throw UnknownFormException(form, r.pos)
        }
    }

    private fun readOffset(r: BoundedReader, offsetSize: Int): Long =
        if (offsetSize == 4) r.u32() else r.u64()

    private fun indexValue(r: BoundedReader, form: Int, index: Long, ctx: CuContext): DwarfValue {
        when (form) {
            Form.STRX, Form.STRX1, Form.STRX2, Form.STRX3, Form.STRX4 ->
                return DwarfValue(form, ctx.sections.strOffsetEntry(ctx.strBase, index, ctx.offsetSize))
            Form.ADDRX, Form.ADDRX1, Form.ADDRX2, Form.ADDRX3, Form.ADDRX4 ->
                return DwarfValue(Form.ADDR, ctx.sections.addrEntry(ctx.addrBase, index, ctx.addressSize))
            Form.RNGLISTX, Form.RNGLISTX1, Form.RNGLISTX2, Form.RNGLISTX3, Form.RNGLISTX4 ->
                return DwarfValue(Form.RNGLISTX, index)
            Form.LOCLISTX, Form.LOCLISTX1, Form.LOCLISTX2, Form.LOCLISTX3, Form.LOCLISTX4 ->
                return DwarfValue(form, index)
            else -> return DwarfValue(form, index)
        }
    }
}
