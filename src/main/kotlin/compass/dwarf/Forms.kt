package compass.dwarf

import compass.elf.Reader

/** Everything a form reader needs to know about the unit being decoded. */
data class FormCtx(
    val version: Int,
    val addrSize: Int,
    val isDwarf64: Boolean,
    val addrBase: Long = 0L,
    val strOffsetsBase: Long = 0L,
    val sections: DwarfSections,
) {
    val offsetSize: Int get() = if (isDwarf64) 8 else 4
}

class AttrVal(
    val form: Long,
    val num: Long = 0L,          // numeric value (also resolved address / string offset)
    val str: String? = null,     // resolved string when applicable
    val block: ByteArray? = null,
) {
    val isAddressClass: Boolean get() = form == Form.ADDR || form in addrxForms
    companion object {
        val addrxForms = setOf(Form.ADDRX, Form.ADDRX1, Form.ADDRX2, Form.ADDRX3, Form.ADDRX4)
    }
}

object FormReader {
    private fun readSized(r: Reader, n: Int): Long {
        var v = 0L
        for (i in 0 until n) v = v or (r.u8().toLong() shl (8 * i))
        return v
    }

    private fun strAt(data: ByteArray?, off: Long, what: String): String {
        if (data == null) throw BadReference("$what table missing for string at $off")
        if (off < 0 || off >= data.size) throw BadReference("$what string offset $off out of bounds (size ${data.size})")
        var p = off.toInt()
        val start = p
        while (p < data.size && data[p].toInt() != 0) p++
        return String(data, start, p - start, Charsets.UTF_8)
    }

    fun read(r: Reader, formIn: Long, ctx: FormCtx, depth: Int = 0): AttrVal {
        if (depth > Limits.MAX_INDIRECT_FORM) throw BadReference("DW_FORM_indirect chain too deep")
        val form = if (formIn == Form.INDIRECT) {
            val f = r.uleb128()
            return read(r, f, ctx, depth + 1)
        } else formIn

        if (form !in Form.KNOWN) throw UnknownForm(form)
        val s = ctx.sections
        return when (form) {
            Form.ADDR -> AttrVal(form, num = readSized(r, ctx.addrSize))
            Form.ADDRX -> AttrVal(form, num = addrByIndex(r.uleb128(), ctx))
            Form.ADDRX1 -> AttrVal(form, num = addrByIndex(r.u8().toLong(), ctx))
            Form.ADDRX2 -> AttrVal(form, num = addrByIndex(r.u16().toLong(), ctx))
            Form.ADDRX3 -> AttrVal(form, num = addrByIndex(readSized(r, 3), ctx))
            Form.ADDRX4 -> AttrVal(form, num = addrByIndex(r.u32(), ctx))
            Form.BLOCK1 -> AttrVal(form, block = r.bytes(r.u8()))
            Form.BLOCK2 -> AttrVal(form, block = r.bytes(r.u16()))
            Form.BLOCK4 -> AttrVal(form, block = r.bytes(r.u32().toInt()))
            Form.BLOCK -> AttrVal(form, block = r.bytes(r.uleb128().toInt()))
            Form.EXPLOC -> AttrVal(form, block = r.bytes(r.uleb128().toInt()))
            Form.DATA1 -> AttrVal(form, num = r.u8().toLong())
            Form.DATA2 -> AttrVal(form, num = r.u16().toLong())
            Form.DATA4 -> AttrVal(form, num = r.u32())
            Form.DATA8 -> AttrVal(form, num = r.u64())
            Form.DATA16 -> AttrVal(form, block = r.bytes(16))
            Form.SDATA -> AttrVal(form, num = r.sleb128())
            Form.UDATA -> AttrVal(form, num = r.uleb128())
            Form.FLAG -> AttrVal(form, num = r.u8().toLong())
            Form.FLAG_PRESENT -> AttrVal(form, num = 1L)
            Form.STRING -> AttrVal(form, str = r.cstring())
            Form.STRP -> {
                val off = if (ctx.isDwarf64) r.u64() else r.u32()
                AttrVal(form, num = off, str = strAt(s.str, off, ".debug_str"))
            }
            Form.LINE_STRP -> {
                val off = if (ctx.isDwarf64) r.u64() else r.u32()
                AttrVal(form, num = off, str = strAt(s.lineStr, off, ".debug_line_str"))
            }
            Form.STRP_SUP -> {
                val off = if (ctx.isDwarf64) r.u64() else r.u32()
                AttrVal(form, num = off) // supplementary file unavailable: keep offset, no string
            }
            Form.STRX -> strx(r.uleb128(), form, ctx)
            Form.STRX1 -> strx(r.u8().toLong(), form, ctx)
            Form.STRX2 -> strx(r.u16().toLong(), form, ctx)
            Form.STRX3 -> strx(readSized(r, 3), form, ctx)
            Form.STRX4 -> strx(r.u32(), form, ctx)
            Form.SEC_OFFSET -> AttrVal(form, num = if (ctx.isDwarf64) r.u64() else r.u32())
            Form.REF_ADDR -> AttrVal(form, num = if (ctx.version <= 3) readSized(r, ctx.addrSize) else if (ctx.isDwarf64) r.u64() else r.u32())
            Form.REF1 -> AttrVal(form, num = r.u8().toLong())
            Form.REF2 -> AttrVal(form, num = r.u16().toLong())
            Form.REF4 -> AttrVal(form, num = r.u32())
            Form.REF8 -> AttrVal(form, num = r.u64())
            Form.REF_UDATA -> AttrVal(form, num = r.uleb128())
            Form.REF_SIG8 -> AttrVal(form, num = r.u64())
            Form.REF_SUP4 -> AttrVal(form, num = r.u32())
            Form.REF_SUP8 -> AttrVal(form, num = r.u64())
            Form.RNGLISTX, Form.LOCLISTX -> AttrVal(form, num = r.uleb128())
            Form.IMPLICIT_CONST -> AttrVal(form) // value carried by the abbrev, patched by caller
            else -> throw UnknownForm(form)
        }
    }

    private fun strx(index: Long, form: Long, ctx: FormCtx): AttrVal {
        val (off, str) = strByIndex(index, ctx)
        return AttrVal(form, num = off, str = str)
    }

    @Synchronized
    private fun strByIndex(index: Long, ctx: FormCtx): Pair<Long, String?> {
        val table = ctx.sections.strOffsets ?: throw BadReference(".debug_str_offsets missing for strx index $index")
        val entryOff = ctx.strOffsetsBase + index * ctx.offsetSize
        if (entryOff < 0 || entryOff + ctx.offsetSize > table.size)
            throw BadReference("strx index $index out of bounds (entry offset $entryOff, table size ${table.size})")
        val er = Reader(table, entryOff.toInt(), table.size, ctx.sections.bigEndian)
        val strOff = if (ctx.offsetSize == 8) er.u64() else er.u32()
        val str = try { strAt(ctx.sections.str, strOff, ".debug_str") } catch (e: BadReference) { null }
        return strOff to str
    }

    private fun addrByIndex(index: Long, ctx: FormCtx): Long {
        val table = ctx.sections.addr ?: throw BadReference(".debug_addr missing for addrx index $index")
        val entryOff = ctx.addrBase + index * ctx.addrSize
        if (entryOff < 0 || entryOff + ctx.addrSize > table.size)
            throw BadReference("addrx index $index out of bounds (entry offset $entryOff, table size ${table.size})")
        val er = Reader(table, entryOff.toInt(), table.size, ctx.sections.bigEndian)
        var v = 0L
        for (i in 0 until ctx.addrSize) v = v or (er.u8().toLong() shl (8 * i))
        return v
    }
}
