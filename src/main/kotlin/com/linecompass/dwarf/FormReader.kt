package com.linecompass.dwarf

import com.linecompass.io.ByteReader
import com.linecompass.io.ParseException

/** Per-CU context required to decode attribute forms. */
class CuDecodeCtx(
    val cu: CompilationUnitRef,
    val offsetSize: Int,
    val le: Boolean,
    val strings: StringTables,
    val addrs: AddrTableReader,
    val issues: MutableList<ParseIssue>
) {
    /** Placeholder CU handle replaced with the real CompilationUnit after tree build. */
    class CompilationUnitRef(var actual: CompilationUnit? = null)
}

/**
 * Decodes one attribute form. Unknown forms throw UnknownFormException so the
 * caller can stop parsing that CU immediately — the cursor must not "recover"
 * by skipping an unknown byte count, which would desync every later DIE.
 */
class UnknownFormException(val form: Int, val offset: Int) :
    ParseException("unknown form 0x${form.toString(16)} at 0x${offset.toString(16)}")

object FormReader {
    private val strxForms = setOf(
        DW.FORM_strx, DW.FORM_strx1, DW.FORM_strx2, DW.FORM_strx3, DW.FORM_strx4,
        DW.FORM_GNU_str_index
    )
    private val addrxForms = setOf(
        DW.FORM_addrx, DW.FORM_addrx1, DW.FORM_addrx2, DW.FORM_addrx3, DW.FORM_addrx4,
        DW.FORM_GNU_addr_index
    )

    @Suppress("UNUSED_PARAMETER")
    fun read(
        r: ByteReader,
        form: Int,
        implicitConst: Long,
        ctx: CuDecodeCtx,
        cuDataStart: Int,
        cuGlobalOffset: Long,
        formIndirect: Boolean = false
    ): AttrValue {
        val os = ctx.offsetSize
        val le = ctx.le
        val cuRef = ctx.cu
        val here = r.offset

        when (form) {
            DW.FORM_addr -> return AttrValue.Addr(r.u(ctx.cu.actual?.addressSize ?: 8))
            DW.FORM_data1, DW.FORM_flag -> return AttrValue.Number(r.u1().toLong())
            DW.FORM_data2 -> return AttrValue.Number(r.u2().toLong())
            DW.FORM_data4 -> return AttrValue.Number(r.s4().toLong())
            DW.FORM_data8 -> return AttrValue.Number(r.u8())
            DW.FORM_sdata -> return AttrValue.Number(r.sleb128())
            DW.FORM_udata -> return AttrValue.Number(r.uleb128())
            DW.FORM_implicit_const -> return AttrValue.Number(implicitConst)

            DW.FORM_string -> return AttrValue.Text(r.cString())
            DW.FORM_strp -> return AttrValue.Text(ctx.strings.strp(r.u(os)))
            DW.FORM_line_strp -> return AttrValue.Text(ctx.strings.lineStrp(r.u(os)))

            DW.FORM_flag_present -> return AttrValue.Number(1)

            DW.FORM_sec_offset -> return AttrValue.SectionOffset(r.u(os))

            DW.FORM_block1 -> { val n = r.u1(); return AttrValue.Expr(r.bytes(n)) }
            DW.FORM_block2 -> { val n = r.u2(); return AttrValue.Expr(r.bytes(n)) }
            DW.FORM_block4 -> { val n = r.s4(); return AttrValue.Expr(r.bytes(n)) }
            DW.FORM_block, DW.FORM_exprloc -> { val n = r.uleb128().toInt(); return AttrValue.Expr(r.bytes(n)) }

            in strxForms -> {
                val idx = readIndex(r, form)
                val base = (cuRef.actual?.strOffsetsBase) ?: 0L
                return AttrValue.Text(ctx.strings.strx(idx, base, cuGlobalOffset, os, le))
            }
            in addrxForms -> {
                val idx = readIndex(r, form)
                val base = (cuRef.actual?.addrBase) ?: 0L
                val v5 = (cuRef.actual?.version ?: 5) >= 5
                return AttrValue.Addr(ctx.addrs.addrx(idx, base, cuGlobalOffset, os, le, v5))
            }

            DW.FORM_ref1 -> return makeRef(cuGlobalOffset, cuDataStart, r.u1().toLong(), local = true)
            DW.FORM_ref2 -> return makeRef(cuGlobalOffset, cuDataStart, r.u2().toLong(), local = true)
            DW.FORM_ref4 -> return makeRef(cuGlobalOffset, cuDataStart, r.u4(), local = true)
            DW.FORM_ref8 -> return makeRef(cuGlobalOffset, cuDataStart, r.u8(), local = true)
            DW.FORM_ref_udata -> return makeRef(cuGlobalOffset, cuDataStart, r.uleb128(), local = true)
            DW.FORM_ref_addr -> return AttrValue.Ref(r.u(os), resolved = false)

            DW.FORM_indirect -> {
                val actualForm = r.uleb128().toInt()
                return read(r, actualForm, 0, ctx, cuDataStart, cuGlobalOffset, formIndirect = true)
            }

            DW.FORM_data16 -> {
                r.bytes(16)
                return AttrValue.Expr(ByteArray(0))
            }

            else -> throw UnknownFormException(form, here)
        }
    }

    private fun readIndex(r: ByteReader, form: Int): Long = when (form) {
        // x1/x3 fixed-width; bare x is ULEB128 (as are the GNU aliases).
        DW.FORM_strx1, DW.FORM_addrx1 -> r.u1().toLong()
        DW.FORM_strx2, DW.FORM_addrx2 -> r.u2().toLong()
        DW.FORM_strx3, DW.FORM_addrx3 -> r.u1().toLong()
        DW.FORM_strx4, DW.FORM_addrx4 -> r.u4()
        DW.FORM_strx, DW.FORM_addrx,
        DW.FORM_GNU_str_index, DW.FORM_GNU_addr_index -> r.uleb128()
        else -> r.uleb128()
    }

    private fun makeRef(cuGlobal: Long, cuDataStart: Int, value: Long, local: Boolean): AttrValue.Ref {
        val target = if (local) cuGlobal + (cuDataStart.toLong()) + value else value
        return AttrValue.Ref(target, resolved = false)
    }
}
