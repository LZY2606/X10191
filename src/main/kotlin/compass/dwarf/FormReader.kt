package compass.dwarf

import compass.core.ByteCursor
import compass.core.CursorException

/** CU 级上下文：版本、地址宽度、字符串/地址/rnglist 基址。 */
data class FormContext(
    val version: Int,
    val dwarf64: Boolean,
    val addressSize: Int,
    val unitStart: Long,
    var strOffsetsBase: Long?,
    var addrBase: Long?,
    var rangesBase: Long?,
    val issues: MutableList<ParseIssue>
) {
    fun refSize(): Int = if (dwarf64) 8 else 4
}

class FormReader(private val sections: DebugSections) {

    fun read(c: ByteCursor, formIn: Int, ctx: FormContext): AttrValue {
        var form = formIn
        var indirectJumps = 0
        while (form == Form.INDIRECT) {
            if (++indirectJumps > MAX_INDIRECT) throw CursorException("DW_FORM_indirect 跳转超过 $MAX_INDIRECT 次")
            form = c.uleb128().toInt()
        }
        return when (form) {
            Form.ADDR -> readAddr(c, ctx)
            Form.DATA1 -> AttrValue.Uconstant(c.u8().toLong(), form)
            Form.DATA2 -> AttrValue.Uconstant(c.u16().toLong(), form)
            Form.DATA4 -> AttrValue.Uconstant(c.u32(), form)
            Form.DATA8 -> {
                // 保留无符号 64 位解释；high_pc 的有符号偏移语义由调用方按 attr 判断
                c.require(8); val b = c.base + c.pos; c.pos += 8
                var v = 0L; for (i in 0 until 8) v = v or ((c.data[b + i].toLong() and 0xFFL) shl (8 * i))
                AttrValue.Uconstant(v, form)
            }
            Form.SDATA -> AttrValue.Sconstant(c.sleb128())
            Form.UDATA -> AttrValue.Uconstant(c.uleb128(), form)
            Form.STRING -> AttrValue.Str(readLocalCString(c))
            Form.FLAG -> AttrValue.Flag(c.u8() != 0)
            Form.FLAG_PRESENT -> AttrValue.Flag(true)
            Form.STRP -> readStrp(c, ctx, Form.STRP)
            Form.LINE_STRP -> readLineStrp(c)
            Form.SEC_OFFSET -> AttrValue.SecOff(readUnitSize(c, ctx), form)
            Form.REF1 -> AttrValue.Ref(ctx.unitStart + c.u8(), form)
            Form.REF2 -> AttrValue.Ref(ctx.unitStart + c.u16(), form)
            Form.REF4 -> AttrValue.Ref(ctx.unitStart + c.u32(), form)
            Form.REF8 -> AttrValue.Ref(ctx.unitStart + c.i64(), form)
            Form.REF_UDATA -> AttrValue.Ref(ctx.unitStart + c.uleb128(), form)
            Form.REF_ADDR -> AttrValue.Ref(if (ctx.dwarf64) c.i64() else c.u32(), form)
            Form.REF_SUP4 -> { c.pos += 4; AttrValue.Unknown(form, 4) }
            Form.REF_SUP8 -> { c.pos += 8; AttrValue.Unknown(form, 8) }
            Form.REF_SIG8 -> { c.pos += 8; AttrValue.Unknown(form, 8) }
            Form.EXPRLOC -> AttrValue.Bytes(c.bytes(c.uleb128().toInt()))
            Form.BLOCK -> AttrValue.Bytes(c.bytes(c.uleb128().toInt()))
            Form.BLOCK1 -> AttrValue.Bytes(c.bytes(c.u8()))
            Form.BLOCK2 -> AttrValue.Bytes(c.bytes(c.u16()))
            Form.BLOCK4 -> AttrValue.Bytes(c.bytes(c.u32().toInt()))
            Form.DATA16 -> AttrValue.Bytes(c.bytes(16))
            Form.IMPLICIT_CONST -> AttrValue.Sconstant(0) // abbrev 无隐式常量载荷（我们不生成）
            Form.STRX, Form.STRX1, Form.STRX2, Form.STRX3, Form.STRX4 ->
                readStrx(c, ctx, form)
            Form.ADDRX, Form.ADDRX1, Form.ADDRX2, Form.ADDRX3, Form.ADDRX4,
            Form.GNU_ADDR_INDEX -> readAddrx(c, ctx, form)
            Form.RNGLISTX, Form.GNU_RANGELIST_X -> AttrValue.Uconstant(readIndex(c, form), form)
            Form.GNU_STR_INDEX -> readStrx(c, ctx, form)
            else -> readUnknown(c, ctx, form)
        }
    }

    private fun readAddr(c: ByteCursor, ctx: FormContext): AttrValue {
        val v = when (ctx.addressSize) {
            1 -> c.u8().toLong()
            2 -> c.u16().toLong()
            4 -> c.u32()
            8 -> c.i64()
            else -> throw CursorException("不支持的地址宽度 ${ctx.addressSize}")
        }
        return AttrValue.Address(v)
    }

    private fun readUnitSize(c: ByteCursor, ctx: FormContext): Long =
        if (ctx.dwarf64) c.i64() else c.u32()

    private fun readLocalCString(c: ByteCursor): String {
        val start = c.base + c.pos
        var end = start
        while (end < c.base + c.limit && c.data[end].toInt() != 0) end++
        if (end >= c.base + c.limit) throw CursorException("内联字符串未终止")
        val s = String(c.data, start, end - start, Charsets.UTF_8)
        c.pos += end - start + 1
        return s
    }

    private fun readStrp(c: ByteCursor, ctx: FormContext, form: Int): AttrValue {
        val off = readUnitSize(c, ctx)
        val s = sections.cString(if (ctx.version >= 5) ".debug_str" else ".debug_str", off)
            ?: throw CursorException(".debug_str+0x${off.toString(16)} 字符串缺失")
        return AttrValue.Str(s)
    }

    private fun readLineStrp(c: ByteCursor): AttrValue {
        val off = c.u32()
        val s = sections.cString(".debug_line_str", off.toLong())
            ?: throw CursorException(".debug_line_str+0x${off.toString(16)} 字符串缺失")
        return AttrValue.Str(s)
    }

    private fun indexSize(form: Int): Int = when (form) {
        Form.STRX1, Form.STRX2, Form.STRX3, Form.STRX4 -> form - Form.STRX1 + 1
        Form.ADDRX1, Form.ADDRX2, Form.ADDRX3, Form.ADDRX4 -> form - Form.ADDRX1 + 1
        else -> -1
    }

    private fun readIndex(c: ByteCursor, form: Int): Long {
        val n = indexSize(form)
        return when {
            n > 0 -> when (n) { 1 -> c.u8().toLong(); 2 -> c.u16().toLong(); 3 -> c.u32() and 0xffffff; else -> c.u32() }
            else -> c.uleb128()
        }
    }

    private fun readStrx(c: ByteCursor, ctx: FormContext, form: Int): AttrValue {
        val idx = readIndex(c, form)
        val base = ctx.strOffsetsBase ?: throw CursorException("缺少 DW_AT_str_offsets_base 却使用字符串索引 form=0x${form.toString(16)}")
        val strOff = readStrOffsetEntry(base, idx, ctx)
        val s = sections.cString(".debug_str", strOff)
            ?: throw CursorException("str_offsets[base=0x${base.toString(16)}, idx=$idx] 指向坏字符串")
        return AttrValue.Str(s)
    }

    /** 读取 .debug_str_offsets 的一个条目（自动识别 4/8 字节的 header 长度）。 */
    private fun readStrOffsetEntry(base: Long, idx: Long, ctx: FormContext): Long {
        val sc = sections.cursor(".debug_str_offsets") ?: throw CursorException("缺少 .debug_str_offsets")
        val entrySize = ctx.addressSize.coerceAtLeast(4)
        val hdr = try { sc.pos = (base - 8).toInt(); sc.u32() } catch (e: Exception) { -1L }
        // base 指向 header 之后第一个条目；直接从 base 取第 idx 项
        sc.jump(base + idx * entrySize, MAX_REF_JUMPS)
        return if (entrySize == 8) sc.i64() else sc.u32()
    }

    private fun readAddrx(c: ByteCursor, ctx: FormContext, form: Int): AttrValue {
        val idx = readIndex(c, form)
        val base = ctx.addrBase ?: 0L
        val ac = sections.cursor(".debug_addr") ?: throw CursorException("使用了地址索引但缺少 .debug_addr")
        ac.jump(base + idx * ctx.addressSize, MAX_REF_JUMPS)
        val v = when (ctx.addressSize) {
            4 -> ac.u32(); 8 -> ac.i64(); 2 -> ac.u16().toLong(); else -> ac.u8().toLong()
        }
        return AttrValue.Address(v)
    }

    private fun readUnknown(c: ByteCursor, ctx: FormContext, form: Int): AttrValue {
        // 未知 form 无法确定长度 → 不能安全继续读取同一 DIE，抛错让上层把 CU 标记损坏，
        // 避免游标错位后继续产生伪结果。
        ctx.issues += ParseIssue(ParseIssue.Severity.ERROR, "dwarf.unknown_form",
            "未知 DW_FORM 0x${form.toString(16)}，已隔离当前编译单元", ".debug_info")
        throw CursorException("未知 form 0x${form.toString(16)}")
    }

    companion object {
        const val MAX_INDIRECT = 8
        const val MAX_REF_JUMPS = 64
    }
}
