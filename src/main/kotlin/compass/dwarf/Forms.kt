package compass.dwarf

import compass.BinReader

// DW_FORM
const val DW_FORM_addr = 0x01
const val DW_FORM_block2 = 0x03
const val DW_FORM_block4 = 0x04
const val DW_FORM_data2 = 0x05
const val DW_FORM_data4 = 0x06
const val DW_FORM_data8 = 0x07
const val DW_FORM_string = 0x08
const val DW_FORM_block = 0x09
const val DW_FORM_block1 = 0x0a
const val DW_FORM_data1 = 0x0b
const val DW_FORM_flag = 0x0c
const val DW_FORM_sdata = 0x0d
const val DW_FORM_strp = 0x0e
const val DW_FORM_udata = 0x0f
const val DW_FORM_ref_addr = 0x10
const val DW_FORM_ref1 = 0x11
const val DW_FORM_ref2 = 0x12
const val DW_FORM_ref4 = 0x13
const val DW_FORM_ref8 = 0x14
const val DW_FORM_ref_udata = 0x15
const val DW_FORM_indirect = 0x16
const val DW_FORM_sec_offset = 0x17
const val DW_FORM_exprloc = 0x18
const val DW_FORM_flag_present = 0x19
const val DW_FORM_strx = 0x1a
const val DW_FORM_addrx = 0x1b
const val DW_FORM_ref_sup4 = 0x1c
const val DW_FORM_strp_sup = 0x1d
const val DW_FORM_data16 = 0x1e
const val DW_FORM_line_strp = 0x1f
const val DW_FORM_ref_sig8 = 0x20
const val DW_FORM_implicit_const = 0x21
const val DW_FORM_loclistx = 0x22
const val DW_FORM_rnglistx = 0x23
const val DW_FORM_ref_sup8 = 0x24
const val DW_FORM_strx1 = 0x25
const val DW_FORM_strx2 = 0x26
const val DW_FORM_strx3 = 0x27
const val DW_FORM_strx4 = 0x28
const val DW_FORM_addrx1 = 0x29
const val DW_FORM_addrx2 = 0x2a
const val DW_FORM_addrx3 = 0x2b
const val DW_FORM_addrx4 = 0x2c

/** form 读取时的 CU 上下文。 */
data class FormCtx(
    val data: SectionData,
    val version: Int,
    val dwarf64: Boolean,
    val addressSize: Int,
    val refAddrSize: Int,
    val cuOffset: Long,
    val strOffsetsBase: Long,
    val addrBase: Long,
    val rngListsBase: Long,
    val useDwo: Boolean = false,
    val cuHeaderLength: Long = 0L
)

/** 读取一个 attribute 值。未知 form 抛 [UnknownFormException]，调用方负责隔离整个 CU。 */
fun readForm(r: BinReader, formIn: Int, implicitConst: Long?, ctx: FormCtx): AttrValue {
    var form = formIn
    if (form == DW_FORM_indirect) {
        form = r.uleb128().toInt()
    }
    return when (form) {
        DW_FORM_string -> AttrValue.Str(readCStringHere(r))
        DW_FORM_strp -> {
            val off = readRefWidth(r, ctx)
            AttrValue.Str(ctx.data.readString(ctx.data.debugStr, off) ?: "<str+0x${off.toString(16)}?>")
        }
        DW_FORM_line_strp -> {
            val off = readRefWidth(r, ctx)
            val sec = if (ctx.useDwo) ctx.data.debugLineDwo else ctx.data.debugLineStr
            AttrValue.Str(ctx.data.readString(sec, off) ?: "<line_str+0x${off.toString(16)}?>")
        }
        DW_FORM_strx, DW_FORM_strx1, DW_FORM_strx2, DW_FORM_strx3, DW_FORM_strx4 -> {
            val idx = readIndex(r, form)
            AttrValue.Str(ctx.data.resolveStrx(idx, ctx.strOffsetsBase, ctx.useDwo) ?: "<strx$idx?>")
        }
        DW_FORM_addr -> AttrValue.Addr(readN(r, ctx.addressSize))
        DW_FORM_addrx, DW_FORM_addrx1, DW_FORM_addrx2, DW_FORM_addrx3, DW_FORM_addrx4 -> {
            val idx = readIndex(r, form)
            AttrValue.Addr(ctx.data.readAddr(idx, ctx.addrBase, ctx.addressSize, ctx.useDwo) ?: -1L)
        }
        DW_FORM_data1 -> AttrValue.Num(r.u1().toLong())
        DW_FORM_data2 -> AttrValue.Num(r.u2().toLong())
        DW_FORM_data4 -> AttrValue.Num(r.u4().toLong())
        DW_FORM_data8 -> AttrValue.Num(r.u8())
        DW_FORM_sdata -> AttrValue.Num(r.sleb128())
        DW_FORM_udata -> AttrValue.Num(r.uleb128().toLong())
        DW_FORM_flag -> AttrValue.Num(r.u1().toLong())
        DW_FORM_flag_present -> AttrValue.Num(1)
        DW_FORM_implicit_const -> AttrValue.Num(implicitConst ?: 0L)
        DW_FORM_sec_offset -> AttrValue.SecOffset(readRefWidth(r, ctx))
        DW_FORM_ref1 -> AttrValue.Ref(ctx.cuOffset + r.u1())
        DW_FORM_ref2 -> AttrValue.Ref(ctx.cuOffset + r.u2())
        DW_FORM_ref4 -> AttrValue.Ref(ctx.cuOffset + (r.u4().toLong() and 0xffffffffL))
        DW_FORM_ref8 -> AttrValue.Ref(ctx.cuOffset + r.u8())
        DW_FORM_ref_udata -> AttrValue.Ref(ctx.cuOffset + r.uleb128().toLong())
        DW_FORM_ref_addr -> AttrValue.Ref(readN(r, ctx.refAddrSize))
        DW_FORM_ref_sig8 -> { r.u8(); AttrValue.UnknownForm(form) } // type units 不支持，安全跳过
        DW_FORM_block1 -> { val n = r.u1(); AttrValue.Num(skipBlock(r, n.toLong())) }
        DW_FORM_block2 -> { val n = r.u2().toLong(); AttrValue.Num(skipBlock(r, n)) }
        DW_FORM_block4 -> { val n = r.u4().toLong() and 0xffffffffL; AttrValue.Num(skipBlock(r, n)) }
        DW_FORM_block -> { val n = r.uleb128().toLong(); AttrValue.Num(skipBlock(r, n)) }
        DW_FORM_exprloc -> { val n = r.uleb128().toLong(); AttrValue.Num(skipBlock(r, n)) }
        DW_FORM_data16 -> { r.require(16); r.pos += 16; AttrValue.Num(0) }
        DW_FORM_rnglistx -> {
            val idx = r.uleb128().toLong()
            // 不做实际索引展开（需要 rnglist 头），保留索引并附带 base
            AttrValue.SecOffset(ctx.rngListsBase + idx)
        }
        else -> throw UnknownFormException(form)
    }
}

class UnknownFormException(val form: Int) : Exception("未知 DW_FORM 0x${form.toString(16)}，停止解析该 CU 以防游标错位")

private fun skipBlock(r: BinReader, n: Long): Long {
    if (n < 0 || n > MAX_BLOCK) throw DwarfParseError("block 长度异常: $n")
    r.require(n.toInt())
    r.pos += n.toInt()
    return n
}

const val MAX_BLOCK = 16L * 1024 * 1024

fun readN(r: BinReader, width: Int): Long = when (width) {
    1 -> r.u1().toLong()
    2 -> r.u2().toLong()
    4 -> r.u4().toLong() and 0xffffffffL
    8 -> r.u8()
    else -> throw DwarfParseError("不支持的整数宽度 $width")
}

private fun readRefWidth(r: BinReader, ctx: FormCtx): Long =
    if (ctx.dwarf64) r.u8() else r.u4().toLong() and 0xffffffffL

fun readIndex(r: BinReader, form: Int): Long = when (form) {
    DW_FORM_strx, DW_FORM_addrx, DW_FORM_ref_udata, DW_FORM_udata -> r.uleb128().toLong()
    DW_FORM_strx1, DW_FORM_addrx1, DW_FORM_data1 -> r.u1().toLong()
    DW_FORM_strx2, DW_FORM_addrx2, DW_FORM_data2 -> r.u2().toLong()
    DW_FORM_strx3 -> {
        val b0 = r.u1().toLong(); val b1 = r.u1().toLong(); val b2 = r.u1().toLong()
        b0 or (b1 shl 8) or (b2 shl 16)
    }
    DW_FORM_strx4, DW_FORM_addrx4, DW_FORM_data4 -> r.u4().toLong() and 0xffffffffL
    else -> throw DwarfParseError("不是索引 form: 0x${form.toString(16)}")
}

private fun readCStringHere(r: BinReader): String {
    val start = r.pos
    while (r.pos < r.size) {
        if (r.data[r.pos].toInt() == 0) {
            val s = String(r.data, start, r.pos - start, Charsets.UTF_8)
            r.pos++
            return s
        }
        r.pos++
    }
    throw DwarfParseError("DW_FORM_string 未终止")
}
