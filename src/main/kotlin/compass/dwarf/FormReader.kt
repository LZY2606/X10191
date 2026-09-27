package compass.dwarf

import compass.model.Endian
import compass.model.UnknownFormException

/** 属性值的原始分类；字符串解析、地址索引等在 DIE 构建阶段结合 CU 上下文完成。 */
sealed class AttrVal {
    data class Address(val v: Long) : AttrVal()
    data class UConstant(val v: Long) : AttrVal()
    data class SConstant(val v: Long) : AttrVal()
    data class Bool(val v: Boolean) : AttrVal()
    data class InSectionStr(val off: Long) : AttrVal()       // .debug_str 偏移
    data class InLineStr(val off: Long) : AttrVal()          // .debug_line_str 偏移
    data class InlineStr(val v: String) : AttrVal()
    data class RefInfo(val off: Long) : AttrVal()            // .debug_info 内偏移
    data class SecOffset(val v: Long) : AttrVal()
    data class StrIndex(val idx: Long) : AttrVal()
    data class AddrIndex(val idx: Long) : AttrVal()
    data class RngListIndex(val idx: Long) : AttrVal()
    data class Block(val v: ByteArray) : AttrVal()
    data class Expr(val v: ByteArray) : AttrVal()
    data class RefSig(val v: Long) : AttrVal()
    data class Unknown(val form: Int) : AttrVal()
}

class FormReader(
    private val r: ByteReader,
    private val endian: Endian,
    private val dwarfFormat: Int,
    private val addressSize: Int
) {
    /** 读取一个 form。未知 form 抛 [UnknownFormException]，由 CU 解析器隔离。 */
    fun read(form: Int, implicitConst: Long?): AttrVal {
        val f = if (form == DW_FORM.INDIRECT) r.readULEB128().toInt() else form
        return when (f) {
            DW_FORM.ADDR -> AttrVal.Address(r.readAddress(addressSize, endian))
            DW_FORM.DATA1 -> AttrVal.UConstant(r.readByte().toLong())
            DW_FORM.DATA2 -> AttrVal.UConstant(r.readU16(endian).toLong())
            DW_FORM.DATA4 -> AttrVal.UConstant(r.readU32(endian))
            DW_FORM.DATA8 -> AttrVal.UConstant(r.readU64(endian))
            DW_FORM.UDATA -> AttrVal.UConstant(r.readULEB128())
            DW_FORM.SDATA -> AttrVal.SConstant(r.readSLEB128())
            DW_FORM.FLAG -> AttrVal.Bool(r.readByte() != 0)
            DW_FORM.FLAG_PRESENT -> AttrVal.Bool(true)
            DW_FORM.STRING -> AttrVal.InlineStr(r.readNullTerminated())
            DW_FORM.STRP -> AttrVal.InSectionStr(if (dwarfFormat == 64) r.readU64(endian) else r.readU32(endian))
            DW_FORM.LINE_STRP -> AttrVal.InLineStr(if (dwarfFormat == 64) r.readU64(endian) else r.readU32(endian))
            DW_FORM.REF_ADDR -> AttrVal.RefInfo(if (dwarfFormat == 64) r.readU64(endian) else r.readU32(endian))
            DW_FORM.REF1 -> AttrVal.RefInfo(r.readByte().toLong())
            DW_FORM.REF2 -> AttrVal.RefInfo(r.readU16(endian).toLong())
            DW_FORM.REF4 -> AttrVal.RefInfo(r.readU32(endian))
            DW_FORM.REF8 -> AttrVal.RefInfo(r.readU64(endian))
            DW_FORM.REF_UDATA -> AttrVal.RefInfo(r.readULEB128())
            DW_FORM.SEC_OFFSET -> AttrVal.SecOffset(if (dwarfFormat == 64) r.readU64(endian) else r.readU32(endian))
            DW_FORM.STRX, DW_FORM.STRX1, DW_FORM.STRX2,
            DW_FORM.GNU_STR_INDEX -> AttrVal.StrIndex(readIndex(f))
            DW_FORM.ADDRX, DW_FORM.ADDRX1, DW_FORM.GNU_ADDR_INDEX -> AttrVal.AddrIndex(readIndex(f))
            DW_FORM.RNGLISTX -> AttrVal.RngListIndex(r.readULEB128())
            DW_FORM.RNGLIST -> AttrVal.SecOffset(r.readULEB128())
            DW_FORM.BLOCK1 -> AttrVal.Block(r.readBytes(r.readByte()))
            DW_FORM.BLOCK2 -> AttrVal.Block(r.readBytes(r.readU16(endian)))
            DW_FORM.BLOCK4 -> AttrVal.Block(r.readBytes(r.readU32(endian).toInt()))
            DW_FORM.BLOCK -> AttrVal.Block(r.readBytes(r.readULEB128().toInt()))
            DW_FORM.EXPRLOC -> AttrVal.Expr(r.readBytes(r.readULEB128().toInt()))
            DW_FORM.REF_SIG8 -> AttrVal.RefSig(r.readU64(endian))
            DW_FORM.IMPLICIT_CONST -> AttrVal.SConstant(implicitConst ?: 0L)
            DW_FORM.DATA16 -> AttrVal.Block(r.readBytes(16))
            DW_FORM.REF_SUP4 -> { r.readU32(endian); AttrVal.Unknown(f) }
            DW_FORM.STRP_SUP -> { if (dwarfFormat == 64) r.readU64(endian) else r.readU32(endian); AttrVal.Unknown(f) }
            DW_FORM.GNU_REF_ALT -> { r.readULEB128(); AttrVal.Unknown(f) }
            else -> throw UnknownFormException(f)
        }
    }

    private fun readIndex(form: Int): Long = when (form) {
        DW_FORM.STRX1, DW_FORM.ADDRX1 -> r.readByte().toLong()
        DW_FORM.STRX2, DW_FORM.ADDRX2 -> r.readU16(endian).toLong()
        DW_FORM.GNU_STR_INDEX, DW_FORM.GNU_ADDR_INDEX, DW_FORM.STRX, DW_FORM.ADDRX -> r.readULEB128()
        else -> r.readULEB128()
    }
}
