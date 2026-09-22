package compass.dwarf

object DW {
    // tags
    const val TAG_COMPILE_UNIT = 0x11L
    const val TAG_PARTIAL_UNIT = 0x3cL
    const val TAG_SUBPROGRAM = 0x2eL
    const val TAG_INLINED_SUBROUTINE = 0x1dL
    const val TAG_LEXICAL_BLOCK = 0x0bL

    // attributes
    const val AT_NAME = 0x03L
    const val AT_LOW_PC = 0x11L
    const val AT_HIGH_PC = 0x12L
    const val AT_STMT_LIST = 0x10L
    const val AT_COMP_DIR = 0x1bL
    const val AT_PRODUCER = 0x25L
    const val AT_RANGES = 0x55L
    const val AT_CALL_FILE = 0x58L
    const val AT_CALL_LINE = 0x59L
    const val AT_CALL_COLUMN = 0x57L
    const val AT_INLINE = 0x20L
    const val AT_ABSTRACT_ORIGIN = 0x31L
    const val AT_SPECIFICATION = 0x47L
    const val AT_DWO_NAME = 0x76L
    const val AT_GNU_DWO_NAME = 0x2130L
    const val AT_STR_OFFSETS_BASE = 0x72L
    const val AT_RNGLISTS_BASE = 0x74L
    const val AT_ADDR_BASE = 0x73L

    // forms
    const val FORM_ADDR = 0x01L
    const val FORM_BLOCK2 = 0x03L
    const val FORM_BLOCK4 = 0x04L
    const val FORM_DATA2 = 0x05L
    const val FORM_DATA4 = 0x06L
    const val FORM_DATA8 = 0x07L
    const val FORM_STRING = 0x08L
    const val FORM_BLOCK = 0x09L
    const val FORM_BLOCK1 = 0x0aL
    const val FORM_DATA1 = 0x0bL
    const val FORM_FLAG = 0x0cL
    const val FORM_SDATA = 0x0dL
    const val FORM_STRP = 0x0eL
    const val FORM_UDATA = 0x0fL
    const val FORM_REF_ADDR = 0x10L
    const val FORM_REF1 = 0x11L
    const val FORM_REF2 = 0x12L
    const val FORM_REF4 = 0x13L
    const val FORM_REF8 = 0x14L
    const val FORM_REF_UDATA = 0x15L
    const val FORM_INDIRECT = 0x16L
    const val FORM_SEC_OFFSET = 0x17L
    const val FORM_EXPLOC = 0x18L
    const val FORM_FLAG_PRESENT = 0x19L
    const val FORM_STRX = 0x1aL
    const val FORM_ADDRX = 0x1bL
    const val FORM_REF_SUP4 = 0x1cL
    const val FORM_STRP_SUP = 0x1dL
    const val FORM_DATA16 = 0x1eL
    const val FORM_LINE_STRP = 0x1fL
    const val FORM_REF_SIG8 = 0x20L
    const val FORM_IMPLICIT_CONST = 0x21L
    const val FORM_LOCLISTX = 0x22L
    const val FORM_RNGLISTX = 0x23L
    const val FORM_REF_SUP8 = 0x24L
    const val FORM_STRX1 = 0x25L
    const val FORM_STRX2 = 0x26L
    const val FORM_STRX3 = 0x27L
    const val FORM_STRX4 = 0x28L
    const val FORM_ADDRX1 = 0x29L
    const val FORM_ADDRX2 = 0x2aL
    const val FORM_ADDRX3 = 0x2bL
    const val FORM_ADDRX4 = 0x2cL

    // line header content types
    const val LNCT_PATH = 0x1L
    const val LNCT_DIRECTORY_INDEX = 0x2L
    const val LNCT_TIMESTAMP = 0x3L
    const val LNCT_SIZE = 0x4L
    const val LNCT_MD5 = 0x5L

    // unit types (DWARF5)
    const val UT_COMPILE = 0x01
    const val UT_TYPE = 0x02
    const val UT_PARTIAL = 0x03
    const val UT_SKELETON = 0x04
    const val UT_SPLIT_COMPILE = 0x05
    const val UT_SPLIT_TYPE = 0x06

    val ADDRESS_FORMS = setOf(FORM_ADDR, FORM_ADDRX, FORM_ADDRX1, FORM_ADDRX2, FORM_ADDRX3, FORM_ADDRX4)
}

sealed interface AttrValue {
    data class UIntV(val v: Long) : AttrValue
    data class SIntV(val v: Long) : AttrValue
    data class AddrV(val v: Long) : AttrValue
    data class AddrIdxV(val index: Long) : AttrValue
    data class StrV(val s: String) : AttrValue
    data class StrpV(val offset: Long, val table: String) : AttrValue
    data class StrxV(val index: Long) : AttrValue
    data class RefV(val offset: Long) : AttrValue
    data class FlagV(val v: Boolean) : AttrValue
    data class BytesV(val b: ByteArray) : AttrValue
    data class SecOffV(val offset: Long) : AttrValue
}

data class Attr(val attr: Long, val form: Long, val value: AttrValue)

class FormReader(
    private val addrSize: Int,
    private val dwarf64: Boolean,
    private val version: Int,
    private val cuStart: Long,
) {
    fun read(c: Cursor, formIn: Long, implicitConst: Long?, hop: Int = 0): AttrValue {
        var form = formIn
        if (form == DW.FORM_INDIRECT) {
            if (hop >= 4) throw DwarfParseException("DW_FORM_indirect chain too deep")
            form = c.uleb()
            return read(c, form, null, hop + 1)
        }
        return when (form) {
            DW.FORM_ADDR -> AttrValue.AddrV(c.addr(addrSize))
            DW.FORM_BLOCK1 -> AttrValue.BytesV(c.bytes(c.u8()))
            DW.FORM_BLOCK2 -> AttrValue.BytesV(c.bytes(c.u16()))
            DW.FORM_BLOCK4 -> AttrValue.BytesV(c.bytes(c.u32().toInt()))
            DW.FORM_BLOCK, DW.FORM_EXPLOC -> AttrValue.BytesV(c.bytes(c.uleb().toInt()))
            DW.FORM_DATA1 -> AttrValue.UIntV(c.u8().toLong())
            DW.FORM_DATA2 -> AttrValue.UIntV(c.u16().toLong())
            DW.FORM_DATA4 -> AttrValue.UIntV(c.u32())
            DW.FORM_DATA8 -> AttrValue.UIntV(c.u64())
            DW.FORM_DATA16 -> AttrValue.BytesV(c.bytes(16))
            DW.FORM_SDATA -> AttrValue.SIntV(c.sleb())
            DW.FORM_UDATA -> AttrValue.UIntV(c.uleb())
            DW.FORM_STRING -> AttrValue.StrV(c.cstring())
            DW.FORM_STRP -> AttrValue.StrpV(c.offset(dwarf64), ".debug_str")
            DW.FORM_LINE_STRP -> AttrValue.StrpV(c.offset(dwarf64), ".debug_line_str")
            DW.FORM_STRP_SUP -> AttrValue.StrpV(c.offset(dwarf64), ".debug_str (sup)")
            DW.FORM_FLAG -> AttrValue.FlagV(c.u8() != 0)
            DW.FORM_FLAG_PRESENT -> AttrValue.FlagV(true)
            DW.FORM_REF1 -> AttrValue.RefV(cuStart + c.u8())
            DW.FORM_REF2 -> AttrValue.RefV(cuStart + c.u16())
            DW.FORM_REF4 -> AttrValue.RefV(cuStart + c.u32())
            DW.FORM_REF8 -> AttrValue.RefV(cuStart + c.u64())
            DW.FORM_REF_UDATA -> AttrValue.RefV(cuStart + c.uleb())
            DW.FORM_REF_ADDR -> AttrValue.RefV(if (version == 2) c.addr(addrSize) else c.offset(dwarf64))
            DW.FORM_REF_SIG8 -> AttrValue.UIntV(c.u64())
            DW.FORM_REF_SUP4 -> AttrValue.RefV(c.u32())
            DW.FORM_REF_SUP8 -> AttrValue.RefV(c.u64())
            DW.FORM_SEC_OFFSET -> AttrValue.SecOffV(c.offset(dwarf64))
            DW.FORM_IMPLICIT_CONST -> AttrValue.SIntV(implicitConst ?: 0L)
            DW.FORM_STRX -> AttrValue.StrxV(c.uleb())
            DW.FORM_STRX1 -> AttrValue.StrxV(c.u8().toLong())
            DW.FORM_STRX2 -> AttrValue.StrxV(c.u16().toLong())
            DW.FORM_STRX3 -> AttrValue.StrxV(c.u24().toLong())
            DW.FORM_STRX4 -> AttrValue.StrxV(c.u32())
            DW.FORM_ADDRX -> AttrValue.AddrIdxV(c.uleb())
            DW.FORM_ADDRX1 -> AttrValue.AddrIdxV(c.u8().toLong())
            DW.FORM_ADDRX2 -> AttrValue.AddrIdxV(c.u16().toLong())
            DW.FORM_ADDRX3 -> AttrValue.AddrIdxV(c.u24().toLong())
            DW.FORM_ADDRX4 -> AttrValue.AddrIdxV(c.u32())
            DW.FORM_RNGLISTX, DW.FORM_LOCLISTX -> AttrValue.UIntV(c.uleb())
            else -> throw UnknownFormException(form)
        }
    }
}
