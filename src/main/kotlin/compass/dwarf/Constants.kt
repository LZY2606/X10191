package compass.dwarf

object Tag {
    const val COMPILE_UNIT = 0x11
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val SUBRANGE_TYPE = 0x21
    const val COMPILE_UNIT_5 = 0x11
}

object Attr {
    const val SIBLING = 0x01
    const val LOCATION = 0x02
    const val NAME = 0x03
    const val COMP_DIR = 0x1b
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val STMT_LIST = 0x10
    const val ABSTRACT_ORIGIN = 0x31
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val CALL_COLUMN = 0x57
    const val RANGES = 0x55
    const val STR_OFFSETS_BASE = 0x72
    const val ADDR_BASE = 0x73
    const val GNU_ADDR_BASE = 0x2133
    const val RNGLIST_BASE = 0x74
    const val STR_OFFSETS_BASE_SIGNED = 0x72
    const val COMP_NAME = 0x3b
    const val DW_AT_GNU_DWO_NAME = 0x2130
    const val DW_AT_GNU_DWO_ID = 0x2131
    const val DW_AT_dwo_name = 0x76
    const val DW_AT_GNU_ranges_base = 0x2132
}

object Form {
    const val ADDR = 0x01
    const val BLOCK2 = 0x03
    const val BLOCK4 = 0x04
    const val DATA2 = 0x05
    const val DATA4 = 0x06
    const val DATA8 = 0x07
    const val STRING = 0x08
    const val BLOCK = 0x09
    const val BLOCK1 = 0x0a
    const val DATA1 = 0x0b
    const val FLAG = 0x0c
    const val SDATA = 0x0d
    const val STRP = 0x0e
    const val UDATA = 0x0f
    const val REF_ADDR = 0x10
    const val REF1 = 0x11
    const val REF2 = 0x12
    const val REF4 = 0x13
    const val REF8 = 0x14
    const val REF_UDATA = 0x15
    const val INDIRECT = 0x16
    const val SEC_OFFSET = 0x17
    const val EXPRLOC = 0x18
    const val FLAG_PRESENT = 0x19
    const val STRX = 0x1a
    const val ADDRX = 0x1b
    const val REF_SUP4 = 0x1c
    const val STRP_SUP = 0x1d
    const val DATA16 = 0x1e
    const val LINE_STRP = 0x1f
    const val REF_SIG8 = 0x20
    const val IMPLICIT_CONST = 0x21
    const val LOCLISTX = 0x22
    const val RNGLISTX = 0x23
    const val REF_SUP8 = 0x24
    const val STRX1 = 0x25
    const val STRX2 = 0x26
    const val STRX3 = 0x27
    const val STRX4 = 0x28
    const val ADDRX1 = 0x29
    const val ADDRX2 = 0x2a
    const val ADDRX3 = 0x2b
    const val ADDRX4 = 0x2c
    const val LOCLISTX1 = 0x2d
    const val LOCLISTX2 = 0x2e
    const val LOCLISTX3 = 0x2f
    const val LOCLISTX4 = 0x30
    const val RNGLISTX1 = 0x31
    const val RNGLISTX2 = 0x32
    const val RNGLISTX3 = 0x33
    const val RNGLISTX4 = 0x34
    const val GNU_STR_OFFSETS = 0x1f02
    const val GNU_ADDRX = 0x1f03
    const val GNU_ADDRX1 = 0x1f04
    const val GNU_ADDRX2 = 0x1f05
    const val GNU_ADDRX3 = 0x1f06
    const val GNU_ADDRX4 = 0x1f07
    const val GNU_RNGLISTX = 0x1f10
    const val GNU_RNGLISTX1 = 0x1f11
    const val GNU_RNGLISTX2 = 0x1f12
    const val GNU_RNGLISTX3 = 0x1f13
    const val GNU_RNGLISTX4 = 0x1f14
}

/** Line program standard opcodes (DWARF 4/5 share the core set). */
object LineOp {
    const val COPY = 0x01
    const val ADVANCE_PC = 0x02
    const val LINE = 0x03
    const val FILE = 0x04
    const val SET_COLUMN = 0x05
    const val NEGATE_STMT = 0x06
    const val SET_BASIC_BLOCK = 0x07
    const val CONST_ADD_PC = 0x08
    const val FIXED_ADVANCE_PC = 0x09
    const val SET_PROLOGUE_END = 0x0a
    const val SET_EPILOGUE_BEGIN = 0x0b
    const val SET_ISA = 0x0c
    // v5
    const val UNDEFINED = 0x0d
    const val SAME_VALUE = 0x0e
    const val SET_PROLOGUE_END_V5 = 0x0f
    const val SET_EPILOGUE_BEGIN_V5 = 0x10
    const val SET_FILE = 0x04
}

object LineExt {
    const val END_SEQUENCE = 0x01
    const val SET_ADDRESS = 0x02
    const val DEFINE_FILE = 0x03
    const val SET_DISCRIMINATOR = 0x04
    const val SET_IS_STATEMENT_V5 = 0x05
    const val SET_BASIC_BLOCK_V5 = 0x06
    const val ADD_CONST_PC_V5 = 0x07
    const val SET_FIRST_SPECIAL_V5 = 0x08
}

object RangeOp {
    // .debug_ranges (v4) sentinels
    const val MAX_ADDR4 = 0xffffffffL
    const val MAX_ADDR8 = -1L
    // v5 .debug_rnglists
    const val RLE_end_of_list = 0x00
    const val RLE_base_addressx = 0x01
    const val RLE_startx_endx = 0x02
    const val RLE_startx_length = 0x03
    const val RLE_offset_pair = 0x04
    const val RLE_base_address = 0x05
    const val RLE_start_end = 0x06
    const val RLE_start_length = 0x07
}

object Children {
    const val NO = 0x00
    const val YES = 0x01
}
