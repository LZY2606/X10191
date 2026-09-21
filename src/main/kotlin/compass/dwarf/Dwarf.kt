package compass.dwarf

object Dwarf {
    // unit types (DWARF5)
    const val UT_COMPILE = 0x01
    const val UT_SKELETON = 0x04
    const val UT_SPLIT_COMPILE = 0x05

    // tags
    const val TAG_COMPILE_UNIT = 0x11
    const val TAG_SUBPROGRAM = 0x2e
    const val TAG_INLINED_SUBROUTINE = 0x1d

    // attributes
    const val AT_NAME = 0x03
    const val AT_STMT_LIST = 0x10
    const val AT_LOW_PC = 0x11
    const val AT_HIGH_PC = 0x12
    const val AT_COMP_DIR = 0x1b
    const val AT_ABSTRACT_ORIGIN = 0x31
    const val AT_RANGES = 0x55
    const val AT_CALL_FILE = 0x58
    const val AT_CALL_LINE = 0x59
    const val AT_CALL_COLUMN = 0x5a
    const val AT_DECL_FILE = 0x3a
    const val AT_DECL_LINE = 0x3b
    const val AT_DWO_ID = 0x75
    const val AT_DWO_NAME = 0x76
    const val AT_GNU_DWO_NAME = 0x2130
    const val AT_GNU_DWO_ID = 0x2131

    // forms
    const val FORM_ADDR = 0x01
    const val FORM_BLOCK2 = 0x03
    const val FORM_BLOCK4 = 0x04
    const val FORM_DATA2 = 0x05
    const val FORM_DATA4 = 0x06
    const val FORM_DATA8 = 0x07
    const val FORM_STRING = 0x08
    const val FORM_BLOCK = 0x09
    const val FORM_BLOCK1 = 0x0a
    const val FORM_DATA1 = 0x0b
    const val FORM_FLAG = 0x0c
    const val FORM_SDATA = 0x0d
    const val FORM_STRP = 0x0e
    const val FORM_UDATA = 0x0f
    const val FORM_REF_ADDR = 0x10
    const val FORM_REF1 = 0x11
    const val FORM_REF2 = 0x12
    const val FORM_REF4 = 0x13
    const val FORM_REF8 = 0x14
    const val FORM_REF_UDATA = 0x15
    const val FORM_INDIRECT = 0x16
    const val FORM_SEC_OFFSET = 0x17
    const val FORM_EXPRLoc = 0x18
    const val FORM_FLAG_PRESENT = 0x19
    const val FORM_STRX = 0x1a
    const val FORM_ADDRX = 0x1b
    const val FORM_REF_SUP4 = 0x1c
    const val FORM_STRP_SUP = 0x1d
    const val FORM_DATA16 = 0x1e
    const val FORM_LINE_STRP = 0x1f
    const val FORM_REF_SIG8 = 0x20
    const val FORM_IMPLICIT_CONST = 0x21
    const val FORM_LOCLISTX = 0x22
    const val FORM_RNGLISTX = 0x23
    const val FORM_REF_SUP8 = 0x24
    const val FORM_STRX1 = 0x25
    const val FORM_STRX2 = 0x26
    const val FORM_STRX3 = 0x27
    const val FORM_STRX4 = 0x28
    const val FORM_ADDRX1 = 0x29
    const val FORM_ADDRX2 = 0x2a
    const val FORM_ADDRX3 = 0x2b
    const val FORM_ADDRX4 = 0x2c

    val KNOWN_FORMS: Set<Int> = setOf(
        FORM_ADDR, FORM_BLOCK2, FORM_BLOCK4, FORM_DATA2, FORM_DATA4, FORM_DATA8,
        FORM_STRING, FORM_BLOCK, FORM_BLOCK1, FORM_DATA1, FORM_FLAG, FORM_SDATA,
        FORM_STRP, FORM_UDATA, FORM_REF_ADDR, FORM_REF1, FORM_REF2, FORM_REF4,
        FORM_REF8, FORM_REF_UDATA, FORM_INDIRECT, FORM_SEC_OFFSET, FORM_EXPRLoc,
        FORM_FLAG_PRESENT, FORM_STRX, FORM_ADDRX, FORM_REF_SUP4, FORM_STRP_SUP,
        FORM_DATA16, FORM_LINE_STRP, FORM_REF_SIG8, FORM_IMPLICIT_CONST,
        FORM_LOCLISTX, FORM_RNGLISTX, FORM_REF_SUP8, FORM_STRX1, FORM_STRX2,
        FORM_STRX3, FORM_STRX4, FORM_ADDRX1, FORM_ADDRX2, FORM_ADDRX3, FORM_ADDRX4
    )

    val TAG_NAMES = mapOf(0x11 to "compile_unit", 0x2e to "subprogram", 0x1d to "inlined_subroutine")

    val AT_NAMES = mapOf(
        AT_NAME to "DW_AT_name", AT_STMT_LIST to "DW_AT_stmt_list", AT_LOW_PC to "DW_AT_low_pc",
        AT_HIGH_PC to "DW_AT_high_pc", AT_COMP_DIR to "DW_AT_comp_dir",
        AT_ABSTRACT_ORIGIN to "DW_AT_abstract_origin", AT_RANGES to "DW_AT_ranges",
        AT_CALL_FILE to "DW_AT_call_file", AT_CALL_LINE to "DW_AT_call_line",
        AT_CALL_COLUMN to "DW_AT_call_column", AT_DECL_FILE to "DW_AT_decl_file",
        AT_DECL_LINE to "DW_AT_decl_line", AT_DWO_ID to "DW_AT_dwo_id",
        AT_DWO_NAME to "DW_AT_dwo_name", AT_GNU_DWO_NAME to "DW_AT_GNU_dwo_name",
        AT_GNU_DWO_ID to "DW_AT_GNU_dwo_id"
    )

    // line program standard opcodes
    const val LNS_COPY = 1
    const val LNS_ADVANCE_PC = 2
    const val LNS_ADVANCE_LINE = 3
    const val LNS_SET_FILE = 4
    const val LNS_SET_COLUMN = 5
    const val LNS_NEGATE_STMT = 6
    const val LNS_SET_BASIC_BLOCK = 7
    const val LNS_CONST_ADD_PC = 8
    const val LNS_FIXED_ADVANCE_PC = 9
    const val LNS_SET_PROLOGUE_END = 10
    const val LNS_SET_EPILOGUE_BEGIN = 11
    const val LNS_SET_ISA = 12

    // extended opcodes
    const val LNE_END_SEQUENCE = 1
    const val LNE_SET_ADDRESS = 2
    const val LNE_DEFINE_FILE = 3
    const val LNE_SET_DISCRIMINATOR = 4

    // rnglist entry kinds (DWARF5)
    const val RLE_END_OF_LIST = 0
    const val RLE_BASE_ADDRESSX = 1
    const val RLE_STARTX_ENDX = 2
    const val RLE_STARTX_LENGTH = 3
    const val RLE_OFFSET_PAIR = 4
    const val RLE_BASE_ADDRESS = 5
    const val RLE_START_END = 6
    const val RLE_START_LENGTH = 7

    // limits: parser self-defence against corrupt input
    const val MAX_DIE_DEPTH = 64
    const val MAX_DIES_PER_CU = 100_000
    const val MAX_ATTRS_PER_DIE = 512
    const val MAX_INDIRECT_DEPTH = 4
    const val MAX_LINE_ROWS = 1_000_000
}
