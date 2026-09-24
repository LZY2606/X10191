package compass.dwarf

/** 本解析器使用的 DWARF 常量（DW_TAG / DW_AT / DW_FORM / 行号表）。只列需要的，未知值按数字保留。 */
object DW {
    const val TAG_COMPILE_UNIT = 0x11
    const val TAG_SKELETON_UNIT = 0x11
    const val TAG_SPLIT_COMPILE_UNIT = 0x1c
    const val TAG_SUBPROGRAM = 0x2e
    const val TAG_INLINED_SUBROUTINE = 0x1d
    const val TAG_LEXICAL_BLOCK = 0x0b
    const val TAG_PARTIAL_UNIT = 0x3c
    const val TAG_TYPE_UNIT = 0x41

    const val AT_SIBLING = 0x01
    const val AT_LOCATION = 0x02
    const val AT_NAME = 0x03
    const val AT_COMP_DIR = 0x1b
    const val AT_LOW_PC = 0x11
    const val AT_HIGH_PC = 0x12
    const val AT_COMPILATION_DIRECTORY = 0x1b
    const val AT_STMT_LIST = 0x10
    const val AT_ABSTRACT_ORIGIN = 0x31
    const val AT_ABSTRACT_ORIGIN2 = 0x31
    const val AT_SPECIFICATION = 0x47
    const val AT_CALL_FILE = 0x58
    const val AT_CALL_LINE = 0x59
    const val AT_CALL_COLUMN = 0x57
    const val AT_RANGES = 0x55
    const val AT_STR_OFFSETS_BASE = 0x72
    const val AT_ADDR_BASE = 0x73
    const val AT_RNGLISTS_BASE = 0x74
    const val AT_DWO_NAME = 0x76
    const val AT_DWO_ID = 0x2013
    const val AT_GNU_DWO_NAME = 0x2130
    const val AT_GNU_DWO_ID = 0x2134
    const val AT_LINKAGE_NAME = 0x6e

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
    const val FORM_EXPRLOC = 0x18
    const val FORM_FLAG_PRESENT = 0x19
    const val FORM_STRX = 0x1a
    const val FORM_ADDRX = 0x1b
    const val FORM_REF_SUP4 = 0x1c
    const val FORM_STRP_SUP = 0x1d
    const val FORM_DATA16 = 0x1e
    const val FORM_LINE_STRP = 0x1f
    const val FORM_REF_SIG8 = 0x20
    const val FORM_IMPLICIT_CONST = 0x21
    const val FORM_LOCLISTP = 0x22
    const val FORM_RNGLISTP = 0x23
    const val FORM_STRX1 = 0x25
    const val FORM_STRX2 = 0x26
    const val FORM_STRX3 = 0x27
    const val FORM_STRX4 = 0x28
    const val FORM_ADDRX1 = 0x29
    const val FORM_ADDRX2 = 0x2a
    const val FORM_ADDRX3 = 0x2b
    const val FORM_ADDRX4 = 0x2c

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

    const val LNE_END_SEQUENCE = 1
    const val LNE_SET_ADDRESS = 2
    const val LNE_DEFINE_FILE = 3
    const val LNE_SET_DISCARD = 4
    const val LNE_SET_LOC_STMT = 5

    // DWARF5 内容类型码
    const val LNCT_PATH = 0x1
    const val LNCT_DIRECTORY_INDEX = 0x2
    const val LNCT_TIMESTAMP = 0x3
    const val LNCT_SIZE = 0x4
    const val LNCT_MD5 = 0x5

    const val UT_COMPILE = 0x01
    const val UT_PARTIAL = 0x03
    const val UT_SKELETON = 0x04
    const val UT_SPLIT_COMPILE = 0x05
    const val UT_TYPE = 0x06

    const val RLE_END_OF_LIST = 0x00
    const val RLE_BASE_ADDRESSX = 0x01
    const val RLE_STARTX_ENDX = 0x02
    const val RLE_START_LENGTH = 0x03
    const val RLE_OFFSET_LENGTH = 0x04
    const val RLE_BASE_ADDRESS = 0x05
    const val RLE_START_END = 0x06

    const val DW_RLE_max = 0x08
}
