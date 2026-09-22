package compass.dwarf

/** DWARF tags / attributes / forms / opcodes. Values cross-checked against the DWARF 5 spec. */
object DW {
    const val TAG_COMPILE_UNIT = 0x11
    const val TAG_PARTIAL_UNIT = 0x14
    const val TAG_TYPE_UNIT = 0x41
    const val TAG_SKELETON_UNIT = 0x41 // type units reuse 0x41 in some implementations
    const val TAG_SUBPROGRAM = 0x2e
    const val TAG_INLINED_SUBROUTINE = 0x1d

    const val AT_SIBLING = 0x01
    const val AT_NAME = 0x03
    const val AT_STMT_LIST = 0x10
    const val AT_LOW_PC = 0x11
    const val AT_HIGH_PC = 0x12
    const val AT_LANGUAGE = 0x13
    const val AT_COMP_DIR = 0x1b
    const val AT_INLINE = 0x20
    const val AT_PRODUCER = 0x25
    const val AT_ABSTRACT_ORIGIN = 0x31
    const val AT_ENTRY_PC = 0x52
    const val AT_RANGES = 0x55
    const val AT_CALL_FILE = 0x58
    const val AT_CALL_LINE = 0x59
    const val AT_CALL_COLUMN = 0x57
    const val AT_LINKAGE_NAME = 0x6e
    const val AT_STR_OFFSETS_BASE = 0x72
    const val AT_ADDR_BASE = 0x73
    const val AT_RNGLISTS_BASE = 0x74
    const val AT_DWO_NAME = 0x76
    const val AT_DWO_ID = 0x75
    const val AT_MIPS_LINKAGE_NAME = 0x2007

    // GNU fission (DWARF 4 split)
    const val AT_GNU_DWO_NAME = 0x2130
    const val AT_GNU_DWO_ID = 0x2131
    const val AT_GNU_RANGES_BASE = 0x2132
    const val AT_GNU_ADDR_BASE = 0x2133

    const val UT_COMPILE = 0x01
    const val UT_TYPE = 0x02
    const val UT_PARTIAL = 0x03
    const val UT_SKELETON = 0x04
    const val UT_SPLIT_COMPILE = 0x05
    const val UT_SPLIT_TYPE = 0x06

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
    const val FORM_EXPRLOC = 0x18
    const val FORM_FLAG_PRESENT = 0x19
    const val FORM_REF_SIG8 = 0x20
    const val FORM_STRX = 0x1a
    const val FORM_ADDRX = 0x1b
    const val FORM_STRP_SUP = 0x1d
    const val FORM_DATA16 = 0x1e
    const val FORM_LINE_STRP = 0x1f
    const val FORM_IMPLICIT_CONST = 0x21
    const val FORM_LOCLISTX = 0x22
    const val FORM_RNGLISTX = 0x23
    const val FORM_STRX1 = 0x25
    const val FORM_STRX2 = 0x26
    const val FORM_STRX3 = 0x27
    const val FORM_STRX4 = 0x28
    const val FORM_ADDRX1 = 0x29
    const val FORM_ADDRX2 = 0x2a
    const val FORM_ADDRX3 = 0x2b
    const val FORM_ADDRX4 = 0x2c
    const val FORM_GNU_ADDR_INDEX = 0x1f01
    const val FORM_GNU_STR_INDEX = 0x1f02
    const val FORM_GNU_REF_ALT = 0x1f20
    const val FORM_GNU_STRP_ALT = 0x1f21

    // line standard opcodes
    const val LNS_COPY = 0x01
    const val LNS_ADVANCE_PC = 0x02
    const val LNS_ADVANCE_LINE = 0x03
    const val LNS_SET_FILE = 0x04
    const val LNS_SET_COLUMN = 0x05
    const val LNS_NEGATE_STMT = 0x06
    const val LNS_SET_BASIC_BLOCK = 0x07
    const val LNS_CONST_ADD_PC = 0x08
    const val LNS_FIXED_ADVANCE_PC = 0x09
    const val LNS_SET_PROLOGUE_END = 0x0a
    const val LNS_SET_EPILOGUE_BEGIN = 0x0b
    const val LNS_SET_ISA = 0x0c

    const val LNE_END_SEQUENCE = 0x01
    const val LNE_SET_ADDRESS = 0x02
    const val LNE_DEFINE_FILE = 0x03
    const val LNE_SET_DISCRIMINATOR = 0x04

    const val LNCT_PATH = 0x01
    const val LNCT_DIRECTORY_INDEX = 0x02
    const val LNCT_TIMESTAMP = 0x03
    const val LNCT_SIZE = 0x04
    const val LNCT_MD5 = 0x05

    // .debug_rnglists v5 entry kinds
    const val RLE_END_OF_LIST = 0x00
    const val RLE_BASE_ADDRESSX = 0x01
    const val RLE_STARTX_ENDX = 0x02
    const val RLE_STARTX_LENGTH = 0x03
    const val RLE_OFFSET_PAIR = 0x04
    const val RLE_BASE_ADDRESS = 0x05
    const val RLE_START_END = 0x06
    const val RLE_START_LENGTH = 0x07

    const val INL_INLINED = 0x01
    const val INL_DECLARED_NOT_INLINED = 0x02
    const val INL_DECLARED_INLINED = 0x03
}
