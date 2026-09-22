package compass.dwarf

object DW {
    const val TAG_COMPILE_UNIT = 0x11
    const val TAG_SKELETON_UNIT = 0x41
    const val TAG_SPLIT_COMPILE_UNIT = 0x41
    const val TAG_PARTIAL_UNIT = 0x3c
    const val TAG_TYPE_UNIT = 0x41
    const val TAG_SUBPROGRAM = 0x2e
    const val TAG_INLINED_SUBROUTINE = 0x1d
    const val TAG_LEXICAL_BLOCK = 0x0b
    const val TAG_ABSTRACT_ORIGIN_HOLDER = 0

    const val AT_NAME = 0x03
    const val AT_STMT_LIST = 0x10
    const val AT_LOW_PC = 0x11
    const val AT_HIGH_PC = 0x12
    const val AT_COMP_DIR = 0x1b
    const val AT_PRODUCER = 0x25
    const val AT_LANGUAGE = 0x13
    const val AT_RANGES = 0x55
    const val AT_ABSTRACT_ORIGIN = 0x31
    const val AT_SPECIFICATION = 0x47
    const val AT_CALL_FILE = 0x58
    const val AT_CALL_LINE = 0x59
    const val AT_INLINE = 0x20
    const val AT_COMP_DIR_DWO = 0x76
    const val AT_DWO_NAME = 0x76
    const val AT_GNU_DWO_NAME = 0x2130
    const val AT_ADDR_BASE = 0x73
    const val AT_STRL_OFFSETS_BASE = 0x72
    const val AT_RNGLISTS_OFFSETS_BASE = 0x74
    const val AT_SKELETON = 0x78

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
    const val FORM_LOCLISTX = 0x22
    const val FORM_RNGLISTX = 0x23
    const val FORM_REF_SUP8 = 0x24
    const val FORM_STRX1 = 0x25
    const val FORM_STRX2 = 0x26
    const val FORM_STRX3 = 0x27
    const val FORM_STRX4 = 0x28
    const val FORM_ADDRX1 = 0x29
    const val FORM_ADDR2 = 0x2a
    const val FORM_ADDRX2 = 0x2b
    const val FORM_ADDRX3 = 0x2c
    const val FORM_ADDRX4 = 0x2d
    const val FORM_ADDR8 = 0x2e
    const val FORM_GNU_STR_INDEX = 0x1f20
    const val FORM_GNU_ADDR_X = 0x1f21
    const val FORM_GNU_RANGELIST_X = 0x1f24
}

object LNE {
    const val END_SEQUENCE = 1
    const val SET_ADDRESS = 2
    const val DEFINE_FILE = 3
    const val SET_DISCRIMINATOR = 4
}

object LNS {
    const val COPY = 1
    const val ADVANCE_PC = 2
    const val ADVANCE_LINE = 3
    const val SET_FILE = 4
    const val SET_COLUMN = 5
    const val NEGATE_STMT = 6
    const val SET_BASIC_BLOCK = 7
    const val CONST_ADD_PC = 8
    const val FIXED_ADVANCE_PC = 9
    const val SET_PROLOGUE_END = 10
    const val SET_ISA = 11
}

object LCT {
    const val PATH = 0x1
    const val DIRECTORY_INDEX = 0x2
    const val TIMESTAMP = 0x3
    const val SIZE = 0x4
    const val MD5 = 0x5
}

object RLE {
    const val END_OF_LIST = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val STARTX_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val START_END = 0x06
    const val START_LENGTH = 0x07
}
