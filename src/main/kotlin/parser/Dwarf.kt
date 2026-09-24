package parser

object DW {
    const val TAG_COMPILE_UNIT = 0x11
    const val TAG_SUBPROGRAM = 0x2e
    const val TAG_INLINED_SUBROUTINE = 0x1d
    const val TAG_SKELETON_UNIT = 0x41
    const val TAG_SPLIT_COMPILE_UNIT = 0x4a
    const val TAG_SUBPROGRAM_F = 0x2e

    const val AT_SPECIFICATION = 0x47
    const val AT_ABSTRACT_ORIGIN = 0x31
    const val AT_NAME = 0x03
    const val AT_LINKAGE_NAME = 0x6e
    const val AT_HIGH_PC = 0x12
    const val AT_LOW_PC = 0x11
    const val AT_RANGES = 0x55
    const val AT_STMT_LIST = 0x10
    const val AT_COMP_DIR = 0x1b
    const val AT_PRODUCER = 0x25
    const val AT_LANGUAGE = 0x13
    const val AT_GNU_DWO_NAME = 0x2130
    const val AT_DWO_NAME = 0x76
    const val AT_CALL_FILE = 0x58
    const val AT_CALL_LINE = 0x59
    const val AT_CALL_COLUMN = 0x57
    const val AT_DECL_FILE = 0x3a
    const val AT_DECL_LINE = 0x3b
    const val AT_DECL_COLUMN = 0x39
    const val AT_EXTERNAL = 0x3f
    const val AT_ARTIFICIAL = 0x34

    // line numbering header content types (DWARF5)
    const val CT_PATH = 1
    const val CT_DIRECTORY_INDEX = 2
    const val CT_TIMESTAMP = 3
    const val CT_SIZE = 4
    const val CT_MD5 = 5

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
    const val FORM_STRX = 0x1a
    const val FORM_ADDRX = 0x1b
    const val FORM_REF_SUP4 = 0x1c
    const val FORM_STRP_SUP = 0x1d
    const val FORM_DATA16 = 0x1e
    const val FORM_LINE_STRP = 0x1f
    const val FORM_REF_SIG8 = 0x20
    const val FORM_IMPLICIT_CONST = 0x21
    const val FORM_LOC_LISTX = 0x22
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
    const val FORM_RNGLISTX1 = 0x2d

    // extended opcodes
    const val EXT_END_SEQUENCE = 1
    const val EXT_SET_ADDRESS = 2
    const val EXT_DEFINE_FILE = 3
    const val EXT_SET_DISCRIMINATOR = 4

    // standard opcodes
    const val OP_COPY = 1
    const val OP_ADVANCE_PC = 2
    const val OP_ADVANCE_LINE = 3
    const val OP_SET_FILE = 4
    const val OP_SET_COLUMN = 5
    const val OP_NEGATE_STMT = 6
    const val OP_SET_BASIC_BLOCK = 7
    const val OP_CONST_ADD_PC = 8
    const val OP_FIXED_ADVANCE_PC = 9
    const val OP_SET_PROLOGUE_END = 10
    const val OP_SET_EPILOGUE_BEGIN = 11
    const val OP_SET_ISA = 12
}

object LANG {
    fun name(code: Long): String? = when (code) {
        0x001cL -> "C89"
        0x0001L -> "C89"
        0x001dL -> "C"
        0x0004L -> "C++03"
        0x0021L -> "C++11"
        0x002aL -> "C++14"
        0x0030L -> "C++17"
        0x001aL -> "C99"
        0x0002L -> "C"
        else -> null
    }
}
