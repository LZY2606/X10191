package compass.dwarf

object DwTag {
    const val NULL = 0x00
    const val COMPILE_UNIT = 0x11
    const val SKELETON_UNIT = 0x4a
    const val SPLIT_COMPILE_UNIT = 0x4b
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val LEXICAL_BLOCK = 0x0b
}

object DwAt {
    const val SIBLING = 0x01
    const val NAME = 0x03
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val COMP_DIR = 0x1b
    const val STMT_LIST = 0x10
    const val ABSTRACT_ORIGIN = 0x31
    const val SPECIFICATION = 0x47
    const val CALL_COLUMN = 0x57
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val RANGES = 0x55
    const val RANGLISTS_BASE = 0x62
    const val DWO_NAME = 0x76
    const val STR_OFFSETS_BASE = 0x72
    const val ADDR_BASE = 0x73
    const val DWO_ID = 0x2013
    const val GNU_DWO_ID = 0x2130
}

object DwForm {
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
}

object DwLns {
    const val COPY = 0x01
    const val ADVANCE_PC = 0x02
    const val ADVANCE_LINE = 0x03
    const val SET_FILE = 0x04
    const val SET_COLUMN = 0x05
    const val NEGATE_STMT = 0x06
    const val SET_BASIC_BLOCK = 0x07
    const val CONST_ADD_PC = 0x08
    const val FIXED_ADVANCE_PC = 0x09
    const val SET_PROLOGUE_END = 0x0a
    const val SET_ISA = 0x0b

    const val END_SEQUENCE = 0x01
    const val SET_ADDRESS = 0x02
    const val DEFINE_FILE = 0x03
    const val SET_DISCRIMINATOR = 0x04
}

object DwRle {
    const val DWARF4_BASE_ADDRESSX = 0xff
    const val DWARF4_BASE_ADDRESS = 0xfffffffeL

    const val END_OF_LIST = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val START_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val STARTX_LENGTH = 0x06
}

object DwUt {
    const val COMPILE = 0x01
    const val TYPE = 0x02
    const val PARTIAL = 0x03
    const val SKELETON = 0x04
    const val SPLIT_COMPILE = 0x05
    const val SPLIT_TYPE = 0x06
}
