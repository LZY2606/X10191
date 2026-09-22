package compass.dwarf

/** DWARF constants used by the parser (only those we understand). */
object DwTag {
    const val COMPILE_UNIT = 0x11
    const val SKELETON_UNIT = 0x4a // DWARF5 split: only present in .dwo (companion of skeleton)
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val COMPILATION_UNIT_DWO = 0x41 // GNU split DWARF4
}

object DwAttr {
    const val NAME = 0x03
    const val STMT_LIST = 0x10
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val COMP_DIR = 0x1b
    const val ABSTRACT_ORIGIN = 0x31
    const val SPECIFICATION = 0x47
    const val RANGES = 0x55
    const val STR_OFFSETS_BASE = 0x72
    const val ADDR_BASE = 0x73
    const val RNGLISTS_BASE = 0x74
    const val DWO_NAME = 0x76
    const val DWO_ID = 0x2013 // GNU: DW_AT_GNU_dwo_id
    const val GNU_DWO_NAME = 0x2130
    const val GNU_ADDR_BASE = 0x2133 // DW_AT_GNU_addr_base
    const val GNU_RANGES_BASE = 0x2134 // DW_AT_GNU_ranges_base
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val DECL_FILE = 0x3a
    const val DECL_LINE = 0x39
    const val INLINE = 0x20
    const val EXTERNAL = 0x3f
    const val ARTIFICIAL = 0x34
    const val PRODUCER = 0x25
    const val LANGUAGE = 0x13
    const val COMP_DIR_ALT = 0x1b
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
    const val STRP_SUP = 0x18
    const val DATA16 = 0x1e
    const val LINE_STRP = 0x1f
    const val REF_SIG8 = 0x20
    const val IMPLICIT_CONST = 0x21
    const val LOCLISTX = 0x22
    const val RNGLISTX = 0x23
    const val REF_SUP4 = 0x24
    const val STRP_ALT = 0x02
    const val STRX = 0x1a
    const val ADDRX = 0x1b
    const val REF_SUP8 = 0x25
    const val STRX1 = 0x26
    const val STRX2 = 0x27
    const val STRX3 = 0x28
    const val STRX4 = 0x29
    const val ADDRX1 = 0x2a
    const val ADDRX2 = 0x2b
    const val ADDRX3 = 0x2c
    const val ADDRX4 = 0x2d
    // GNU extensions
    const val GNU_STRP = 0x1f26
    const val GNU_ADDR_INDEX = 0x1f01
    const val GNU_STR_INDEX = 0x1f00
    const val GNU_RNGLISTX = 0x1f10
}

object DwLns {
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

object DwLne {
    const val END_SEQUENCE = 1
    const val SET_ADDRESS = 2
    const val DEFINE_FILE = 3
    const val SET_DISC = 4
}

object DwRle {
    const val END_OF_LIST = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val STARTX_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val START_END = 0x06
    const val START_LENGTH = 0x07
    const val STARTX_ENDX_SEL = 0x08
    const val STARTX_LENGTH_SEL = 0x09
    const val OFFSET_PAIR_SEL = 0x0a
}

object DwUt {
    const val COMPILE = 0x01
    const val SKELETON = 0x04
    const val SPLIT_COMPILE = 0x05
}
