package compass.dwarf

object Tag {
    const val COMPILE_UNIT = 0x11
    const val SUBPROGRAM = 0x2E
    const val INLINED_SUBROUTINE = 0x1D
    const val LEXICAL_BLOCK = 0x0B
    const val PARTIAL_UNIT = 0x3C
    const val SKELETON_UNIT = 0x4A
    const val TYPE_UNIT = 0x41
    const val COMPILE_UNIT_5 = 0x11
}

object Attr {
    const val SIBLING = 0x01
    const val LOCATION = 0x02
    const val NAME = 0x03
    const val COMP_DIR = 0x1B
    const val STMT_LIST = 0x10
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val RANGES = 0x55
    const val ABSTRACT_ORIGIN = 0x31
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val CALL_COLUMN = 0x56
    const val COMPILATION_DIRECTORY = 0x1B
    const val DW_AT_GNU_dwo_name = 0x2130
    const val DW_AT_dwo_name = 0x76
    const val DW_AT_GNU_dwo_id = 0x2131
    const val DW_AT_GNU_addr_base = 0x2133
    const val DW_AT_addr_base = 0x57
    const val DW_AT_str_offsets_base = 0x72
    const val DW_AT_rnglists_base = 0x74
    const val DW_AT_loclists_base = 0x8C
    const val DW_AT_GNU_ranges_base = 0x2132
    const val DW_AT_dwo_id5 = 0x71

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
    const val BLOCK1 = 0x0A
    const val DATA1 = 0x0B
    const val FLAG = 0x0C
    const val SDATA = 0x0D
    const val STRP = 0x0E
    const val UDATA = 0x0F
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
    const val STRX = 0x1A
    const val ADDRX = 0x1B
    const val REF_SUP4 = 0x1C
    const val STRP_SUP = 0x1D
    const val DATA16 = 0x1E
    const val LINE_STRP = 0x1F
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
    const val ADDRX2 = 0x2A
    const val ADDRX3 = 0x2B
    const val ADDRX4 = 0x2C
    const val GNUE_ADDR_INDEX = 0x1F01
    const val GNUE_STR_INDEX = 0x1F02
    const val GNUE_RANGES_INDEX = 0x1F03
}

object LineContentType {
    const val PATH = 1
    const val DIRECTORY_INDEX = 2
    const val TIMESTAMP = 3
    const val SIZE = 4
    const val MD5 = 5
}
