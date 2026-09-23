package compass.dwarf

/** DWARF 常量（只列出解析器实际使用的部分）。 */
object Tag {
    const val COMPILE_UNIT = 0x11
    const val SKELETON_UNIT = 0x11
    const val SPLIT_COMPILE_UNIT = 0x1c
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val LEXICAL_BLOCK = 0x0b
    const val COMPILE_UNIT_DWO = 0x4101
}

object Attr {
    const val SIBLING = 0x01
    const val NAME = 0x03
    const val LANGUAGE = 0x13
    const val STMT_LIST = 0x10
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val COMP_DIR = 0x1b
    const val RANGES = 0x55
    const val ABSTRACT_ORIGIN = 0x31
    const val SPECIFICATION = 0x47
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val DW_AT_GNU_call_col = 0x2112
    const val INLINE = 0x20
    const val EXTERNAL = 0x3f
    const val DECL_FILE = 0x3a
    const val DECL_LINE = 0x3b
    const val DW_AT_GNU_dwo_name = 0x2130
    const val DW_AT_dwo_name = 0x76
    const val DW_AT_GNU_dwo_id = 0x2131
    const val DWO_ID = 0x77
    const val STR_OFFSETS_BASE = 0x72
    const val DW_AT_GNU_str_offsets_base = 0x2132
    const val ADDR_BASE = 0x73
    const val DW_AT_GNU_addr_base = 0x2133
    const val RANGES_BASE = 0x74
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
    const val GNU_ADDR_INDEX = 0x1f01
    const val GNU_STR_INDEX = 0x1f00
    const val GNU_RANGELIST_X = 0x2134
}

object LineOp {
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

    const val EXT_END_SEQUENCE = 1
    const val EXT_SET_ADDRESS = 2
    const val EXT_DEFINE_FILE = 3
    const val EXT_SET_DISCRIMINATOR = 4
    const val EXT_SET_FILE = 0
}

object Rng {
    // DWARF 5 .debug_rnglists 条目
    const val END = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val STARTX_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val START_END = 0x06
    const val START_LENGTH = 0x07
}

object Rng4 {
    // DWARF 4 .debug_ranges: base address 项的选择子是最大地址宽度的值
}

object LineContentType {
    const val PATH = 1
    const val DIRECTORY_INDEX = 2
    const val TIMESTAMP = 3
    const val SIZE = 4
    const val MD5 = 5
}

object UnitType5 {
    const val COMPILE = 0x01
    const val TYPE = 0x02
    const val PARTIAL = 0x03
    const val SKELETON = 0x04
    const val SPLIT_COMPILE = 0x05
    const val SPLIT_TYPE = 0x06
}
