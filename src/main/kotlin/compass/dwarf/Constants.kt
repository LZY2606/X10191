package compass.dwarf

object Tag {
    const val COMPILE_UNIT = 0x11
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val SKELETON_UNIT = 0x4a
    fun name(t: Int) = when (t) {
        COMPILE_UNIT -> "DW_TAG_compile_unit"
        SUBPROGRAM -> "DW_TAG_subprogram"
        INLINED_SUBROUTINE -> "DW_TAG_inlined_subroutine"
        SKELETON_UNIT -> "DW_TAG_skeleton_unit"
        else -> "DW_TAG_0x${t.toString(16)}"
    }
}

object Attr {
    const val NAME = 0x03
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val STMT_LIST = 0x10
    const val COMP_DIR = 0x1b
    const val RANGES = 0x55
    const val ABSTRACT_ORIGIN = 0x31
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val LINKAGE_NAME = 0x6e
    const val DWO_NAME = 0x76 // DW_AT_GNU_dwo_name
    const val DWO_ID = 0x75   // DW_AT_GNU_dwo_id
    const val ADDR_BASE = 0x73 // DW_AT_addr_base (v5)
    const val STR_OFFSETS_BASE = 0x72
    const val RNGLISTS_BASE = 0x74
    fun name(a: Int) = when (a) {
        NAME -> "DW_AT_name"; LOW_PC -> "DW_AT_low_pc"; HIGH_PC -> "DW_AT_high_pc"
        STMT_LIST -> "DW_AT_stmt_list"; COMP_DIR -> "DW_AT_comp_dir"; RANGES -> "DW_AT_ranges"
        ABSTRACT_ORIGIN -> "DW_AT_abstract_origin"; CALL_FILE -> "DW_AT_call_file"
        CALL_LINE -> "DW_AT_call_line"; LINKAGE_NAME -> "DW_AT_linkage_name"
        DWO_NAME -> "DW_AT_GNU_dwo_name"; DWO_ID -> "DW_AT_GNU_dwo_id"
        ADDR_BASE -> "DW_AT_addr_base"; STR_OFFSETS_BASE -> "DW_AT_str_offsets_base"
        RNGLISTS_BASE -> "DW_AT_rnglists_base"
        else -> "DW_AT_0x${a.toString(16)}"
    }
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
    const val EXPLOC = 0x18
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
    const val GNU_STRP_ALT = 0x1f21
    fun name(f: Int) = "DW_FORM_0x${f.toString(16)}"
}

object UnitType {
    const val COMPILE = 1
    const val SKELETON = 5
    fun name(t: Int) = when (t) {
        COMPILE -> "DW_UT_compile"; 2 -> "DW_UT_type"; 3 -> "DW_UT_partial"
        4 -> "DW_UT_split_compile"; SKELETON -> "DW_UT_skeleton"
        6 -> "DW_UT_split_type"; 7 -> "DW_UT_split_partial"
        else -> "DW_UT_0x${t.toString(16)}"
    }
}

object Rle {
    const val END_OF_LIST = 0
    const val BASE_ADDRESSX = 1
    const val STARTX_ENDX = 2
    const val STARTX_LENGTH = 3
    const val OFFSET_PAIR = 4
    const val BASE_ADDRESS = 5
    const val START_END = 6
    const val START_LENGTH = 7
}

object Lne {
    const val END_SEQUENCE = 1
    const val SET_ADDRESS = 2
    const val DEFINE_FILE = 3
    const val SET_DISCRIMINATOR = 4
}

object Lns {
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
    const val SET_EPILOGUE_BEGIN = 11
    const val SET_ISA = 12
}

object Lnct {
    const val PATH = 1
    const val DIRECTORY_INDEX = 2
    const val TIMESTAMP = 3
    const val SIZE = 4
    const val MD5 = 5
}
