package compass.dwarf

object Tag {
    const val NULL = 0x00
    const val COMPILE_UNIT = 0x11
    const val SKELETON_UNIT = 0x11
    const val TYPE_UNIT = 0x41
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val LEXICAL_BLOCK = 0x0b
    const val ABSTRACT_ORIGIN_MARKER = -1
    fun name(tag: Int): String = when (tag) {
        0x11 -> "DW_TAG_compile_unit"
        0x41 -> "DW_TAG_type_unit"
        0x2e -> "DW_TAG_subprogram"
        0x1d -> "DW_TAG_inlined_subroutine"
        0x0b -> "DW_TAG_lexical_block"
        else -> "DW_TAG_0x${tag.toString(16)}"
    }
}

object Attr {
    const val SIBLING = 0x01
    const val LOCATION = 0x02
    const val NAME = 0x03
    const val COMP_DIR = 0x1b
    const val STMT_LIST = 0x10
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val RANGES = 0x55
    const val ABSTRACT_ORIGIN = 0x31
    const val SPECIFICATION = 0x47
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val CALL_COLUMN = 0x57
    const val COMPILATION_DIRECTORY = 0x1b
    const val PRODUCER = 0x25
    const val LANGUAGE = 0x13
    const val RANGELIST_BASE = 0x74
    const val STR_OFFSETS_BASE = 0x72
    const val ADDR_BASE = 0x73
    const val DWO_NAME = 0x76
    const val GNU_DWO_NAME = 0x2130
    const val DWO_ID = 0x2134
    const val GNU_DWO_ID = 0x2135
    const val LINKAGE_NAME = 0x6e
    const val LINE_PROGRAM_HEADER = 0x2000

    fun name(a: Int): String = when (a) {
        0x03 -> "DW_AT_name"
        0x10 -> "DW_AT_stmt_list"
        0x11 -> "DW_AT_low_pc"
        0x12 -> "DW_AT_high_pc"
        0x55 -> "DW_AT_ranges"
        0x31 -> "DW_AT_abstract_origin"
        0x47 -> "DW_AT_specification"
        0x58 -> "DW_AT_call_file"
        0x59 -> "DW_AT_call_line"
        0x57 -> "DW_AT_call_column"
        0x1b -> "DW_AT_comp_dir"
        0x25 -> "DW_AT_producer"
        0x76 -> "DW_AT_dwo_name"
        0x2130 -> "DW_AT_GNU_dwo_name"
        0x2134 -> "DW_AT_dwo_id"
        0x2135 -> "DW_AT_GNU_dwo_id"
        0x74 -> "DW_AT_rnglists_base"
        0x72 -> "DW_AT_str_offsets_base"
        0x73 -> "DW_AT_addr_base"
        0x6e -> "DW_AT_linkage_name"
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
    const val UNKNOWN = -1

    fun name(f: Int): String = when (f) {
        ADDR -> "DW_FORM_addr"; DATA1 -> "DW_FORM_data1"; DATA2 -> "DW_FORM_data2"
        DATA4 -> "DW_FORM_data4"; DATA8 -> "DW_FORM_data8"; SDATA -> "DW_FORM_sdata"
        UDATA -> "DW_FORM_udata"; STRING -> "DW_FORM_string"; STRP -> "DW_FORM_strp"
        LINE_STRP -> "DW_FORM_line_strp"; SEC_OFFSET -> "DW_FORM_sec_offset"; EXPRLOC -> "DW_FORM_exprloc"
        REF_ADDR -> "DW_FORM_ref_addr"; REF1 -> "DW_FORM_ref1"; REF2 -> "DW_FORM_ref2"
        REF4 -> "DW_FORM_ref4"; REF8 -> "DW_FORM_ref8"; REF_UDATA -> "DW_FORM_ref_udata"
        REF_SIG8 -> "DW_FORM_ref_sig8"; FLAG -> "DW_FORM_flag"; FLAG_PRESENT -> "DW_FORM_flag_present"
        STRX -> "DW_FORM_strx"; STRX1 -> "DW_FORM_strx1"; STRX2 -> "DW_FORM_strx2"
        STRX3 -> "DW_FORM_strx3"; STRX4 -> "DW_FORM_strx4"
        ADDRX -> "DW_FORM_addrx"; ADDRX1 -> "DW_FORM_addrx1"; ADDRX2 -> "DW_FORM_addrx2"
        ADDRX3 -> "DW_FORM_addrx3"; ADDRX4 -> "DW_FORM_addrx4"; RNGLISTX -> "DW_FORM_rnglistx"
        INDIRECT -> "DW_FORM_indirect"; IMPLICIT_CONST -> "DW_FORM_implicit_const"
        else -> "DW_FORM_0x${f.toString(16)}"
    }
}

object Rng {
    const val END_OF_LIST = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val STARTX_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val START_END = 0x06
    const val START_LENGTH = 0x07
}

object LineContent {
    const val PATH = 0x1
    const val DIRECTORY_INDEX = 0x2
    const val TIMESTAMP = 0x3
    const val SIZE = 0x4
    const val MD5 = 0x5
}

object LineStdOp {
    const val COPY = 0x01
    const val ADVANCE_PC = 0x02
    const val ADVANCE_LINE = 0x03
    const val SET_FILE = 0x04
    const val SET_COLUMN = 0x05
    const val NEGATE_STMT = 0x06
    const val SET_BASIC_BLOCK_V4 = 0x07
    const val CONST_ADD_PC_V4 = 0x08
    const val FIXED_ADVANCE_PC_V4 = 0x09
    const val SET_PROLOGUE_END_V4 = 0x0a
    const val SET_EPILOGUE_BEGIN_V4 = 0x0b
    const val SET_ISA_V4 = 0x0c
    const val SET_BASIC_BLOCK_V5 = 0x08
    const val CONST_ADD_PC_V5 = 0x09
    const val FIXED_ADVANCE_PC_V5 = 0x0a
    const val SET_PROLOGUE_END_V5 = 0x0b
    const val SET_EPILOGUE_BEGIN_V5 = 0x0c
    const val SET_ISA_V5 = 0x0d
}

object LineExtOp {
    const val END_SEQUENCE = 0x01
    const val SET_ADDRESS = 0x02
    const val DEFINE_FILE = 0x03
    const val SET_DISCRIMINATOR = 0x04
    const val SET_IS_STMT_V5 = 0x05
}
