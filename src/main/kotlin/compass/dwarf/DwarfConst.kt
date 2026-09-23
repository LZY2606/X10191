package compass.dwarf

object Tag {
    const val COMPILE_UNIT = 0x11
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBPROGRAM = 0x1d
    const val PARTIAL_UNIT = 0x3c
    const val SKELETON_UNIT = 0x4a
    private val NAMES = mapOf(
        0x01 to "DW_TAG_array_type", 0x0f to "DW_TAG_pointer_type",
        0x11 to "DW_TAG_compile_unit", 0x13 to "DW_TAG_base_type",
        0x16 to "DW_TAG_typedef", 0x17 to "DW_TAG_enumeration_type",
        0x1d to "DW_TAG_inlined_subprogram", 0x24 to "DW_TAG_enumerator",
        0x2e to "DW_TAG_subprogram", 0x3c to "DW_TAG_partial_unit",
        0x4a to "DW_TAG_skeleton_unit"
    )
    fun name(tag: Int): String = NAMES[tag] ?: "DW_TAG_0x${tag.toString(16)}"
}

object At {
    const val NAME = 0x03
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val STMT_LIST = 0x10
    const val COMP_DIR = 0x1b
    const val PRODUCER = 0x25
    const val LANGUAGE = 0x13
    const val RANGES = 0x55
    const val ABSTRACT_ORIGIN = 0x31
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val CALL_COLUMN = 0x57
    const val LINKAGE_NAME = 0x6e
    const val DECL_FILE = 0x3a
    const val DECL_LINE = 0x3b
    const val DECL_COLUMN = 0x39
    const val DWO_NAME = 0x76
    const val DWO_ID = 0x75
    const val ADDR_BASE = 0x73
    const val RNGLISTS_BASE = 0x74
    const val STR_OFFSETS_BASE = 0x72
    const val COMP_DIR_STR = 0x1b
    private val NAMES = mapOf(
        0x03 to "DW_AT_name", 0x10 to "DW_AT_stmt_list", 0x11 to "DW_AT_low_pc",
        0x12 to "DW_AT_high_pc", 0x13 to "DW_AT_language", 0x1b to "DW_AT_comp_dir",
        0x25 to "DW_AT_producer", 0x31 to "DW_AT_abstract_origin",
        0x39 to "DW_AT_decl_column", 0x3a to "DW_AT_decl_file", 0x3b to "DW_AT_decl_line",
        0x55 to "DW_AT_ranges", 0x57 to "DW_AT_call_column", 0x58 to "DW_AT_call_file",
        0x59 to "DW_AT_call_line", 0x6e to "DW_AT_linkage_name",
        0x72 to "DW_AT_str_offsets_base", 0x73 to "DW_AT_addr_base",
        0x74 to "DW_AT_rnglists_base", 0x75 to "DW_AT_dwo_id", 0x76 to "DW_AT_dwo_name"
    )
    fun name(at: Int): String = NAMES[at] ?: "DW_AT_0x${at.toString(16)}"
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
    private val NAMES = mapOf(
        0x01 to "DW_FORM_addr", 0x03 to "DW_FORM_block2", 0x04 to "DW_FORM_block4",
        0x05 to "DW_FORM_data2", 0x06 to "DW_FORM_data4", 0x07 to "DW_FORM_data8",
        0x08 to "DW_FORM_string", 0x09 to "DW_FORM_block", 0x0a to "DW_FORM_block1",
        0x0b to "DW_FORM_data1", 0x0c to "DW_FORM_flag", 0x0d to "DW_FORM_sdata",
        0x0e to "DW_FORM_strp", 0x0f to "DW_FORM_udata", 0x10 to "DW_FORM_ref_addr",
        0x11 to "DW_FORM_ref1", 0x12 to "DW_FORM_ref2", 0x13 to "DW_FORM_ref4",
        0x14 to "DW_FORM_ref8", 0x15 to "DW_FORM_ref_udata", 0x16 to "DW_FORM_indirect",
        0x17 to "DW_FORM_sec_offset", 0x18 to "DW_FORM_exprloc", 0x19 to "DW_FORM_flag_present",
        0x1a to "DW_FORM_strx", 0x1b to "DW_FORM_addrx", 0x1c to "DW_FORM_ref_sup4",
        0x1d to "DW_FORM_strp_sup", 0x1e to "DW_FORM_data16", 0x1f to "DW_FORM_line_strp",
        0x20 to "DW_FORM_ref_sig8", 0x21 to "DW_FORM_implicit_const", 0x22 to "DW_FORM_loclistx",
        0x23 to "DW_FORM_rnglistx", 0x24 to "DW_FORM_ref_sup8", 0x25 to "DW_FORM_strx1",
        0x26 to "DW_FORM_strx2", 0x27 to "DW_FORM_strx3", 0x28 to "DW_FORM_strx4",
        0x29 to "DW_FORM_addrx1", 0x2a to "DW_FORM_addrx2", 0x2b to "DW_FORM_addrx3",
        0x2c to "DW_FORM_addrx4"
    )
    fun name(form: Int): String = NAMES[form] ?: "DW_FORM_0x${form.toString(16)}"
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

object Lne {
    const val END_SEQUENCE = 1
    const val SET_ADDRESS = 2
    const val DEFINE_FILE = 3
    const val SET_DISCRIMINATOR = 4
}

object Rle {
    const val END_OF_LIST = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val STARTX_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val START_END = 0x06
    const val START_LENGTH = 0x07
}

object UnitType {
    const val COMPILE = 0x01
    const val TYPE = 0x02
    const val PARTIAL = 0x03
    const val SKELETON = 0x04
    const val SPLIT_COMPILE = 0x05
    const val SPLIT_TYPE = 0x06
}
