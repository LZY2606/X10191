package compass.dwarf

object DW_TAG {
    const val COMPILE_UNIT = 0x11
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val LEXICAL_BLOCK = 0x0b
    const val TYPE_UNIT = 0x41
    const val PARTIAL_UNIT = 0x3e
    const val SUBPROGRAM_ID = 0x4c

    fun name(tag: Int): String = when (tag) {
        COMPILE_UNIT -> "DW_TAG_compile_unit"
        SUBPROGRAM -> "DW_TAG_subprogram"
        INLINED_SUBROUTINE -> "DW_TAG_inlined_subroutine"
        LEXICAL_BLOCK -> "DW_TAG_lexical_block"
        TYPE_UNIT -> "DW_TAG_type_unit"
        PARTIAL_UNIT -> "DW_TAG_partial_unit"
        else -> "DW_TAG_0x${tag.toString(16)}"
    }
}

object DW_AT {
    const val NAME = 0x03
    const val STMT_LIST = 0x10
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val COMP_DIR = 0x1b
    const val ABSTRACT_ORIGIN = 0x31
    const val SPECIFICATION = 0x47
    const val RANGES = 0x55
    const val DECL_FILE = 0x3a
    const val DECL_LINE = 0x3b
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val CALL_COLUMN = 0x57
    const val INLINE = 0x20
    const val EXTERNAL = 0x3f
    const val DECLARATION = 0x3c
    const val LINKAGE_NAME = 0x6e
    const val LANGUAGE = 0x13
    const val DWARF_VERSION = 0x209e
    const val GNU_DWO_NAME = 0x2130
    const val GNU_DWO_ID = 0x2131
    const val DWO_NAME = 0x76
    const val DWO_ID = 0x2097
    const val STR_OFFSETS_BASE = 0x72
    const val GNU_DWO_ID_OLD = 0x2131
    const val RANGES_BASE = 0x74
    const val ADDR_BASE = 0x73
    const val LOCATION = 0x02
    const val STR_OFF_SETS_BASE = 0x72
    const val RNGLISTS_BASE = 0x74
    const val ADDR_BASE = 0x73
    const val FRAME_BASE = 0x40
}

object DW_FORM {
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
    const val STRX1 = 0x25
    const val STRX2 = 0x26
    const val ADDRX1 = 0x24
    const val RNGLIST = 0x27

    // GNU 扩展
    const val GNU_ADDR_INDEX = 0x1f01
    const val GNU_STR_INDEX = 0x1f00
    const val GNU_REF_ALT = 0x1f20
}

object DW_UT {
    const val COMPILE = 0x01
    const val TYPE = 0x02
    const val PARTIAL = 0x03
    const val SKELETON = 0x04
    const val SPLIT_COMPILE = 0x05
    const val SPLIT_TYPE = 0x06
    fun name(t: Int): String = when (t) {
        COMPILE -> "DW_UT_compile"; TYPE -> "DW_UT_type"; PARTIAL -> "DW_UT_partial"
        SKELETON -> "DW_UT_skeleton"; SPLIT_COMPILE -> "DW_UT_split_compile"
        SPLIT_TYPE -> "DW_UT_split_type"; else -> "DW_UT_0x${t.toString(16)}"
    }
}

object DW_LNS {
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
}

object DW_LNE {
    const val END_SEQUENCE = 0x01
    const val SET_ADDRESS = 0x02
    const val DEFINE_FILE = 0x03
    const val SET_DISCRIMINATOR = 0x04
}

object DW_RLE {
    // DWARF <=4
    const val V4_END = 0x00
    const val V4_BASE_ADDRESS = 0x01
    const val V4_BASE_ADDRESSX = 0x02
    const val V4_STARTX_ENDX = 0x03
    const val V4_STARTX_LENGTH = 0x04
    // DWARF 5
    const val END_OF_LIST = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val STARTX_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val START_END = 0x06
    const val START_LENGTH = 0x07
}

private val AT_NAMES = mapOf(
    DW_AT.NAME to "DW_AT_name",
    DW_AT.STMT_LIST to "DW_AT_stmt_list",
    DW_AT.LOW_PC to "DW_AT_low_pc",
    DW_AT.HIGH_PC to "DW_AT_high_pc",
    DW_AT.COMP_DIR to "DW_AT_comp_dir",
    DW_AT.ABSTRACT_ORIGIN to "DW_AT_abstract_origin",
    DW_AT.SPECIFICATION to "DW_AT_specification",
    DW_AT.RANGES to "DW_AT_ranges",
    DW_AT.DECL_FILE to "DW_AT_decl_file",
    DW_AT.DECL_LINE to "DW_AT_decl_line",
    DW_AT.CALL_FILE to "DW_AT_call_file",
    DW_AT.CALL_LINE to "DW_AT_call_line",
    DW_AT.CALL_COLUMN to "DW_AT_call_column",
    DW_AT.INLINE to "DW_AT_inline",
    DW_AT.EXTERNAL to "DW_AT_external",
    DW_AT.DECLARATION to "DW_AT_declaration",
    DW_AT.LINKAGE_NAME to "DW_AT_linkage_name",
    DW_AT.LANGUAGE to "DW_AT_language",
    DW_AT.GNU_DWO_NAME to "DW_AT_GNU_dwo_name",
    DW_AT.GNU_DWO_ID to "DW_AT_GNU_dwo_id",
    DW_AT.DWO_NAME to "DW_AT_dwo_name",
    DW_AT.DWO_ID to "DW_AT_dwo_id",
    DW_AT.STR_OFF_SETS_BASE to "DW_AT_str_offsets_base",
    DW_AT.RNGLISTS_BASE to "DW_AT_rnglists_base",
    DW_AT.ADDR_BASE to "DW_AT_addr_base",
    DW_AT.LOCATION to "DW_AT_location"
)

private val FORM_NAMES = mapOf(
    DW_FORM.ADDR to "DW_FORM_addr",
    DW_FORM.DATA1 to "DW_FORM_data1",
    DW_FORM.DATA2 to "DW_FORM_data2",
    DW_FORM.DATA4 to "DW_FORM_data4",
    DW_FORM.DATA8 to "DW_FORM_data8",
    DW_FORM.UDATA to "DW_FORM_udata",
    DW_FORM.SDATA to "DW_FORM_sdata",
    DW_FORM.FLAG to "DW_FORM_flag",
    DW_FORM.FLAG_PRESENT to "DW_FORM_flag_present",
    DW_FORM.STRING to "DW_FORM_string",
    DW_FORM.STRP to "DW_FORM_strp",
    DW_FORM.LINE_STRP to "DW_FORM_line_strp",
    DW_FORM.REF_ADDR to "DW_FORM_ref_addr",
    DW_FORM.REF1 to "DW_FORM_ref1",
    DW_FORM.REF2 to "DW_FORM_ref2",
    DW_FORM.REF4 to "DW_FORM_ref4",
    DW_FORM.REF8 to "DW_FORM_ref8",
    DW_FORM.REF_UDATA to "DW_FORM_ref_udata",
    DW_FORM.SEC_OFFSET to "DW_FORM_sec_offset",
    DW_FORM.STRX to "DW_FORM_strx",
    DW_FORM.STRX1 to "DW_FORM_strx1",
    DW_FORM.STRX2 to "DW_FORM_strx2",
    DW_FORM.ADDRX to "DW_FORM_addrx",
    DW_FORM.ADDRX1 to "DW_FORM_addrx1",
    DW_FORM.RNGLISTX to "DW_FORM_rnglistx",
    DW_FORM.RNGLIST to "DW_FORM_rnglist",
    DW_FORM.BLOCK to "DW_FORM_block",
    DW_FORM.BLOCK1 to "DW_FORM_block1",
    DW_FORM.BLOCK2 to "DW_FORM_block2",
    DW_FORM.BLOCK4 to "DW_FORM_block4",
    DW_FORM.EXPRLOC to "DW_FORM_exprloc",
    DW_FORM.REF_SIG8 to "DW_FORM_ref_sig8",
    DW_FORM.IMPLICIT_CONST to "DW_FORM_implicit_const",
    DW_FORM.DATA16 to "DW_FORM_data16",
    DW_FORM.GNU_ADDR_INDEX to "DW_FORM_GNU_addr_index",
    DW_FORM.GNU_STR_INDEX to "DW_FORM_GNU_str_index",
    DW_FORM.GNU_REF_ALT to "DW_FORM_GNU_ref_alt",
    DW_FORM.INDIRECT to "DW_FORM_indirect"
)

fun dwAtName(a: Int): String = AT_NAMES[a] ?: "DW_AT_0x${a.toString(16)}"
fun dwFormName(f: Int): String = FORM_NAMES[f] ?: "DW_FORM_0x${f.toString(16)}"
