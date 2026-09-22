package compass

/** DWARF constants used by the parser. Only the subset we interpret is listed. */
object Dw {
    // DW_TAG_*
    const val TAG_COMPILE_UNIT = 0x11L
    const val TAG_PARTIAL_UNIT = 0x13L
    const val TAG_TYPE_UNIT = 0x41L
    const val TAG_SUBPROGRAM = 0x2eL
    const val TAG_INLINED_SUBROUTINE = 0x1dL
    const val TAG_LEXICAL_BLOCK = 0x0bL
    const val TAG_SKELETON_UNIT = 0x4aL

    // DW_AT_*
    const val AT_SIBLING = 0x01L
    const val AT_LOCATION = 0x02L
    const val AT_NAME = 0x03L
    const val AT_STMT_LIST = 0x10L
    const val AT_LOW_PC = 0x11L
    const val AT_HIGH_PC = 0x12L
    const val AT_LANGUAGE = 0x13L
    const val AT_COMP_DIR = 0x1bL
    const val AT_CONST_VALUE = 0x1cL
    const val AT_ABSTRACT_ORIGIN = 0x31L
    const val AT_LINKAGE_NAME = 0x6eL
    const val AT_MIPS_LINKAGE_NAME = 0x2007L
    const val AT_SPECIFICATION = 0x47L
    const val AT_CALL_FILE = 0x58L
    const val AT_CALL_LINE = 0x59L
    const val AT_CALL_COLUMN = 0x5aL
    const val AT_DECL_FILE = 0x3aL
    const val AT_DECL_LINE = 0x3bL
    const val AT_DECL_COLUMN = 0x39L
    const val AT_PRODUCER = 0x25L
    const val AT_RANGES = 0x55L
    const val AT_INLINE = 0x20L
    const val AT_ADDR_BASE = 0x2133L
    const val AT_RNGLISTS_BASE = 0x2134L
    const val AT_STR_OFFSETS_BASE = 0x2135L
    const val AT_LINE_BASE = 0x2136L
    const val AT_DWO_NAME = 0x2130L
    const val AT_DWO_ID = 0x2131L
    const val AT_GNU_DWO_NAME = 0x2130L
    const val AT_GNU_DWO_ID = 0x2131L
    const val AT_GNU_ADDR_BASE = 0x2133L
    const val AT_GNU_RANGES_BASE = 0x2132L
    const val AT_GNU_PUBNAMES = 0x2134L
    const val AT_GNU_PUBTYPES = 0x2135L
    const val AT_GNU_STR_OFFSETS_BASE = 0x2137L

    // DW_FORM_*
    const val FORM_ADDR = 0x01L
    const val FORM_BLOCK2 = 0x03L
    const val FORM_BLOCK4 = 0x04L
    const val FORM_DATA2 = 0x05L
    const val FORM_DATA4 = 0x06L
    const val FORM_DATA8 = 0x07L
    const val FORM_STRING = 0x08L
    const val FORM_BLOCK = 0x09L
    const val FORM_BLOCK1 = 0x0aL
    const val FORM_DATA1 = 0x0bL
    const val FORM_FLAG = 0x0cL
    const val FORM_SDATA = 0x0dL
    const val FORM_STRP = 0x0eL
    const val FORM_UDATA = 0x0fL
    const val FORM_REF_ADDR = 0x10L
    const val FORM_REF1 = 0x11L
    const val FORM_REF2 = 0x12L
    const val FORM_REF4 = 0x13L
    const val FORM_REF8 = 0x14L
    const val FORM_REF_UDATA = 0x15L
    const val FORM_INDIRECT = 0x16L
    const val FORM_SEC_OFFSET = 0x17L
    const val FORM_EXPRLOC = 0x18L
    const val FORM_FLAG_PRESENT = 0x19L
    const val FORM_STRX = 0x1aL
    const val FORM_ADDRX = 0x1bL
    const val FORM_REF_SUP4 = 0x1cL
    const val FORM_STRP_SUP = 0x1dL
    const val FORM_DATA16 = 0x1eL
    const val FORM_LINE_STRP = 0x1fL
    const val FORM_REF_SIG8 = 0x20L
    const val FORM_IMPLICIT_CONST = 0x21L
    const val FORM_LOCLISTX = 0x22L
    const val FORM_RNGLISTX = 0x23L
    const val FORM_REF_SUP8 = 0x24L
    const val FORM_STRX1 = 0x25L
    const val FORM_STRX2 = 0x26L
    const val FORM_STRX3 = 0x27L
    const val FORM_STRX4 = 0x28L
    const val FORM_ADDRX1 = 0x29L
    const val FORM_ADDRX2 = 0x2aL
    const val FORM_ADDRX3 = 0x2bL
    const val FORM_ADDRX4 = 0x2cL
    const val FORM_GNU_ADDR_INDEX = 0x1f01L
    const val FORM_GNU_STR_INDEX = 0x1f02L
    const val FORM_GNU_REF_ALT = 0x1f20L
    const val FORM_GNU_STRP_ALT = 0x1f21L

    // DW_UT_*
    const val UT_COMPILE = 0x01
    const val UT_TYPE = 0x02
    const val UT_PARTIAL = 0x03
    const val UT_SKELETON = 0x04
    const val UT_SPLIT_COMPILE = 0x05
    const val UT_SPLIT_TYPE = 0x06

    // DW_RLE_*
    const val RLE_END_OF_LIST = 0x00
    const val RLE_BASE_ADDRESSX = 0x01
    const val RLE_STARTX_ENDX = 0x02
    const val RLE_STARTX_LENGTH = 0x03
    const val RLE_OFFSET_PAIR = 0x04
    const val RLE_BASE_ADDRESS = 0x05
    const val RLE_START_END = 0x06
    const val RLE_START_LENGTH = 0x07

    // DW_LNE_*
    const val LNE_END_SEQUENCE = 0x01
    const val LNE_SET_ADDRESS = 0x02
    const val LNE_DEFINE_FILE = 0x03
    const val LNE_SET_DISCRIMINATOR = 0x04
    const val LNE_LO_HI = 0x00

    // DW_LNS_*
    const val LNS_COPY = 1
    const val LNS_ADVANCE_PC = 2
    const val LNS_ADVANCE_LINE = 3
    const val LNS_SET_FILE = 4
    const val LNS_SET_COLUMN = 5
    const val LNS_NEGATE_STMT = 6
    const val LNS_SET_BASIC_BLOCK = 7
    const val LNS_CONST_ADD_PC = 8
    const val LNS_FIXED_ADVANCE_PC = 9
    const val LNS_SET_PROLOGUE_END = 10
    const val LNS_SET_EPILOGUE_BEGIN = 11
    const val LNS_SET_ISA = 12

    // DW_LNCT_*
    const val LNCT_PATH = 0x1
    const val LNCT_DIRECTORY_INDEX = 0x2
    const val LNCT_TIMESTAMP = 0x3
    const val LNCT_SIZE = 0x4
    const val LNCT_MD5 = 0x5

    // DW_INL_*
    const val INL_NOT_INLINED = 0x0L
    const val INL_INLINED = 0x1L
    const val INL_DECLARED_NOT_INLINED = 0x2L
    const val INL_DECLARED_INLINED = 0x3L

    fun tagName(tag: Long): String = when (tag) {
        TAG_COMPILE_UNIT -> "DW_TAG_compile_unit"
        TAG_PARTIAL_UNIT -> "DW_TAG_partial_unit"
        TAG_TYPE_UNIT -> "DW_TAG_type_unit"
        TAG_SUBPROGRAM -> "DW_TAG_subprogram"
        TAG_INLINED_SUBROUTINE -> "DW_TAG_inlined_subroutine"
        TAG_LEXICAL_BLOCK -> "DW_TAG_lexical_block"
        TAG_SKELETON_UNIT -> "DW_TAG_skeleton_unit"
        else -> "DW_TAG_0x${tag.toString(16)}"
    }

    fun formName(form: Long): String = when (form) {
        FORM_ADDR -> "DW_FORM_addr"
        FORM_BLOCK2 -> "DW_FORM_block2"
        FORM_BLOCK4 -> "DW_FORM_block4"
        FORM_DATA2 -> "DW_FORM_data2"
        FORM_DATA4 -> "DW_FORM_data4"
        FORM_DATA8 -> "DW_FORM_data8"
        FORM_STRING -> "DW_FORM_string"
        FORM_BLOCK -> "DW_FORM_block"
        FORM_BLOCK1 -> "DW_FORM_block1"
        FORM_DATA1 -> "DW_FORM_data1"
        FORM_FLAG -> "DW_FORM_flag"
        FORM_SDATA -> "DW_FORM_sdata"
        FORM_STRP -> "DW_FORM_strp"
        FORM_UDATA -> "DW_FORM_udata"
        FORM_REF_ADDR -> "DW_FORM_ref_addr"
        FORM_REF1 -> "DW_FORM_ref1"
        FORM_REF2 -> "DW_FORM_ref2"
        FORM_REF4 -> "DW_FORM_ref4"
        FORM_REF8 -> "DW_FORM_ref8"
        FORM_REF_UDATA -> "DW_FORM_ref_udata"
        FORM_INDIRECT -> "DW_FORM_indirect"
        FORM_SEC_OFFSET -> "DW_FORM_sec_offset"
        FORM_EXPRLOC -> "DW_FORM_exprloc"
        FORM_FLAG_PRESENT -> "DW_FORM_flag_present"
        FORM_STRX -> "DW_FORM_strx"
        FORM_ADDRX -> "DW_FORM_addrx"
        FORM_REF_SUP4 -> "DW_FORM_ref_sup4"
        FORM_STRP_SUP -> "DW_FORM_strp_sup"
        FORM_DATA16 -> "DW_FORM_data16"
        FORM_LINE_STRP -> "DW_FORM_line_strp"
        FORM_REF_SIG8 -> "DW_FORM_ref_sig8"
        FORM_IMPLICIT_CONST -> "DW_FORM_implicit_const"
        FORM_LOCLISTX -> "DW_FORM_loclistx"
        FORM_RNGLISTX -> "DW_FORM_rnglistx"
        FORM_REF_SUP8 -> "DW_FORM_ref_sup8"
        FORM_STRX1 -> "DW_FORM_strx1"
        FORM_STRX2 -> "DW_FORM_strx2"
        FORM_STRX3 -> "DW_FORM_strx3"
        FORM_STRX4 -> "DW_FORM_strx4"
        FORM_ADDRX1 -> "DW_FORM_addrx1"
        FORM_ADDRX2 -> "DW_FORM_addrx2"
        FORM_ADDRX3 -> "DW_FORM_addrx3"
        FORM_ADDRX4 -> "DW_FORM_addrx4"
        FORM_GNU_ADDR_INDEX -> "DW_FORM_GNU_addr_index"
        FORM_GNU_STR_INDEX -> "DW_FORM_GNU_str_index"
        FORM_GNU_REF_ALT -> "DW_FORM_GNU_ref_alt"
        FORM_GNU_STRP_ALT -> "DW_FORM_GNU_strp_alt"
        else -> "DW_FORM_0x${form.toString(16)}"
    }
}

/** Hard safety limits for parsing hostile/corrupt input. */
object Limits {
    const val MAX_SECTION_SIZE = 256L * 1024 * 1024
    const val MAX_UNIT_LENGTH = 256L * 1024 * 1024
    const val MAX_DIE_DEPTH = 256
    const val MAX_DIES_PER_CU = 1_000_000
    const val MAX_ABBREV_ATTRS = 10_000
    const val MAX_ABBREV_ENTRIES = 100_000
    const val MAX_INDIRECT_HOPS = 16
    const val MAX_REF_HOPS = 32
    const val MAX_RANGES = 1_000_000
    const val MAX_LINE_ROWS = 4_000_000
    const val MAX_LINE_FILES = 1_000_000
    const val MAX_ADDR_TABLE = 1_000_000
    const val MAX_STR_OFFSETS = 1_000_000
    const val MAX_BATCH_ADDRESSES = 4096
    const val MAX_UPLOAD_BYTES = 512L * 1024 * 1024
    const val MAX_LINE_PROGRAMS_PER_CU = 64
}
