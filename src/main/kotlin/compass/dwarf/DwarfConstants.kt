package compass.dwarf

object Tags {
    const val COMPILE_UNIT = 0x11L
    const val SUBPROGRAM = 0x2eL
    const val INLINED_SUBROUTINE = 0x1dL
    const val SUBROUTINE_TYPE = 0x15L
    const val LEXICAL_BLOCK = 0x0bL
    const val ABSTRACT_ORIGIN_CANDIDATES = true
    fun name(tag: Long): String = when (tag) {
        0x01L -> "DW_TAG_array_type"; 0x0bL -> "DW_TAG_lexical_block"; 0x11L -> "DW_TAG_compile_unit"
        0x13L -> "DW_TAG_structure_type"; 0x15L -> "DW_TAG_subroutine_type"; 0x1dL -> "DW_TAG_inlined_subroutine"
        0x24L -> "DW_TAG_base_type"; 0x27L -> "DW_TAG_pointer_type"; 0x2eL -> "DW_TAG_subprogram"
        0x2fL -> "DW_TAG_formal_parameter"; 0x34L -> "DW_TAG_variable"; 0x41L -> "DW_TAG_compile_unit"
        else -> "DW_TAG_0x${tag.toString(16)}"
    }
}

object Attrs {
    const val NAME = 0x03L; const val ORDER = 0x09L; const val BYTE_SIZE = 0x0bL; const val STMT_LIST = 0x10L
    const val LOW_PC = 0x11L; const val HIGH_PC = 0x12L; const val COMP_DIR = 0x1bL
    const val HIGH_PC_CONST = HIGH_PC; const val CALL_FILE = 0x6bL; const val CALL_LINE = 0x6cL
    const val CALL_COLUMN = 0x6dL; const val ABSTRACT_ORIGIN = 0x31L; const val SPECIFICATION = 0x47L
    const val RANGES = 0x55L; const val PRIORITY = 0x69L; const val DWO_NAME = 0x76L
    const val DWO_ID = 0x2011L; const val ADDR_BASE = 0x73L; const val STR_OFFSETS_BASE = 0x72L
    fun name(attr: Long): String = when (attr) {
        NAME -> "DW_AT_name"; ORDER -> "DW_AT_ordering"; BYTE_SIZE -> "DW_AT_byte_size"
        STMT_LIST -> "DW_AT_stmt_list"; LOW_PC -> "DW_AT_low_pc"; HIGH_PC -> "DW_AT_high_pc"
        COMP_DIR -> "DW_AT_comp_dir"; CALL_FILE -> "DW_AT_call_file"; CALL_LINE -> "DW_AT_call_line"
        CALL_COLUMN -> "DW_AT_call_column"; ABSTRACT_ORIGIN -> "DW_AT_abstract_origin"
        SPECIFICATION -> "DW_AT_specification"; RANGES -> "DW_AT_ranges"; PRIORITY -> "DW_AT_priority"
        DWO_NAME -> "DW_AT_dwo_name"; DWO_ID -> "DW_AT_GNU_dwo_id"; ADDR_BASE -> "DW_AT_addr_base"
        STR_OFFSETS_BASE -> "DW_AT_str_offsets_base"; else -> "DW_AT_0x${attr.toString(16)}"
    }
}

object Forms {
    const val ADDR = 0x01L; const val BLOCK2 = 0x03L; const val BLOCK4 = 0x04L; const val DATA2 = 0x05L
    const val DATA4 = 0x06L; const val DATA8 = 0x07L; const val STRING = 0x08L; const val BLOCK = 0x09L
    const val BLOCK1 = 0x0aL; const val DATA1 = 0x0bL; const val FLAG = 0x0cL; const val SDATA = 0x0dL
    const val STRP = 0x0eL; const val UDATA = 0x0fL; const val REF_ADDR = 0x10L; const val REF1 = 0x11L
    const val REF2 = 0x12L; const val REF4 = 0x13L; const val REF8 = 0x14L; const val REF_UDATA = 0x15L
    const val INDIRECT = 0x16L; const val SEC_OFFSET = 0x17L; const val EXPRLOC = 0x18L; const val FLAG_PRESENT = 0x19L
    const val STRX = 0x1aL; const val ADDRX = 0x1bL; const val REF_SUP4 = 0x1cL; const val STRP_SUP = 0x1dL
    const val DATA16 = 0x1eL; const val LINE_STRP = 0x1fL; const val REF_SIG8 = 0x20L; const val IMPLICIT_CONST = 0x21L
    const val LOCLISTX = 0x22L; const val RNGLISTX = 0x23L; const val REF_SUP8 = 0x24L; const val STRX1 = 0x25L
    const val STRX2 = 0x26L; const val STRX3 = 0x27L; const val STRX4 = 0x28L; const val ADDRX1 = 0x29L
    const val ADDRX2 = 0x2aL; const val ADDRX3 = 0x2bL; const val ADDRX4 = 0x2cL; 
    fun name(form: Long): String = when (form) {
        ADDR -> "DW_FORM_addr"; BLOCK2 -> "DW_FORM_block2"; BLOCK4 -> "DW_FORM_block4"; DATA2 -> "DW_FORM_data2"
        DATA4 -> "DW_FORM_data4"; DATA8 -> "DW_FORM_data8"; STRING -> "DW_FORM_string"; BLOCK -> "DW_FORM_block"
        BLOCK1 -> "DW_FORM_block1"; DATA1 -> "DW_FORM_data1"; FLAG -> "DW_FORM_flag"; SDATA -> "DW_FORM_sdata"
        STRP -> "DW_FORM_strp"; UDATA -> "DW_FORM_udata"; REF_ADDR -> "DW_FORM_ref_addr"; REF1 -> "DW_FORM_ref1"
        REF2 -> "DW_FORM_ref2"; REF4 -> "DW_FORM_ref4"; REF8 -> "DW_FORM_ref8"; REF_UDATA -> "DW_FORM_ref_udata"
        INDIRECT -> "DW_FORM_indirect"; SEC_OFFSET -> "DW_FORM_sec_offset"; EXPRLOC -> "DW_FORM_exprloc"
        FLAG_PRESENT -> "DW_FORM_flag_present"; STRX -> "DW_FORM_strx"; ADDRX -> "DW_FORM_addrx"
        REF_SUP4 -> "DW_FORM_ref_sup4"; STRP_SUP -> "DW_FORM_strp_sup"; DATA16 -> "DW_FORM_data16"
        LINE_STRP -> "DW_FORM_line_strp"; REF_SIG8 -> "DW_FORM_ref_sig8"; IMPLICIT_CONST -> "DW_FORM_implicit_const"
        LOCLISTX -> "DW_FORM_loclistx"; RNGLISTX -> "DW_FORM_rnglistx"; REF_SUP8 -> "DW_FORM_ref_sup8"
        STRX1 -> "DW_FORM_strx1"; STRX2 -> "DW_FORM_strx2"; STRX3 -> "DW_FORM_strx3"; STRX4 -> "DW_FORM_strx4"
        ADDRX1 -> "DW_FORM_addrx1"; ADDRX2 -> "DW_FORM_addrx2"; ADDRX3 -> "DW_FORM_addrx3"; ADDRX4 -> "DW_FORM_addrx4"
        else -> "DW_FORM_0x${form.toString(16)}"
    }
}

const val DW_LNS_COPY = 0L
const val DW_LNS_ADVANCE_PC = 2L
const val DW_LNS_ADVANCE_LINE = 3L
const val DW_LNS_SET_FILE = 4L
const val DW_LNS_SET_COLUMN = 5L
const val DW_LNS_NEGATE_STMT = 6L
const val DW_LNS_SET_BASIC_BLOCK = 7L
const val DW_LNS_CONST_ADD_PC = 8L
const val DW_LNS_FIXED_ADVANCE_PC = 9L
const val DW_LNS_SET_PROLOGUE_END = 10L
const val DW_LNS_SET_ISA = 11L
const val DW_LNS_0_END_SEQUENCE = 1L

const val DW_LNE_END_SEQUENCE = 1L
const val DW_LNE_SET_ADDRESS = 2L
const val DW_LNE_DEFINE_FILE = 3L
const val DW_LNE_SET_DISCRIMINATOR = 4L
const val DW_LNE_SET_SEGMENT = 0x80L
