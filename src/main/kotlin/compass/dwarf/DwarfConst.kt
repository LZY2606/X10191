package compass.dwarf

object Tag {
    const val COMPILE_UNIT = 0x11
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val LEXICAL_BLOCK = 0x0b
    const val NAMESPACE = 0x39
    const val MODULE = 0x1e
    const val LABEL = 0x0a
    const val TRY_BLOCK = 0x32
    const val CATCH_BLOCK = 0x33
    fun name(code: Int): String = when (code) {
        0x11 -> "DW_TAG_compile_unit"
        0x2e -> "DW_TAG_subprogram"
        0x1d -> "DW_TAG_inlined_subroutine"
        0x0b -> "DW_TAG_lexical_block"
        0x0a -> "DW_TAG_label"
        0x39 -> "DW_TAG_namespace"
        0x1e -> "DW_TAG_module"
        0x32 -> "DW_TAG_try_block"
        0x33 -> "DW_TAG_catch_block"
        0x13 -> "DW_TAG_structure_type"
        0x15 -> "DW_TAG_pointer_type"
        0x24 -> "DW_TAG_base_type"
        0x01 -> "DW_TAG_array_type"
        0x34 -> "DW_TAG_variable"
        0x05 -> "DW_TAG_formal_parameter"
        0x41 -> "DW_TAG_enumeration_type"
        0x17 -> "DW_TAG_union_type"
        0x16 -> "DW_TAG_typedef"
        else -> "DW_TAG_0x${code.toString(16)}"
    }
}

object Attr {
    const val SIBLING = 0x01
    const val LOCATION = 0x02
    const val NAME = 0x03
    const val ORDERING = 0x09
    const val BYTE_SIZE = 0x0b
    const val STMT_LIST = 0x10
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val LANGUAGE = 0x13
    const val DISCR = 0x15
    const val COMP_DIR = 0x1b
    const val CONST_VALUE = 0x1c
    const val CONTAINING_TYPE = 0x1d
    const val INLINE = 0x20
    const val PRODUCER = 0x25
    const val PROTOTYPED = 0x27
    const val UPPER_BOUND = 0x2f
    const val ABSTRACT_ORIGIN = 0x31
    const val CONCRETE_ORIGIN = 0x33
    const val ACCESSIBILITY = 0x32
    const val DECLARATION = 0x3c
    const val ENCODING = 0x3e
    const val EXTERNAL = 0x3f
    const val DECL_FILE = 0x3a
    const val DECL_LINE = 0x3b
    const val SPECIFICATION = 0x47
    const val CALL_COLUMN = 0x57
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val LINKAGE_NAME = 0x6e
    const val ENTRY_PC = 0x52
    const val RANGES = 0x55
    const val STR_OFFSETS_BASE = 0x72
    const val ADDR_BASE = 0x73
    const val RNGLISTS_BASE = 0x74
    const val DWO_NAME = 0x76
    const val DWO_ID = 0x75
    const val MACRO_INFO = 0x43
    const val USE_UTF8 = 0x53
    const val MIPS_LINKAGE_NAME = 0x2007
    fun name(code: Int): String = when (code) {
        SIBLING -> "DW_AT_sibling"
        LOCATION -> "DW_AT_location"
        NAME -> "DW_AT_name"
        STMT_LIST -> "DW_AT_stmt_list"
        LOW_PC -> "DW_AT_low_pc"
        HIGH_PC -> "DW_AT_high_pc"
        LANGUAGE -> "DW_AT_language"
        COMP_DIR -> "DW_AT_comp_dir"
        INLINE -> "DW_AT_inline"
        PRODUCER -> "DW_AT_producer"
        ABSTRACT_ORIGIN -> "DW_AT_abstract_origin"
        SPECIFICATION -> "DW_AT_specification"
        DECL_FILE -> "DW_AT_decl_file"
        DECL_LINE -> "DW_AT_decl_line"
        CALL_FILE -> "DW_AT_call_file"
        CALL_LINE -> "DW_AT_call_line"
        CALL_COLUMN -> "DW_AT_call_column"
        LINKAGE_NAME -> "DW_AT_linkage_name"
        ENTRY_PC -> "DW_AT_entry_pc"
        RANGES -> "DW_AT_ranges"
        STR_OFFSETS_BASE -> "DW_AT_str_offsets_base"
        ADDR_BASE -> "DW_AT_addr_base"
        RNGLISTS_BASE -> "DW_AT_rnglists_base"
        DWO_NAME -> "DW_AT_dwo_name"
        DWO_ID -> "DW_AT_dwo_id"
        MACRO_INFO -> "DW_AT_macro_info"
        else -> "DW_AT_0x${code.toString(16)}"
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
    val KNOWN: Set<Int> = setOf(
        ADDR, BLOCK2, BLOCK4, DATA2, DATA4, DATA8, STRING, BLOCK, BLOCK1, DATA1, FLAG,
        SDATA, STRP, UDATA, REF_ADDR, REF1, REF2, REF4, REF8, REF_UDATA, INDIRECT,
        SEC_OFFSET, EXPRLOC, FLAG_PRESENT, STRX, ADDRX, REF_SUP4, STRP_SUP, DATA16,
        LINE_STRP, REF_SIG8, IMPLICIT_CONST, LOCLISTX, RNGLISTX, REF_SUP8,
        STRX1, STRX2, STRX3, STRX4, ADDRX1, ADDRX2, ADDRX3, ADDRX4
    )
    fun name(code: Int): String = when (code) {
        ADDR -> "DW_FORM_addr"; BLOCK2 -> "DW_FORM_block2"; BLOCK4 -> "DW_FORM_block4"
        DATA2 -> "DW_FORM_data2"; DATA4 -> "DW_FORM_data4"; DATA8 -> "DW_FORM_data8"
        STRING -> "DW_FORM_string"; BLOCK -> "DW_FORM_block"; BLOCK1 -> "DW_FORM_block1"
        DATA1 -> "DW_FORM_data1"; FLAG -> "DW_FORM_flag"; SDATA -> "DW_FORM_sdata"
        STRP -> "DW_FORM_strp"; UDATA -> "DW_FORM_udata"; REF_ADDR -> "DW_FORM_ref_addr"
        REF1 -> "DW_FORM_ref1"; REF2 -> "DW_FORM_ref2"; REF4 -> "DW_FORM_ref4"
        REF8 -> "DW_FORM_ref8"; REF_UDATA -> "DW_FORM_ref_udata"; INDIRECT -> "DW_FORM_indirect"
        SEC_OFFSET -> "DW_FORM_sec_offset"; EXPRLOC -> "DW_FORM_exprloc"
        FLAG_PRESENT -> "DW_FORM_flag_present"; STRX -> "DW_FORM_strx"; ADDRX -> "DW_FORM_addrx"
        REF_SUP4 -> "DW_FORM_ref_sup4"; STRP_SUP -> "DW_FORM_strp_sup"; DATA16 -> "DW_FORM_data16"
        LINE_STRP -> "DW_FORM_line_strp"; REF_SIG8 -> "DW_FORM_ref_sig8"
        IMPLICIT_CONST -> "DW_FORM_implicit_const"; LOCLISTX -> "DW_FORM_loclistx"
        RNGLISTX -> "DW_FORM_rnglistx"; REF_SUP8 -> "DW_FORM_ref_sup8"
        STRX1 -> "DW_FORM_strx1"; STRX2 -> "DW_FORM_strx2"; STRX3 -> "DW_FORM_strx3"
        STRX4 -> "DW_FORM_strx4"; ADDRX1 -> "DW_FORM_addrx1"; ADDRX2 -> "DW_FORM_addrx2"
        ADDRX3 -> "DW_FORM_addrx3"; ADDRX4 -> "DW_FORM_addrx4"
        else -> "DW_FORM_0x${code.toString(16)}"
    }
}

object LineOp {
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
    fun name(code: Int): String = when (code) {
        COPY -> "DW_LNS_copy"; ADVANCE_PC -> "DW_LNS_advance_pc"; ADVANCE_LINE -> "DW_LNS_advance_line"
        SET_FILE -> "DW_LNS_set_file"; SET_COLUMN -> "DW_LNS_set_column"
        NEGATE_STMT -> "DW_LNS_negate_stmt"; SET_BASIC_BLOCK -> "DW_LNS_set_basic_block"
        CONST_ADD_PC -> "DW_LNS_const_add_pc"; FIXED_ADVANCE_PC -> "DW_LNS_fixed_advance_pc"
        SET_PROLOGUE_END -> "DW_LNS_set_prologue_end"; SET_EPILOGUE_BEGIN -> "DW_LNS_set_epilogue_begin"
        SET_ISA -> "DW_LNS_set_isa"
        else -> "DW_LNS_0x${code.toString(16)}"
    }
}

object LineExt {
    const val END_SEQUENCE = 1
    const val SET_ADDRESS = 2
    const val DEFINE_FILE = 3
    const val SET_DISCRIMINATOR = 4
    fun name(code: Int): String = when (code) {
        END_SEQUENCE -> "DW_LNE_end_sequence"; SET_ADDRESS -> "DW_LNE_set_address"
        DEFINE_FILE -> "DW_LNE_define_file"; SET_DISCRIMINATOR -> "DW_LNE_set_discriminator"
        else -> "DW_LNE_0x${code.toString(16)}"
    }
}

object RngList {
    const val END_OF_LIST = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val STARTX_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val START_END = 0x06
    const val START_LENGTH = 0x07
    fun name(code: Int): String = when (code) {
        END_OF_LIST -> "DW_RLE_end_of_list"; BASE_ADDRESSX -> "DW_RLE_base_addressx"
        STARTX_ENDX -> "DW_RLE_startx_endx"; STARTX_LENGTH -> "DW_RLE_startx_length"
        OFFSET_PAIR -> "DW_RLE_offset_pair"; BASE_ADDRESS -> "DW_RLE_base_address"
        START_END -> "DW_RLE_start_end"; START_LENGTH -> "DW_RLE_start_length"
        else -> "DW_RLE_0x${code.toString(16)}"
    }
}

object LineContent {
    const val PATH = 0x1
    const val DIRECTORY_INDEX = 0x2
    const val TIMESTAMP = 0x3
    const val SIZE = 0x4
    const val MD5 = 0x5
}
