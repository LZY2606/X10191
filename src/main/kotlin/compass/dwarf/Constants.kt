package compass.dwarf

// DWARF tags / attributes / forms — only the subset the parser understands,
// plus named constants for diagnostics. Unknown values are kept numerically.
object DW {
    // tags
    const val TAG_compile_unit = 0x11
    const val TAG_skeleton_unit = 0x4a
    const val TAG_split_compile_unit = 0x4c
    const val TAG_type_unit = 0x41
    const val TAG_subprogram = 0x2e
    const val TAG_inlined_subroutine = 0x1d
    const val TAG_lexical_block = 0x0b
    const val TAG_compile_unit_lo_user = 0x4080

    // attributes
    const val AT_sibling = 0x01
    const val AT_location = 0x02
    const val AT_name = 0x03
    const val AT_low_pc = 0x11
    const val AT_high_pc = 0x12
    const val AT_comp_dir = 0x1b
    const val AT_ranges = 0x55
    const val AT_stmt_list = 0x10
    const val AT_compilation_directory = 0x1b
    const val AT_producer = 0x25
    const val AT_language = 0x13
    const val AT_call_file = 0x58
    const val AT_call_line = 0x59
    const val AT_call_column = 0x57
    const at_abstract_origin = 0x31
    const val AT_specification = 0x47
    const val AT_abstract_origin = 0x31
    const val AT_rnglists = 0x2137
    const val AT_str_offsets_base = 0x72
    const val AT_addr_base = 0x73
    const val AT_dwo_name = 0x2130
    const val AT_dwo_id = 0x2135
    const val AT_GNU_dwo_name = 0x2130
    const val AT_GNU_dwo_id = 0x2135
    const val AT_GNU_addr_base = 0x2133
    const val AT_GNU_str_offsets_base = 0x2132
    const val AT_GNU_ranges_base = 0x2134
    const val AT_linkage_name = 0x6e
    const val AT_decl_file = 0x3a
    const val AT_decl_line = 0x3b
    const val AT_decl_column = 0x39
    const val AT_type = 0x49
    const val AT_imported_declaration = 0x81 // reused no-op
    const val AT_ranges_base = 0x74

    // forms
    const val FORM_addr = 0x01
    const val FORM_block2 = 0x03
    const val FORM_block4 = 0x04
    const val FORM_data2 = 0x05
    const val FORM_data4 = 0x06
    const val FORM_data8 = 0x07
    const val FORM_string = 0x08
    const val FORM_block = 0x09
    const val FORM_block1 = 0x0a
    const val FORM_data1 = 0x0b
    const val FORM_flag = 0x0c
    const val FORM_sdata = 0x0d
    const val FORM_strp = 0x0e
    const val FORM_udata = 0x0f
    const val FORM_ref_addr = 0x10
    const val FORM_ref1 = 0x11
    const val FORM_ref2 = 0x12
    const val FORM_ref4 = 0x13
    const val FORM_ref8 = 0x14
    const val FORM_ref_udata = 0x15
    const val FORM_indirect = 0x16
    const val FORM_sec_offset = 0x17
    const val FORM_exprloc = 0x18
    const val FORM_flag_present = 0x19
    const val FORM_strx = 0x1a
    const val FORM_addrx = 0x1b
    const val FORM_ref_sup4 = 0x1c
    const val FORM_strp_sup = 0x1d
    const val FORM_data16 = 0x1e
    const val FORM_line_strp = 0x1f
    const val FORM_ref_sig8 = 0x20
    const val FORM_implicit_const = 0x21
    const val FORM_loclistx = 0x22
    const val FORM_rnglistx = 0x23
    const val FORM_ref_sup8 = 0x24
    const val FORM_strx1 = 0x25
    const val FORM_strx2 = 0x26
    const val FORM_strx3 = 0x27
    const val FORM_strx4 = 0x28
    const val FORM_addrx1 = 0x29
    const val FORM_addrx2 = 0x2a
    const val FORM_addrx3 = 0x2b
    const val FORM_addrx4 = 0x2c
    const val FORM_GNU_addr_index = 0x1f01
    const val FORM_GNU_str_index = 0x1f02
    const val FORM_GNU_ref_alt = 0x1f20
    const val FORM_GNU_strp_alt = 0x1f21

    // children flag
    const val CHILDREN_no = 0
    const val CHILDREN_yes = 1

    // line header content types (DWARF 5)
    const val LNCT_path = 0x1
    const val LNCT_directory_index = 0x2
    const val LNCT_timestamp = 0x3
    const val LNCT_size = 0x4
    const val LNCT_MD5 = 0x5
    const val LNCT_lo_user = 0x2000
    const val LNCT_hi_user = 0x3fff

    fun tagName(tag: Int): String = when (tag) {
        TAG_compile_unit -> "DW_TAG_compile_unit"
        TAG_skeleton_unit -> "DW_TAG_skeleton_unit"
        TAG_split_compile_unit -> "DW_TAG_split_compile_unit"
        TAG_type_unit -> "DW_TAG_type_unit"
        TAG_subprogram -> "DW_TAG_subprogram"
        TAG_inlined_subroutine -> "DW_TAG_inlined_subroutine"
        TAG_lexical_block -> "DW_TAG_lexical_block"
        in TAG_compile_unit_lo_user..0xffff -> "DW_TAG_lo_user+0x${(tag - TAG_compile_unit_lo_user).toString(16)}"
        else -> "DW_TAG_0x${tag.toString(16)}"
    }

    fun formName(form: Int): String = when (form) {
        FORM_addr -> "DW_FORM_addr"; FORM_block2 -> "DW_FORM_block2"; FORM_block4 -> "DW_FORM_block4"
        FORM_data2 -> "DW_FORM_data2"; FORM_data4 -> "DW_FORM_data4"; FORM_data8 -> "DW_FORM_data8"
        FORM_string -> "DW_FORM_string"; FORM_block -> "DW_FORM_block"; FORM_block1 -> "DW_FORM_block1"
        FORM_data1 -> "DW_FORM_data1"; FORM_flag -> "DW_FORM_flag"; FORM_sdata -> "DW_FORM_sdata"
        FORM_strp -> "DW_FORM_strp"; FORM_udata -> "DW_FORM_udata"; FORM_ref_addr -> "DW_FORM_ref_addr"
        FORM_ref1 -> "DW_FORM_ref1"; FORM_ref2 -> "DW_FORM_ref2"; FORM_ref4 -> "DW_FORM_ref4"
        FORM_ref8 -> "DW_FORM_ref8"; FORM_ref_udata -> "DW_FORM_ref_udata"; FORM_indirect -> "DW_FORM_indirect"
        FORM_sec_offset -> "DW_FORM_sec_offset"; FORM_exprloc -> "DW_FORM_exprloc"; FORM_flag_present -> "DW_FORM_flag_present"
        FORM_strx -> "DW_FORM_strx"; FORM_addrx -> "DW_FORM_addrx"; FORM_ref_sup4 -> "DW_FORM_ref_sup4"
        FORM_strp_sup -> "DW_FORM_strp_sup"; FORM_data16 -> "DW_FORM_data16"; FORM_line_strp -> "DW_FORM_line_strp"
        FORM_ref_sig8 -> "DW_FORM_ref_sig8"; FORM_implicit_const -> "DW_FORM_implicit_const"
        FORM_loclistx -> "DW_FORM_loclistx"; FORM_rnglistx -> "DW_FORM_rnglistx"; FORM_ref_sup8 -> "DW_FORM_ref_sup8"
        FORM_strx1 -> "DW_FORM_strx1"; FORM_strx2 -> "DW_FORM_strx2"; FORM_strx3 -> "DW_FORM_strx3"
        FORM_strx4 -> "DW_FORM_strx4"; FORM_addrx1 -> "DW_FORM_addrx1"; FORM_addrx2 -> "DW_FORM_addrx2"
        FORM_addrx3 -> "DW_FORM_addrx3"; FORM_addrx4 -> "DW_FORM_addrx4"
        FORM_GNU_addr_index -> "DW_FORM_GNU_addr_index"; FORM_GNU_str_index -> "DW_FORM_GNU_str_index"
        FORM_GNU_ref_alt -> "DW_FORM_GNU_ref_alt"; FORM_GNU_strp_alt -> "DW_FORM_GNU_strp_alt"
        else -> "DW_FORM_0x${form.toString(16)}"
    }

    fun attrName(attr: Int): String = when (attr) {
        AT_name -> "DW_AT_name"; AT_low_pc -> "DW_AT_low_pc"; AT_high_pc -> "DW_AT_high_pc"
        AT_ranges -> "DW_AT_ranges"; AT_stmt_list -> "DW_AT_stmt_list"; AT_comp_dir -> "DW_AT_comp_dir"
        AT_producer -> "DW_AT_producer"; AT_language -> "DW_AT_language"
        AT_call_file -> "DW_AT_call_file"; AT_call_line -> "DW_AT_call_line"; AT_call_column -> "DW_AT_call_column"
        AT_abstract_origin -> "DW_AT_abstract_origin"; AT_specification -> "DW_AT_specification"
        AT_rnglists -> "DW_AT_rnglists"; AT_str_offsets_base -> "DW_AT_str_offsets_base"
        AT_addr_base -> "DW_AT_addr_base"; AT_dwo_name -> "DW_AT_dwo_name/GNU_dwo_name"
        AT_dwo_id -> "DW_AT_GNU_dwo_id"; AT_GNU_addr_base -> "DW_AT_GNU_addr_base"
        AT_GNU_str_offsets_base -> "DW_AT_GNU_str_offsets_base"; AT_GNU_ranges_base -> "DW_AT_GNU_ranges_base"
        AT_linkage_name -> "DW_AT_linkage_name"; AT_decl_file -> "DW_AT_decl_file"
        AT_decl_line -> "DW_AT_decl_line"; AT_decl_column -> "DW_AT_decl_column"
        AT_location -> "DW_AT_location"
        else -> "DW_AT_0x${attr.toString(16)}"
    }
}
