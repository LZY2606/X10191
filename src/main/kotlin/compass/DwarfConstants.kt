package compass

object DwarfConstants {
    const val DW_TAG_compile_unit = 0x11
    const val DW_TAG_skeleton_unit = 0x4a
    const val DW_TAG_partial_unit = 0x3c
    const val DW_TAG_type_unit = 0x41
    const val DW_TAG_subprogram = 0x2e
    const val DW_TAG_inlined_subroutine = 0x1d

    const val DW_AT_sibling = 0x01
    const val DW_AT_name = 0x03
    const val DW_AT_stmt_list = 0x10
    const val DW_AT_low_pc = 0x11
    const val DW_AT_high_pc = 0x12
    const val DW_AT_comp_dir = 0x1b
    const val DW_AT_ranges = 0x55
    const val DW_AT_call_file = 0x58
    const val DW_AT_call_line = 0x59
    const val DW_AT_linkage_name = 0x6e
    const val DW_AT_abstract_origin = 0x31
    const val DW_AT_specification = 0x47
    const val DW_AT_inline = 0x20
    const val DW_AT_GNU_dwo_name = 0x2130
    const val DW_AT_dwo_name = 0x76
    const val DW_AT_GNU_dwo_id = 0x2131
    const val DW_AT_dwo_id = 0x77
    const val DW_AT_rnglists_base = 0x73
    const val DW_AT_str_offsets_base = 0x72

    const val DW_FORM_addr = 0x01
    const val DW_FORM_block2 = 0x03
    const val DW_FORM_block4 = 0x04
    const val DW_FORM_data2 = 0x05
    const val DW_FORM_data4 = 0x06
    const val DW_FORM_data8 = 0x07
    const val DW_FORM_string = 0x08
    const val DW_FORM_block = 0x09
    const val DW_FORM_block1 = 0x0a
    const val DW_FORM_data1 = 0x0b
    const val DW_FORM_flag = 0x0c
    const val DW_FORM_sdata = 0x0d
    const val DW_FORM_strp = 0x0e
    const val DW_FORM_udata = 0x0f
    const val DW_FORM_ref_addr = 0x10
    const val DW_FORM_ref1 = 0x11
    const val DW_FORM_ref2 = 0x12
    const val DW_FORM_ref4 = 0x13
    const val DW_FORM_ref8 = 0x14
    const val DW_FORM_ref_udata = 0x15
    const val DW_FORM_indirect = 0x16
    const val DW_FORM_sec_offset = 0x17
    const val DW_FORM_exprloc = 0x18
    const val DW_FORM_flag_present = 0x19
    const val DW_FORM_strx = 0x1a
    const val DW_FORM_addrx = 0x1b
    const val DW_FORM_ref_sup4 = 0x1c
    const val DW_FORM_strp_sup = 0x1d
    const val DW_FORM_data16 = 0x1e
    const val DW_FORM_line_strp = 0x1f
    const val DW_FORM_ref_sig8 = 0x20
    const val DW_FORM_implicit_const = 0x21
    const val DW_FORM_loclistx = 0x22
    const val DW_FORM_rnglistx = 0x23
    const val DW_FORM_ref_sup8 = 0x24
    const val DW_FORM_strx1 = 0x25
    const val DW_FORM_strx2 = 0x26
    const val DW_FORM_strx3 = 0x27
    const val DW_FORM_strx4 = 0x28
    const val DW_FORM_addrx1 = 0x29
    const val DW_FORM_addrx2 = 0x2a
    const val DW_FORM_addrx3 = 0x2b
    const val DW_FORM_addrx4 = 0x2c

    const val DW_LNS_copy = 1
    const val DW_LNS_advance_pc = 2
    const val DW_LNS_advance_line = 3
    const val DW_LNS_set_file = 4
    const val DW_LNS_set_column = 5
    const val DW_LNS_negate_stmt = 6
    const val DW_LNS_set_basic_block = 7
    const val DW_LNS_const_add_pc = 8
    const val DW_LNS_fixed_advance_pc = 9
    const val DW_LNS_set_prologue_end = 10
    const val DW_LNS_set_epilogue_begin = 11
    const val DW_LNS_set_isa = 12

    const val DW_LNE_end_sequence = 1
    const val DW_LNE_set_address = 2
    const val DW_LNE_define_file = 3
    const val DW_LNE_set_discriminator = 4

    const val DW_LNCT_path = 1
    const val DW_LNCT_directory_index = 2
    const val DW_LNCT_timestamp = 3
    const val DW_LNCT_size = 4
    const val DW_LNCT_MD5 = 5

    fun tagName(tag: Int): String = when (tag) {
        DW_TAG_compile_unit -> "DW_TAG_compile_unit"
        DW_TAG_skeleton_unit -> "DW_TAG_skeleton_unit"
        DW_TAG_partial_unit -> "DW_TAG_partial_unit"
        DW_TAG_type_unit -> "DW_TAG_type_unit"
        DW_TAG_subprogram -> "DW_TAG_subprogram"
        DW_TAG_inlined_subroutine -> "DW_TAG_inlined_subroutine"
        else -> "DW_TAG_0x${tag.toString(16)}"
    }

    fun attrName(attr: Int): String = when (attr) {
        DW_AT_sibling -> "DW_AT_sibling"
        DW_AT_name -> "DW_AT_name"
        DW_AT_stmt_list -> "DW_AT_stmt_list"
        DW_AT_low_pc -> "DW_AT_low_pc"
        DW_AT_high_pc -> "DW_AT_high_pc"
        DW_AT_comp_dir -> "DW_AT_comp_dir"
        DW_AT_ranges -> "DW_AT_ranges"
        DW_AT_call_file -> "DW_AT_call_file"
        DW_AT_call_line -> "DW_AT_call_line"
        DW_AT_linkage_name, 0x6f -> "DW_AT_linkage_name"
        DW_AT_abstract_origin -> "DW_AT_abstract_origin"
        DW_AT_specification -> "DW_AT_specification"
        DW_AT_inline -> "DW_AT_inline"
        DW_AT_GNU_dwo_name, DW_AT_dwo_name -> "DW_AT_dwo_name"
        DW_AT_GNU_dwo_id, DW_AT_dwo_id -> "DW_AT_dwo_id"
        DW_AT_rnglists_base -> "DW_AT_rnglists_base"
        DW_AT_str_offsets_base -> "DW_AT_str_offsets_base"
        else -> "DW_AT_0x${attr.toString(16)}"
    }

    fun formName(form: Int): String = "DW_FORM_0x${form.toString(16)}"
}
