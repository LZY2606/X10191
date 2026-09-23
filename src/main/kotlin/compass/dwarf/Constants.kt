package compass.dwarf

/** Subset of DWARF tags/attributes/forms/opcodes used by the parser. */
object DW {
    // tags
    const val TAG_compile_unit = 0x11
    const val TAG_partial_unit = 0x3c
    const val TAG_skeleton_unit = 0x4a
    const val TAG_split_compile_unit = 0x41
    const val TAG_type_unit = 0x41
    const val TAG_subprogram = 0x2e
    const val TAG_inlined_subroutine = 0x2f
    const val TAG_subroutine_type = 0x35

    // attributes
    const val AT_sibling = 0x01
    const val AT_location = 0x02
    const val AT_name = 0x03
    const val AT_comp_dir = 0x1b
    const val AT_stmt_list = 0x10
    const val AT_low_pc = 0x11
    const val AT_high_pc = 0x12
    const val AT_producer = 0x25
    const val AT_ranges = 0x55
    const val AT_rnglists_base = 0x74
    const val AT_language = 0x13
    const val AT_inline = 0x20
    const val AT_call_file = 0x58
    const val AT_call_line = 0x59
    const val AT_decl_file = 0x3a
    const val AT_decl_line = 0x3b
    const at_abstract_origin = 0x31
    const val at_specification = 0x47
    const val AT_call_column = 0x57
    const val AT_linkage_name = 0x6e
    const val AT_external = 0x3f
    const val AT_GNU_dwo_name = 0x2130
    const val AT_dwo_name = 0x76
    const val AT_GNU_dwo_id = 0x2131
    const val AT_dwo_id = 0x2131
    const val AT_str_offsets_base = 0x72
    const val AT_addr_base = 0x73
    const val AT_GNU_addr_base = 0x2133
    const val AT_GNU_str_offsets_base = 0x2132

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

    // line opcodes
    const val LINE_copy = 0x01
    const val LINE_advance_pc = 0x02
    const val LINE_advance_line = 0x03
    const val LINE_set_file = 0x04
    const val LINE_set_column = 0x05
    const val LINE_negate_stmt = 0x06
    const val LINE_set_basic_block = 0x07
    const val LINE_const_add_pc = 0x08
    const val LINE_fixed_advance_pc = 0x09
    const val LINE_set_prologue_end = 0x0a
    const val LINE_set_epilogue_begin = 0x0b
    const val LINE_set_isa = 0x0c
    // v5 standard opcodes (0x0d set_file_entry, 0x0f set_address)
    const val LINE_set_file_entry = 0x0d
    const val LINE_set_epilogue_begin5 = 0x0e
    const val LINE_set_address = 0x0f

    const val LNE_end_sequence = 0x01
    const val LNE_set_address = 0x02
    const val LNE_define_file = 0x03
    const val LNE_set_discriminator = 0x04

    const val LN_path_path = 1
    const val LN_directory_index = 2
    const val LN_timestamp = 3
    const val LN_size = 4
    const val LN_MD5 = 5

    // inline
    const val INL_not_inlined = 0
    const val INL_inlined = 1
    const val INL_declared_not_inlined = 2
    const val INL_declared_inlined = 3

    const val CHILDREN_no = 0
    const val CHILDREN_yes = 1

    fun tagName(tag: Int): String = when (tag) {
        TAG_compile_unit, TAG_skeleton_unit, TAG_partial_unit -> "DW_TAG_compile_unit"
        TAG_split_compile_unit -> "DW_TAG_split_compile_unit/type_unit"
        TAG_subprogram -> "DW_TAG_subprogram"
        TAG_inlined_subroutine -> "DW_TAG_inlined_subroutine"
        else -> "DW_TAG_0x%x".format(tag)
    }

    fun languageName(l: Long): String? = when (l) {
        0x0001L -> "C89"; 0x0002L -> "C"; 0x0004L -> "C++"; 0x0003L -> "Ada83"
        0x001fL -> "C++11"; 0x002aL -> "C++14"; 0x0031L -> "C++17"
        0x000eL -> "Java"; 0x000fL -> "C99"; 0x0021L -> "Objective-C"
        0x001dL -> "Go"; 0x001cL -> "Rust"
        else -> "DW_LANG_0x%x".format(l)
    }
}

// GNU extension forms (real-world split DWARF 4, .debug_addr / .debug_str_offsets)
const val FORM_GNU_addr_index = 0x1f20
const val FORM_GNU_str_index = 0x1f21
const val FORM_GNU_rnglistx = 0x1f23
