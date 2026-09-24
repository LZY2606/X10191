package compass.dwarf

/** DWARF 常量表（标签、属性、表单、行程序操作码、范围列表编码）。 */
object Dw {
    // ---- TAG ----
    const val TAG_compile_unit = 0x11
    const val TAG_subprogram = 0x2e
    const val TAG_inlined_subroutine = 0x1d
    const val TAG_lexical_block = 0x0b

    val TAG_NAMES = mapOf(
        0x00 to "DW_TAG_null", 0x01 to "DW_TAG_array_type", 0x02 to "DW_TAG_class_type",
        0x03 to "DW_TAG_entry_point", 0x04 to "DW_TAG_enumeration_type", 0x05 to "DW_TAG_formal_parameter",
        0x08 to "DW_TAG_imported_declaration", 0x0a to "DW_TAG_label", 0x0b to "DW_TAG_lexical_block",
        0x0d to "DW_TAG_member", 0x0f to "DW_TAG_pointer_type", 0x10 to "DW_TAG_reference_type",
        0x11 to "DW_TAG_compile_unit", 0x12 to "DW_TAG_string_type", 0x13 to "DW_TAG_structure_type",
        0x15 to "DW_TAG_subroutine_type", 0x16 to "DW_TAG_typedef", 0x17 to "DW_TAG_union_type",
        0x18 to "DW_TAG_unspecified_parameters", 0x19 to "DW_TAG_variant", 0x1a to "DW_TAG_common_block",
        0x1b to "DW_TAG_common_inclusion", 0x1c to "DW_TAG_inheritance", 0x1d to "DW_TAG_inlined_subroutine",
        0x1e to "DW_TAG_module", 0x1f to "DW_TAG_ptr_to_member_type", 0x20 to "DW_TAG_set_type",
        0x21 to "DW_TAG_subrange_type", 0x22 to "DW_TAG_with_stmt", 0x23 to "DW_TAG_access_declaration",
        0x24 to "DW_TAG_base_type", 0x25 to "DW_TAG_catch_block", 0x26 to "DW_TAG_const_type",
        0x27 to "DW_TAG_constant", 0x28 to "DW_TAG_enumerator", 0x29 to "DW_TAG_file_type",
        0x2a to "DW_TAG_friend", 0x2b to "DW_TAG_namelist", 0x2c to "DW_TAG_namelist_item",
        0x2d to "DW_TAG_packed_type", 0x2e to "DW_TAG_subprogram", 0x2f to "DW_TAG_template_type_parameter",
        0x30 to "DW_TAG_template_value_parameter", 0x31 to "DW_TAG_thrown_type", 0x32 to "DW_TAG_try_block",
        0x33 to "DW_TAG_variant_part", 0x34 to "DW_TAG_variable", 0x35 to "DW_TAG_volatile_type",
        0x36 to "DW_TAG_dwarf_procedure", 0x37 to "DW_TAG_restrict_type", 0x38 to "DW_TAG_interface_type",
        0x39 to "DW_TAG_namespace", 0x3a to "DW_TAG_imported_module", 0x3b to "DW_TAG_unspecified_type",
        0x3c to "DW_TAG_partial_unit", 0x3d to "DW_TAG_imported_unit", 0x3f to "DW_TAG_condition",
        0x40 to "DW_TAG_shared_type", 0x41 to "DW_TAG_type_unit", 0x42 to "DW_TAG_rvalue_reference_type",
        0x43 to "DW_TAG_template_alias", 0x44 to "DW_TAG_coarray_type", 0x45 to "DW_TAG_generic_subrange",
        0x46 to "DW_TAG_dynamic_type", 0x47 to "DW_TAG_atomic_type", 0x48 to "DW_TAG_call_site",
        0x49 to "DW_TAG_call_site_parameter", 0x4a to "DW_TAG_skeleton_unit", 0x4b to "DW_TAG_immutable_type",
    )

    fun tagName(tag: Int): String = TAG_NAMES[tag] ?: "DW_TAG_0x${tag.toString(16)}"

    // ---- AT ----
    const val AT_sibling = 0x01
    const val AT_name = 0x03
    const val AT_stmt_list = 0x10
    const val AT_low_pc = 0x11
    const val AT_high_pc = 0x12
    const val AT_comp_dir = 0x1b
    const val AT_producer = 0x25
    const val AT_abstract_origin = 0x31
    const val AT_decl_file = 0x3a
    const val AT_decl_line = 0x3b
    const val AT_specification = 0x47
    const val AT_ranges = 0x55
    const val AT_call_column = 0x57
    const val AT_call_file = 0x58
    const val AT_call_line = 0x59
    const val AT_linkage_name = 0x6e
    const val AT_str_offsets_base = 0x72
    const val AT_addr_base = 0x73
    const val AT_rnglists_base = 0x74
    const val AT_dwo_id = 0x75
    const val AT_dwo_name = 0x76

    val AT_NAMES = mapOf(
        0x01 to "DW_AT_sibling", 0x03 to "DW_AT_name", 0x10 to "DW_AT_stmt_list",
        0x11 to "DW_AT_low_pc", 0x12 to "DW_AT_high_pc", 0x1b to "DW_AT_comp_dir",
        0x25 to "DW_AT_producer", 0x31 to "DW_AT_abstract_origin", 0x3a to "DW_AT_decl_file",
        0x3b to "DW_AT_decl_line", 0x47 to "DW_AT_specification", 0x55 to "DW_AT_ranges",
        0x57 to "DW_AT_call_column", 0x58 to "DW_AT_call_file", 0x59 to "DW_AT_call_line",
        0x6e to "DW_AT_linkage_name", 0x72 to "DW_AT_str_offsets_base", 0x73 to "DW_AT_addr_base",
        0x74 to "DW_AT_rnglists_base", 0x75 to "DW_AT_dwo_id", 0x76 to "DW_AT_dwo_name",
    )

    fun atName(at: Int): String = AT_NAMES[at] ?: "DW_AT_0x${at.toString(16)}"

    // ---- FORM ----
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

    val FORM_NAMES = mapOf(
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
        0x2c to "DW_FORM_addrx4",
    )

    fun formName(form: Int): String = FORM_NAMES[form] ?: "DW_FORM_0x${form.toString(16)}"

    // ---- 行程序标准操作码 ----
    const val LNS_copy = 1
    const val LNS_advance_pc = 2
    const val LNS_advance_line = 3
    const val LNS_set_file = 4
    const val LNS_set_column = 5
    const val LNS_negate_stmt = 6
    const val LNS_set_basic_block = 7
    const val LNS_const_add_pc = 8
    const val LNS_fixed_advance_pc = 9
    const val LNS_set_prologue_end = 10
    const val LNS_set_epilogue_begin = 11
    const val LNS_set_isa = 12

    // ---- 行程序扩展操作码 ----
    const val LNE_end_sequence = 1
    const val LNE_set_address = 2
    const val LNE_define_file = 3
    const val LNE_set_discriminator = 4

    // ---- 范围列表（DWARF5 .debug_rnglists）----
    const val RLE_end_of_list = 0x00
    const val RLE_base_addressx = 0x01
    const val RLE_startx_end = 0x02
    const val RLE_startx_length = 0x03
    const val RLE_offset_pair = 0x04
    const val RLE_base_address = 0x05
    const val RLE_start_end = 0x06
    const val RLE_start_length = 0x07

    // ---- 单元类型（DWARF5）----
    const val UT_compile = 0x01
    const val UT_type = 0x02
    const val UT_partial = 0x03
    const val UT_skeleton = 0x04
    const val UT_split_compile = 0x05
    const val UT_split_type = 0x06

    // ---- 行程序 v5 目录/文件内容类型 ----
    const val LNCT_path = 0x1
    const val LNCT_directory_index = 0x2
    const val LNCT_timestamp = 0x3
    const val LNCT_size = 0x4
    const val LNCT_MD5 = 0x5
}
