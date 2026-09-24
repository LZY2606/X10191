package compass.dwarf

object Dw {
    // TAGs (subset)
    const val TAG_compile_unit = 0x11
    const val TAG_subprogram = 0x2e
    const val TAG_inlined_subroutine = 0x1d
    const val TAG_lexical_block = 0x0b

    val TAG_NAMES = mapOf(
        0x01 to "array_type", 0x02 to "class_type", 0x03 to "entry_point",
        0x04 to "enumeration_type", 0x05 to "formal_parameter", 0x08 to "imported_declaration",
        0x0a to "label", 0x0b to "lexical_block", 0x0d to "member", 0x0f to "pointer_type",
        0x10 to "reference_type", 0x11 to "compile_unit", 0x12 to "string_type",
        0x13 to "structure_type", 0x15 to "subroutine_type", 0x16 to "typedef",
        0x17 to "union_type", 0x18 to "unspecified_parameters", 0x19 to "variant",
        0x1a to "common_block", 0x1b to "common_inclusion", 0x1c to "inheritance",
        0x1d to "inlined_subroutine", 0x1e to "module", 0x1f to "ptr_to_member_type",
        0x20 to "set_type", 0x21 to "subrange_type", 0x22 to "with_stmt",
        0x23 to "access_declaration", 0x24 to "base_type", 0x25 to "catch_block",
        0x26 to "const_type", 0x27 to "constant", 0x28 to "enumerator", 0x29 to "file_type",
        0x2a to "friend", 0x2b to "namelist", 0x2c to "namelist_item",
        0x2d to "packed_type", 0x2e to "subprogram", 0x2f to "template_type_parameter",
        0x30 to "template_value_parameter", 0x31 to "thrown_type", 0x32 to "try_block",
        0x33 to "variant_part", 0x34 to "variable", 0x35 to "volatile_type",
        0x36 to "dwarf_procedure", 0x37 to "restrict_type", 0x38 to "interface_type",
        0x39 to "namespace", 0x3a to "imported_module", 0x3b to "unspecified_type",
        0x3c to "partial_unit", 0x3d to "imported_unit", 0x3f to "condition",
        0x40 to "shared_type", 0x41 to "type_unit", 0x42 to "rvalue_reference_type",
        0x43 to "template_alias", 0x44 to "coarray_type", 0x45 to "generic_subrange",
        0x46 to "dynamic_type", 0x47 to "atomic_type", 0x48 to "call_site",
        0x49 to "call_site_parameter", 0x4a to "skeleton_unit", 0x4b to "immutable_type"
    )

    // ATtributes (subset)
    const val AT_sibling = 0x01
    const val AT_name = 0x03
    const val AT_stmt_list = 0x10
    const val AT_low_pc = 0x11
    const val AT_high_pc = 0x12
    const val AT_comp_dir = 0x1b
    const val AT_abstract_origin = 0x31
    const val AT_decl_file = 0x3a
    const val AT_decl_line = 0x3b
    const val AT_decl_column = 0x39
    const val AT_ranges = 0x55
    const val AT_call_column = 0x57
    const val AT_call_file = 0x58
    const val AT_call_line = 0x59
    const val AT_str_offsets_base = 0x72
    const val AT_addr_base = 0x73
    const val AT_rnglists_base = 0x74
    const val AT_dwo_name = 0x75
    const val AT_linkage_name = 0x6e

    val AT_NAMES = mapOf(
        0x01 to "sibling", 0x02 to "location", 0x03 to "name", 0x09 to "ordering",
        0x0b to "byte_size", 0x0c to "bit_offset", 0x0d to "bit_size", 0x10 to "stmt_list",
        0x11 to "low_pc", 0x12 to "high_pc", 0x13 to "language", 0x15 to "discr",
        0x16 to "discr_value", 0x17 to "visibility", 0x18 to "import", 0x19 to "string_length",
        0x1a to "common_reference", 0x1b to "comp_dir", 0x1c to "const_value",
        0x1d to "containing_type", 0x1e to "default_value", 0x20 to "inline",
        0x21 to "is_optional", 0x22 to "lower_bound", 0x25 to "producer", 0x27 to "prototyped",
        0x2a to "return_addr", 0x2c to "start_scope", 0x2e to "bit_stride", 0x2f to "upper_bound",
        0x31 to "abstract_origin", 0x32 to "accessibility", 0x33 to "address_class",
        0x34 to "artificial", 0x35 to "base_types", 0x36 to "calling_convention",
        0x37 to "count", 0x38 to "data_member_location", 0x39 to "decl_column",
        0x3a to "decl_file", 0x3b to "decl_line", 0x3c to "declaration", 0x3d to "discr_list",
        0x3e to "encoding", 0x3f to "external", 0x40 to "explicit", 0x41 to "friend",
        0x42 to "identifier_case", 0x43 to "macro_info", 0x44 to "namelist_item",
        0x45 to "priority", 0x46 to "segment", 0x47 to "specification", 0x48 to "static_link",
        0x49 to "type", 0x4a to "use_location", 0x4b to "variable_parameter",
        0x4c to "virtuality", 0x4d to "vtable_elem_location", 0x4e to "allocated",
        0x4f to "associated", 0x50 to "data_location", 0x51 to "byte_stride",
        0x52 to "entry_pc", 0x53 to "use_UTF8", 0x54 to "extension", 0x55 to "ranges",
        0x56 to "trampoline", 0x57 to "call_column", 0x58 to "call_file", 0x59 to "call_line",
        0x5a to "description", 0x5b to "binary_scale", 0x5c to "decimal_scale", 0x5d to "small",
        0x5e to "decimal_sign", 0x5f to "digit_count", 0x60 to "picture_string",
        0x61 to "mutable", 0x62 to "threads_scaled", 0x63 to "explicit", 0x64 to "object_pointer",
        0x65 to "endianity", 0x66 to "elemental", 0x67 to "pure", 0x68 to "recursive",
        0x69 to "signature", 0x6a to "main_subprogram", 0x6b to "data_bit_offset",
        0x6c to "const_expr", 0x6d to "enum_class", 0x6e to "linkage_name",
        0x6f to "string_length_bit_size", 0x70 to "string_length_byte_size", 0x71 to "rank",
        0x72 to "str_offsets_base", 0x73 to "addr_base", 0x74 to "rnglists_base",
        0x75 to "dwo_name", 0x76 to "reference", 0x77 to "rvalue_reference", 0x78 to "macros",
        0x79 to "call_all_calls", 0x7a to "call_all_source_calls", 0x7b to "call_all_tail_calls",
        0x7c to "call_return_pc", 0x7d to "call_value", 0x7e to "call_origin",
        0x7f to "call_parameter", 0x80 to "call_pc", 0x81 to "call_tail_call",
        0x82 to "call_target", 0x83 to "call_target_clobbered", 0x84 to "call_data_location",
        0x85 to "call_data_value", 0x86 to "noreturn", 0x87 to "alignment",
        0x88 to "export_symbols", 0x89 to "deleted", 0x8a to "defaulted", 0x8b to "loclists_base"
    )

    // FORM constants
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
        0x01 to "addr", 0x03 to "block2", 0x04 to "block4", 0x05 to "data2", 0x06 to "data4",
        0x07 to "data8", 0x08 to "string", 0x09 to "block", 0x0a to "block1", 0x0b to "data1",
        0x0c to "flag", 0x0d to "sdata", 0x0e to "strp", 0x0f to "udata", 0x10 to "ref_addr",
        0x11 to "ref1", 0x12 to "ref2", 0x13 to "ref4", 0x14 to "ref8", 0x15 to "ref_udata",
        0x16 to "indirect", 0x17 to "sec_offset", 0x18 to "exprloc", 0x19 to "flag_present",
        0x1a to "strx", 0x1b to "addrx", 0x1c to "ref_sup4", 0x1d to "strp_sup",
        0x1e to "data16", 0x1f to "line_strp", 0x20 to "ref_sig8", 0x21 to "implicit_const",
        0x22 to "loclistx", 0x23 to "rnglistx", 0x24 to "ref_sup8", 0x25 to "strx1",
        0x26 to "strx2", 0x27 to "strx3", 0x28 to "strx4", 0x29 to "addrx1", 0x2a to "addrx2",
        0x2b to "addrx3", 0x2c to "addrx4"
    )

    // Line program opcodes
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

    const val LNE_end_sequence = 1
    const val LNE_set_address = 2
    const val LNE_define_file = 3
    const val LNE_set_discriminator = 4

    const val LNCT_path = 0x1
    const val LNCT_directory_index = 0x2
    const val LNCT_timestamp = 0x3
    const val LNCT_size = 0x4
    const val LNCT_MD5 = 0x5

    // Range list entry kinds (DWARF5 .debug_rnglists)
    const val RLE_end_of_list = 0x00
    const val RLE_base_addressx = 0x01
    const val RLE_startx_endx = 0x02
    const val RLE_startx_length = 0x03
    const val RLE_offset_pair = 0x04
    const val RLE_base_address = 0x05
    const val RLE_start_end = 0x06
    const val RLE_start_length = 0x07

    // Unit types (DWARF5)
    const val UT_compile = 0x01
    const val UT_type = 0x02
    const val UT_partial = 0x03
    const val UT_skeleton = 0x04
    const val UT_split_compile = 0x05
    const val UT_split_type = 0x06

    fun tagName(tag: Int) = TAG_NAMES[tag] ?: "TAG_0x${tag.toString(16)}"
    fun atName(at: Int) = AT_NAMES[at] ?: "AT_0x${at.toString(16)}"
    fun formName(form: Int) = FORM_NAMES[form] ?: "FORM_0x${form.toString(16)}"
}
