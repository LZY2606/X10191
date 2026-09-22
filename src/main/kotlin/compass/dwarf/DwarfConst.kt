package compass.dwarf

object DW {
    // tags
    const val TAG_compile_unit = 0x11
    const val TAG_skeleton_unit = 0x41000001.toInt()
    const val TAG_partial_unit = 0x12
    const val TAG_type_unit = 0x41000002.toInt()
    const val TAG_subprogram = 0x2e
    const val TAG_inlined_subroutine = 0x1d
    const val TAG_compile_unit_5_partial = 0x12

    // attributes
    const val AT_sibling = 0x01
    const val AT_location = 0x02
    const val AT_name = 0x03
    const val AT_byte_size = 0x0b
    const val AT_stmt_list = 0x10
    const val AT_low_pc = 0x11
    const val AT_high_pc = 0x12
    const val AT_language = 0x13
    const val AT_comp_dir = 0x1b
    const val AT_ranges = 0x55
    const val AT_abstract_origin = 0x31
    const val AT_specification = 0x47
    const val AT_call_file = 0x58
    const val AT_call_line = 0x59
    const val AT_call_column = 0x57
    const val AT_ranges_base = 0x745 // GNU value; DWARF5: 0x74
    const val AT_rnglists_base = 0x74
    const val AT_str_offsets_base = 0x72
    const val AT_addr_base = 0x73
    const val AT_GNU_addr_base = 0x2133
    const val AT_GNU_str_offsets_base = 0x2132
    const val AT_dwo_name = 0x76
    const val AT_GNU_dwo_name = 0x2130
    const val AT_dwo_id = 0x2135
    const val AT_GNU_dwo_id = 0x2134
    const val AT_signature = 0x69
    const val AT_decl_file = 0x3a
    const val AT_decl_line = 0x3b
    const val AT_decl_column = 0x39
    const val AT_linkage_name = 0x6e
    const val AT_MIPS_linkage_name = 0x2007
    const val AT_priority = 0x6f // vendor/pseudo used by compass fixtures for explicit priority
    const val AT_explicit_priority = 0x7000 // vendor range; compass fixture marker
    const val AT_segment = 0x7001 // compass fixture pseudo attribute for segment selector

    // unit types (DWARF5)
    const val UT_COMPILE = 0x01
    const val UT_TYPE = 0x02
    const val UT_PARTIAL = 0x03
    const val UT_SKELETON = 0x04
    const val UT_SPLIT_COMPILE = 0x05
    const val UT_SPLIT_TYPE = 0x06

    // standard line opcodes
    const val LNS_copy = 0x01
    const val LNS_advance_pc = 0x02
    const val LNS_advance_line = 0x03
    const val LNS_set_file = 0x04
    const val LNS_set_column = 0x05
    const val LNS_negate_stmt = 0x06
    const val LNS_set_basic_block = 0x07
    const val LNS_const_add_pc = 0x08
    const val LNS_fixed_advance_pc = 0x09
    const val LNS_set_prologue_end = 0x0a
    const val LNS_set_epilogue_begin = 0x0b
    const val LNS_set_isa = 0x0c
    // DWARF4 actually places prologue_end=10, epilogue_begin=11, isa=12 too (same layout)

    // extended line opcodes
    const val LNE_end_sequence = 0x01
    const val LNE_set_address = 0x02
    const val LNE_define_file = 0x03
    const val LNE_set_discriminator = 0x04

    // line header content types (DWARF5)
    const val LCT_path = 0x1
    const val LCT_directory_index = 0x2
    const val LCT_timestamp = 0x3
    const val LCT_size = 0x4
    const val LCT_MD5 = 0x5

    // range list entry codes
    const val DW_RLE_end_of_list = 0x00
    const val DW_RLE_base_addressx = 0x01
    const val DW_RLE_startx_endx = 0x02
    const val DW_RLE_startx_length = 0x03
    const val DW_RLE_offset_pair = 0x04
    const val DW_RLE_base_address = 0x05
    const val DW_RLE_start_end = 0x06
    const val DW_RLE_start_length = 0x07
}

object DwarfNames {
    private val tags = mapOf(
        DW.TAG_compile_unit to "DW_TAG_compile_unit",
        DW.TAG_skeleton_unit to "DW_TAG_skeleton_unit",
        DW.TAG_partial_unit to "DW_TAG_partial_unit",
        DW.TAG_type_unit to "DW_TAG_type_unit",
        DW.TAG_subprogram to "DW_TAG_subprogram",
        DW.TAG_inlined_subroutine to "DW_TAG_inlined_subroutine",
    )
    private val attrs = mapOf(
        DW.AT_name to "DW_AT_name",
        DW.AT_low_pc to "DW_AT_low_pc",
        DW.AT_high_pc to "DW_AT_high_pc",
        DW.AT_ranges to "DW_AT_ranges",
        DW.AT_stmt_list to "DW_AT_stmt_list",
        DW.AT_language to "DW_AT_language",
        DW.AT_comp_dir to "DW_AT_comp_dir",
        DW.AT_abstract_origin to "DW_AT_abstract_origin",
        DW.AT_specification to "DW_AT_specification",
        DW.AT_call_file to "DW_AT_call_file",
        DW.AT_call_line to "DW_AT_call_line",
        DW.AT_call_column to "DW_AT_call_column",
        DW.AT_dwo_name to "DW_AT_dwo_name",
        DW.AT_GNU_dwo_name to "DW_AT_GNU_dwo_name",
        DW.AT_dwo_id to "DW_AT_dwo_id",
        DW.AT_GNU_dwo_id to "DW_AT_GNU_dwo_id",
        DW.AT_rnglists_base to "DW_AT_rnglists_base",
        DW.AT_str_offsets_base to "DW_AT_str_offsets_base",
        DW.AT_addr_base to "DW_AT_addr_base",
        DW.AT_GNU_addr_base to "DW_AT_GNU_addr_base",
        DW.AT_GNU_str_offsets_base to "DW_AT_GNU_str_offsets_base",
        DW.AT_decl_file to "DW_AT_decl_file",
        DW.AT_decl_line to "DW_AT_decl_line",
        DW.AT_decl_column to "DW_AT_decl_column",
        DW.AT_linkage_name to "DW_AT_linkage_name",
        DW.AT_explicit_priority to "DW_AT_explicit_priority",
        DW.AT_segment to "DW_AT_segment(selector)",
    )
    private val forms = compass.model.AttrForm.entries.associateBy { it.code }.mapValues { "DW_FORM_${it.value.name.lowercase()}" }

    fun tag(code: Int): String = tags[code] ?: "DW_TAG_0x${code.toString(16)}"
    fun attr(code: Int): String = attrs[code] ?: "DW_AT_0x${code.toString(16)}"
    fun form(code: Int): String = forms[code] ?: "DW_FORM_unknown(0x${code.toString(16)})"
}
