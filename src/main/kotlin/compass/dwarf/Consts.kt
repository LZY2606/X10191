package compass.dwarf

object Dw {
    // Tags
    const val TAG_compile_unit = 0x11
    const val TAG_subprogram = 0x2e
    const val TAG_inlined_subroutine = 0x1d
    const val TAG_lexical_block = 0x0b
    const val TAG_skeleton_unit = 0x4a

    // Attributes
    const val AT_name = 0x03
    const val AT_low_pc = 0x11
    const val AT_high_pc = 0x12
    const val AT_stmt_list = 0x10
    const val AT_comp_dir = 0x1b
    const val AT_producer = 0x25
    const val AT_ranges = 0x55
    const val AT_call_file = 0x58
    const val AT_call_line = 0x59
    const val AT_call_column = 0x57
    const val AT_abstract_origin = 0x31
    const val AT_inline = 0x20
    const val AT_linkage_name = 0x6e
    const val AT_MIPS_linkage_name = 0x2007
    const val AT_dwo_name = 0x2130 // DW_AT_GNU_dwo_name / DW_AT_dwo_name
    const val AT_dwo_id = 0x2131
    const val AT_addr_base = 0x2133
    const val AT_rnglists_base = 0x2132 // DW_AT_rnglists_base (DWARF5) == GNU_ranges_base alias zone
    const val AT_str_offsets_base = 0x2134

    // Forms
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
    const val FORM_GNU_strp_alt = 0x1f1d

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

    // Line header content types (DWARF5)
    const val LNCT_path = 0x1
    const val LNCT_directory_index = 0x2
    const val LNCT_timestamp = 0x3
    const val LNCT_size = 0x4
    const val LNCT_MD5 = 0x5

    // Range list entry codes (DWARF5 .debug_rnglists)
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
    const val UT_partial = 0x02
    const val UT_skeleton = 0x04
    const val UT_split_compile = 0x05

    // Children
    const val CHILDREN_no = 0
    const val CHILDREN_yes = 1

    // Limits: parser must stay bounded on corrupt input.
    const val MAX_DIE_DEPTH = 128
    const val MAX_DIES_PER_CU = 200_000
    const val MAX_REF_JUMPS = 64
    const val MAX_LINE_ROWS = 1_000_000
    const val MAX_RANGE_ENTRIES = 1_000_000
    const val MAX_ABBREV_ATTRS = 1_000
    const val MAX_ABBREV_DECLS = 100_000

    fun tagName(tag: Int): String = when (tag) {
        TAG_compile_unit -> "DW_TAG_compile_unit"
        TAG_subprogram -> "DW_TAG_subprogram"
        TAG_inlined_subroutine -> "DW_TAG_inlined_subroutine"
        TAG_lexical_block -> "DW_TAG_lexical_block"
        TAG_skeleton_unit -> "DW_TAG_skeleton_unit"
        else -> "DW_TAG_0x${tag.toString(16)}"
    }

    fun attrName(at: Int): String = when (at) {
        AT_name -> "DW_AT_name"
        AT_low_pc -> "DW_AT_low_pc"
        AT_high_pc -> "DW_AT_high_pc"
        AT_stmt_list -> "DW_AT_stmt_list"
        AT_comp_dir -> "DW_AT_comp_dir"
        AT_producer -> "DW_AT_producer"
        AT_ranges -> "DW_AT_ranges"
        AT_call_file -> "DW_AT_call_file"
        AT_call_line -> "DW_AT_call_line"
        AT_abstract_origin -> "DW_AT_abstract_origin"
        AT_inline -> "DW_AT_inline"
        AT_dwo_name -> "DW_AT_dwo_name"
        AT_addr_base -> "DW_AT_addr_base"
        AT_rnglists_base -> "DW_AT_rnglists_base"
        else -> "DW_AT_0x${at.toString(16)}"
    }
}
