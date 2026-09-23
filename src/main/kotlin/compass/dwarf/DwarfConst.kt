package compass.dwarf

object Dw {
    // tags
    const val TAG_compile_unit = 0x11
    const val TAG_subprogram = 0x2E
    const val TAG_inlined_subroutine = 0x1D
    const val TAG_skeleton_unit = 0x4A
    const val TAG_type_unit = 0x41

    // attributes
    const val AT_name = 0x03
    const val AT_low_pc = 0x11
    const val AT_high_pc = 0x12
    const val AT_stmt_list = 0x10
    const val AT_comp_dir = 0x1B
    const val AT_ranges = 0x55
    const val AT_call_file = 0x58
    const val AT_call_line = 0x59
    const val AT_call_column = 0x5A
    const val AT_abstract_origin = 0x31
    const val AT_specification = 0x47
    const val AT_producer = 0x25
    const val AT_dwo_name = 0x76
    const val AT_GNU_dwo_name = 0x2130
    const val AT_addr_base = 0x73
    const val AT_rnglists_base = 0x74
    const val AT_str_offsets_base = 0x72
    const val AT_GNU_ranges = 0x2132

    // forms
    const val FORM_addr = 0x01
    const val FORM_block2 = 0x03
    const val FORM_block4 = 0x04
    const val FORM_data2 = 0x05
    const val FORM_data4 = 0x06
    const val FORM_data8 = 0x07
    const val FORM_string = 0x08
    const val FORM_block = 0x09
    const val FORM_block1 = 0x0A
    const val FORM_data1 = 0x0B
    const val FORM_flag = 0x0C
    const val FORM_sdata = 0x0D
    const val FORM_strp = 0x0E
    const val FORM_udata = 0x0F
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
    const val FORM_strx = 0x1A
    const val FORM_addrx = 0x1B
    const val FORM_ref_sup4 = 0x1C
    const val FORM_strp_sup = 0x1D
    const val FORM_data16 = 0x1E
    const val FORM_line_strp = 0x1F
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
    const val FORM_addrx2 = 0x2A
    const val FORM_addrx3 = 0x2B
    const val FORM_addrx4 = 0x2C
    const val FORM_GNU_addr_index = 0x1F01
    const val FORM_GNU_str_index = 0x1F02
    const val FORM_GNU_strp_alt = 0x1F1F

    // line program opcodes
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

    // rnglists entry kinds (DWARF5)
    const val RLE_end_of_list = 0x00
    const val RLE_base_addressx = 0x01
    const val RLE_startx_endx = 0x02
    const val RLE_startx_length = 0x03
    const val RLE_offset_pair = 0x04
    const val RLE_base_address = 0x05
    const val RLE_start_end = 0x06
    const val RLE_start_length = 0x07

    // unit types (DWARF5)
    const val UT_compile = 0x01
    const val UT_type = 0x02
    const val UT_partial = 0x03
    const val UT_skeleton = 0x04
    const val UT_split_compile = 0x05
    const val UT_split_type = 0x06

    fun tagName(tag: Int) = when (tag) {
        TAG_compile_unit -> "DW_TAG_compile_unit"
        TAG_subprogram -> "DW_TAG_subprogram"
        TAG_inlined_subroutine -> "DW_TAG_inlined_subroutine"
        TAG_skeleton_unit -> "DW_TAG_skeleton_unit"
        TAG_type_unit -> "DW_TAG_type_unit"
        else -> "DW_TAG_0x${tag.toString(16)}"
    }
}
