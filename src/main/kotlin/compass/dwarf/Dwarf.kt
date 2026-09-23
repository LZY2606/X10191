package compass.dwarf

/** DWARF tag / attribute / form 等常量（DWARF 4/5 用到的子集）。 */
object DW {
    const val DW_TAG_compile_unit = 0x11
    const val DW_TAG_subprogram = 0x2e
    const val DW_TAG_inlined_subroutine = 0x1d
    const val DW_TAG_partial_unit = 0x3c
    const val DW_TAG_type_unit = 0x41
    const val DW_TAG_skeleton_unit = 0x4a

    const val DW_AT_name = 0x03
    const val DW_AT_stmt_list = 0x10
    const val DW_AT_low_pc = 0x11
    const val DW_AT_high_pc = 0x12
    const val DW_AT_ranges = 0x55
    const val DW_AT_comp_dir = 0x1b
    const val DW_AT_abstract_origin = 0x31
    const val DW_AT_specification = 0x47
    const val DW_AT_inline = 0x20
    const val DW_AT_call_file = 0x58
    const val DW_AT_call_line = 0x59
    const val DW_AT_call_column = 0x57
    const val DW_AT_rnglists_base = 0x74
    const val DW_AT_str_offsets_base = 0x72
    const val DW_AT_addr_base = 0x73
    const val DW_AT_GNU_addr_base = 0x2133
    const val DW_AT_GNU_ranges_base = 0x2132
    const val DW_AT_GNU_dwo_name = 0x2130
    const val DW_AT_dwo_name = 0x76
    const val DW_AT_GNU_dwo_id = 0x2131
    const val DW_AT_dwo_id = 0x77
    const val DW_AT_language = 0x13
    const val DW_AT_linkage_name = 0x6e
    const val DW_AT_MIPS_linkage_name = 0x2007
    const val DW_AT_decl_file = 0x3a
    const val DW_AT_decl_line = 0x3b
    const val DW_AT_decl_column = 0x39

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
    const val DW_FORM_GNU_str_index = 0x1f21
    const val DW_FORM_GNU_addr_index = 0x1f20
    const val DW_FORM_GNU_strp_alt = 0x1f23
    const val DW_FORM_GNU_ref_alt = 0x1f22

    const val DW_INL_not_inlined = 0x00
    const val DW_INL_inlined = 0x01
    const val DW_INL_declared_inlined = 0x02

    // line program opcodes
    const val DW_LNS_copy = 0x01
    const val DW_LNS_advance_pc = 0x02
    const val DW_LNS_advance_line = 0x03
    const val DW_LNS_set_file = 0x04
    const val DW_LNS_set_column = 0x05
    const val DW_LNS_negate_stmt = 0x06
    const val DW_LNS_set_basic_block = 0x07
    const val DW_LNS_const_add_pc = 0x08
    const val DW_LNS_fixed_advance_pc = 0x09
    const val DW_LNS_set_prologue_end = 0x0a
    const val DW_LNS_set_isa = 0x0b

    const val DW_LNE_end_sequence = 0x01
    const val DW_LNE_set_address = 0x02
    const val DW_LNE_define_file = 0x03
    const val DW_LNE_set_discriminator = 0x04

    // rnglist (DWARF5 .debug_rnglists)
    const val DW_RLE_end_of_list = 0x00
    const val DW_RLE_base_addressx = 0x01
    const val DW_RLE_startx_endx = 0x02
    const val DW_RLE_startx_length = 0x03
    const val DW_RLE_offset_pair = 0x04
    const val DW_RLE_base_address = 0x05
    const val DW_RLE_start_end = 0x06
    const val DW_RLE_start_length = 0x07
}
