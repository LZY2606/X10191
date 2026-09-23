package compass.dwarf

/** DWARF tag / attribute / form / opcode constants used by the parser. */
object DW {
    // tags
    const val TAG_compile_unit = 0x11
    const val TAG_skeleton_unit = 0x41000001
    const val TAG_partial_unit = 0x3c
    const val TAG_type_unit = 0x41000002
    const val TAG_subprogram = 0x2e
    const val TAG_inlined_subroutine = 0x1d
    const val TAG_lexical_block = 0x0b

    // attributes
    const val AT_name = 0x03
    const val AT_stmt_list = 0x10
    const val AT_low_pc = 0x11
    const val AT_high_pc = 0x12
    const val AT_comp_dir = 0x1b
    const val AT_ranges = 0x55
    const val AT_str_offsets_base = 0x72
    const val AT_addr_base = 0x73
    const val AT_rnglists_base = 0x74
    const val AT_linkage_name = 0x6e
    const val AT_MIPS_linkage_name = 0x2007
    const val AT_call_file = 0x58
    const val AT_call_line = 0x59
    const val AT_call_column = 0x57
    const val AT_inline = 0x20
    const val AT_decl_file = 0x3a
    const val AT_decl_line = 0x3b
    const val AT_decl_column = 0x39
    const val AT_specification = 0x47
    const val AT_abstract_origin = 0x31
    const val AT_dwo_name = 0x76
    const val AT_dwo_id = 0x2013
    const val AT_GNU_dwo_name = 0x2130
    const val AT_GNU_dwo_id = 0x2131
    const val AT_GNU_ranges_base = 0x2132
    const val AT_GNU_addr_base = 0x2133
    const val AT_GNU_str_index = 0x202a
    const val AT_GNU_addr_index = 0x202b

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
    const val FORM_line_strp = 0x1b
    const val FORM_implicit_const = 0x21
    const val FORM_loclistx = 0x23
    const val FORM_rnglistx = 0x22
    const val FORM_ref_sup4 = 0x1c
    const val FORM_strx_sup = 0x1f
    const val FORM_data16 = 0x1e
    const val FORM_addrx = 0x20
    const val FORM_ref_sup8 = 0x1d
    const val FORM_ref_signed = 0x92
    const val FORM_strx1 = 0x25
    const val FORM_strx2 = 0x26
    const val FORM_strx3 = 0x27
    const val FORM_strx4 = 0x28
    const val FORM_addrx1 = 0x29
    const val FORM_addrx2 = 0x2a
    const val FORM_addrx3 = 0x2b
    const val FORM_addrx4 = 0x2c
    const val FORM_GNU_ref_alt = 0x1f20
    const val FORM_GNU_strp_alt = 0x1f21
    const val FORM_GNU_addr_index = 0x1f24
    const val FORM_GNU_str_index = 0x1f25

    // inline codes
    const val INL_not_inlined = 0x00
    const val INL_inlined = 0x01
    const val INL_declared_not_inlined = 0x02
    const val INL_declared_inlined = 0x03

    // line header content types (DWARF5)
    const val CT_path = 0x1
    const val CT_directory_index = 0x2
    const val CT_timestamp = 0x3
    const val CT_size = 0x4
    const val CT_MD5 = 0x5

    // line standard opcodes
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

    // line extended opcodes
    const val LNE_end_sequence = 0x01
    const val LNE_set_address = 0x02
    const val LNE_define_file = 0x03
    const val LNE_set_discriminator = 0x04

    // range list encoding (DWARF 5 rnglists)
    const val RLE_end_of_list = 0x00
    const val RLE_base_addressx = 0x01
    const val RLE_startx_endx = 0x02
    const val RLE_startx_length = 0x03
    const val RLE_offset_pair = 0x04
    const val RLE_base_address = 0x05
    const val RLE_start_end = 0x06
    const val RLE_start_length = 0x07

    // ELF section types
    const val SHT_STRTAB = 3
    const val SHT_NOBITS = 8
    const val SHT_NOTE = 7
}
