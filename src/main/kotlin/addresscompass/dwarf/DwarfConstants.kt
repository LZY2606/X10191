@file:Suppress("unused", "MemberVisibilityCanBePrivate")
package addresscompass.dwarf

object Dwarf {
    // unit types (DWARF5)
    const val UT_COMPILE = 0x01
    const val UT_TYPE = 0x02
    const val UT_PARTIAL = 0x03
    const val UT_SKELETON = 0x04
    const val UT_SPLIT_COMPILE = 0x05
    const val UT_SPLIT_TYPE = 0x06

    object UnitTypes {
        fun name(t: Int, version: Int): String = when {
            version < 5 -> "DWARF$version CU"
            t == UT_COMPILE -> "DWARF5 compile"
            t == UT_TYPE -> "DWARF5 type"
            t == UT_PARTIAL -> "DWARF5 partial"
            t == UT_SKELETON -> "DWARF5 skeleton"
            t == UT_SPLIT_COMPILE -> "DWARF5 split compile"
            t == UT_SPLIT_TYPE -> "DWARF5 split type"
            else -> "DWARF5 unit(0x${t.toString(16)})"
        }
    }

    // tags we care about
    const val DW_TAG_compile_unit = 0x11
    const val DW_TAG_subprogram = 0x2e
    const val DW_TAG_inlined_subroutine = 0x1d
    const val DW_TAG_partial_unit = 0x3c

    // attributes
    const val DW_AT_name = 0x03
    const val DW_AT_stmt_list = 0x10
    const val DW_AT_low_pc = 0x11
    const val DW_AT_high_pc = 0x12
    const val DW_AT_comp_dir = 0x1b
    const val DW_AT_abstract_origin = 0x31
    const val DW_AT_decl_file = 0x3a
    const val DW_AT_decl_line = 0x3b
    const val DW_AT_inline = 0x20
    const val DW_AT_specification = 0x47
    const val DW_AT_ranges = 0x55
    const val DW_AT_call_file = 0x58
    const val DW_AT_call_line = 0x59
    const val DW_AT_GNU_ranges_base = 0x2133
    const val DW_AT_rnglists_base = 0x74
    const val DW_AT_addr_base = 0x73
    const val DW_AT_str_offsets_base = 0x72
    const val DW_AT_dwo_name = 0x76
    const val DW_AT_GNU_dwo_name = 0x2130
    const val DW_AT_dwo_id = 0x2000 + 0x31 // 0x2031
    const val DW_AT_GNU_dwo_id = 0x2131
    const val DW_AT_segment = 0x68
    const val DW_AT_priority = 0x7a

    // forms
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
    const val DW_FORM_ref_sup8 = 0x20
    const val DW_FORM_strx1 = 0x25
    const val DW_FORM_strx2 = 0x26
    const val DW_FORM_strx3 = 0x27
    const val DW_FORM_strx4 = 0x28
    const val DW_FORM_addrx1 = 0x29
    const val DW_FORM_addrx2 = 0x2a
    const val DW_FORM_addrx3 = 0x2b
    const val DW_FORM_addrx4 = 0x2c
    const val DW_FORM_rnglistx = 0x23
    const val DW_FORM_loclistx = 0x22
    const val DW_FORM_implicit_const = 0x21
    // GNU
    const val DW_FORM_GNU_addr_index = 0x1f01
    const val DW_FORM_GNU_str_index = 0x1f02
    const val DW_FORM_GNU_ref_alt = 0x1f20
    const val DW_FORM_GNU_strp_alt = 0x1f21

    // rnglists entry kinds (v5)
    const val DW_RLE_end_of_list = 0x00
    const val DW_RLE_base_addressx = 0x01
    const val DW_RLE_startx_endx = 0x02
    const val DW_RLE_startx_length = 0x03
    const val DW_RLE_offset_pair = 0x04
    const val DW_RLE_base_address = 0x05
    const val DW_RLE_start_end = 0x06
    const val DW_RLE_start_length = 0x07
}

object LineConstants {
    // standard opcodes (v4/v5 share 1..12; v5 adds 13 set_isa)
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
    const val DW_LNS_set_logical_pc = 0x0c       // DWARF 5
    const val DW_LNS_set_address_from_logical_pc = 0x0d // DWARF 5

    const val DW_LNE_end_sequence = 0x01
    const val DW_LNE_set_address = 0x02
    const val DW_LNE_define_file = 0x03
    const val DW_LNE_set_discriminator = 0x04

    // v5 line content types
    const val DW_LNCT_path = 0x1
    const val DW_LNCT_directory_index = 0x2
    const val DW_LNCT_timestamp = 0x3
    const val DW_LNCT_size = 0x4
    const val DW_LNCT_MD5 = 0x5
}
