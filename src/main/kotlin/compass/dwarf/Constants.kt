package compass.dwarf

object DW {
    const val TAG_compile_unit = 0x11
    const val TAG_skeleton_unit = 0x4a
    const val TAG_split_compile_unit = 0x41
    const val TAG_subprogram = 0x2e
    const val TAG_inlined_subroutine = 0x1d

    const val AT_name = 0x03
    const val AT_stmt_list = 0x10
    const val AT_low_pc = 0x11
    const val AT_high_pc = 0x12
    const val AT_ranges = 0x55
    const val AT_comp_dir = 0x1b
    const val AT_str_offsets_base = 0x72
    const val AT_addr_base = 0x73
    const val AT_dwo_name = 0x76
    const val AT_dwo_id = 0x2013
    const val AT_abstract_origin = 0x31
    const val AT_specification = 0x47
    const val AT_origin = 0x49
    const val AT_call_file = 0x58
    const val AT_call_line = 0x59
    const val AT_linkage_name = 0x6e
    const val AT_rnglists_base = 0x74
    const val AT_loclists_base = 0x802c

    // DW_AT_type
    const val AT_type = 0x49
    const val AT_declaration = 0x3c
}

object FORM {
    const val addr = 0x01
    const val block2 = 0x03
    const val block4 = 0x04
    const val data2 = 0x05
    const val data4 = 0x06
    const val data8 = 0x07
    const val string = 0x08
    const val block = 0x09
    const val block1 = 0x0a
    const val data1 = 0x0b
    const val flag = 0x0c
    const val sdata = 0x0d
    const val strp = 0x0e
    const val udata = 0x0f
    const val ref_addr = 0x10
    const val ref1 = 0x11
    const val ref2 = 0x12
    const val ref4 = 0x13
    const val ref8 = 0x14
    const val ref_udata = 0x15
    const val indirect = 0x16
    const val sec_offset = 0x17
    const val exprloc = 0x18
    const val flag_present = 0x19
    const val strx = 0x1a
    const val addrx = 0x1b
    const val ref_sup4 = 0x1c
    const val strp_sup = 0x1d
    const val data16 = 0x1e
    const val line_strp = 0x1f
    const val ref_sig8 = 0x20
    const val implicit_const = 0x21
    const val loclistx = 0x22
    const val rnglistx = 0x23
    const val ref_sup8 = 0x24
    const val strx1 = 0x25
    const val strx2 = 0x26
    const val strx3 = 0x27
    const val strx4 = 0x28
    const val addrx1 = 0x29
    const val addrx2 = 0x2a
    const val addrx3 = 0x2b
    const val addrx4 = 0x2c
}

object LNE {
    const val end_sequence = 1
    const val set_address = 2
    const val define_file = 3
    const val set_discriminator = 4
}

object LNS {
    const val copy = 1
    const val advance_pc = 2
    const val advance_line = 3
    const val set_file = 4
    const val set_column = 5
    const val negate_stmt = 6
    const val set_basic_block = 7
    const val const_add_pc = 8
    const val fixed_advance_pc = 9
    const val set_prologue_end = 10
    const val set_epilogue_begin = 11
    const val set_isa = 12
}

object LNCT {
    const val path = 1
    const val directory_index = 2
    const val timestamp = 3
    const val size = 4
    const val MD5 = 5
}

object RLE {
    const val end_of_list = 0x00
    const val base_addressx = 0x01
    const val startx_endx = 0x02
    const val startx_length = 0x03
    const val offset_pair = 0x04
    const val default_location = 0x05
    const val base_address = 0x06
    const val start_end = 0x07
    const val start_length = 0x08
}

/**
 * 行表来源版本。fixture 可构造“自报版本”的行程序头，用于演示 4/5 混用。
 */
data class TableVersion(val dwarfVersion: Int, val headerIs64Bit: Boolean, val headerOffset: Long)
