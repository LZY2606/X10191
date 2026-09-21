package compass.dwarf

object DW {
    // tags
    const val TAG_compile_unit = 0x11
    const val TAG_skeleton_unit = 0x41
    const val TAG_type_unit = 0x41 // same value in v5; disambiguated by unit_type
    const val TAG_partial_unit = 0x3c
    const val TAG_type_unit_gnu = 0x4100
    const val TAG_subprogram = 0x2e
    const val TAG_inlined_subroutine = 0x1d
    const val TAG_compile_unit_lo = 0x11

    // attributes
    const val AT_sibling = 0x01
    const val AT_name = 0x03
    const val AT_stmt_list = 0x10
    const val AT_low_pc = 0x11
    const val AT_high_pc = 0x12
    const val AT_comp_dir = 0x1b
    const val AT_ranges = 0x55
    const val AT_abstract_origin = 0x31
    const val AT_specification = 0x47
    const val AT_artificial = 0x34
    const val AT_decl_file = 0x3a
    const val AT_decl_line = 0x3b
    const val AT_call_file = 0x58
    const val AT_call_line = 0x59
    const val AT_type = 0x49
    const val AT_linkage_name = 0x6e
    const val AT_MIPS_linkage_name = 0x2007
    const val AT_comp_dir_alt = 0x1b
    const val AT_GNU_dwo_name = 0x2130
    const val AT_dwo_name = 0x76
    const val AT_GNU_addr_base = 0x2133
    const val AT_addr_base = 0x73
    const val AT_str_offsets_base = 0x72
    const val AT_GNU_str_offsets_base = 0x2132
    const val AT_rnglists_base = 0x74
    const val AT_language = 0x13
    const val AT_producer = 0x25
    const val AT_call_column = 0x57
    const val AT_decl_column = 0x39

    // forms
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
        val strx2 = 0x26
        const val strx3 = 0x27
        const val strx4 = 0x28
        const val addrx1 = 0x29
        const val addrx2 = 0x2a
        const val addrx3 = 0x2b
        const val addrx4 = 0x2c
        const val GNU_addr_index = 0x1f01
        const val GNU_str_index = 0x1f02
        const val GNU_strp_offset = 0x1f03
    }

    // line header content type codes (DWARF 5)
    object LNCT {
        const val path = 0x01
        const val directory_index = 0x02
        const val timestamp = 0x03
        const val size = 0x04
        const val MD5 = 0x05
        const val lo_user = 0x2000
        const val directory = 0x2000 // approximation unused
    }

    // line standard opcodes
    object LNS {
        const val copy = 1
        const val advance_pc = 2
        const val line = 3
        const val file = 4
        const val set_column = 5
        const val negate_stmt = 6
        const val set_basic_block = 7
        const val const_add_pc = 8
        const val fixed_add_pc = 9
        const val set_prologue_end = 10
        const val set_epilogue_begin = 11
        const val set_isa = 12
    }

    object LNE {
        const val end_sequence = 1
        const val set_address = 2
        const val define_file = 3
        const val set_discriminator = 4
    }

    object UT {
        const val compile = 0x01
        const val type = 0x02
        const val partial = 0x03
        const val skeleton = 0x04
        const val split_compile = 0x05
        const val split_type = 0x06
    }
}
