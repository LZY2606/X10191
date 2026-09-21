package compass.fixtures

import compass.dwarf.DW

object Fixtures {

    fun elf(bytes: Map<String, ByteArray>): ByteArray {
        val w = ElfWriter()
        for ((name, data) in bytes) {
            // .debug_addr allocated so a PT_LOAD covers it and segmented lookup works
            val alloc = name == ".text" || name == ".debug_addr"
            w.debug(name, data, alloc)
        }
        return w.build()
    }

    fun sectionsOf(f: DwarfFixture): Map<String, ByteArray> {
        f.finalizeLine()
        val map = LinkedHashMap<String, ByteArray>()
        if (f.info.bytes().isNotEmpty()) map[".debug_info"] = f.info.bytes()
        if (f.abbrev.bytes().isNotEmpty()) map[".debug_abbrev"] = f.abbrev.bytes()
        if (f.line.bytes().isNotEmpty()) map[".debug_line"] = f.line.bytes()
        if (f.ranges.bytes().isNotEmpty()) map[".debug_ranges"] = f.ranges.bytes()
        if (f.rnglists.bytes().isNotEmpty()) map[".debug_rnglists"] = f.rnglists.bytes()
        if (f.str.bytes().isNotEmpty()) map[".debug_str"] = f.str.bytes()
        if (f.lineStr.bytes().isNotEmpty()) map[".debug_line_str"] = f.lineStr.bytes()
        if (f.addr.bytes().isNotEmpty()) map[".debug_addr"] = f.addr.bytes()
        if (f.strOffsets.bytes().isNotEmpty()) map[".debug_str_offsets"] = f.strOffsets.bytes()
        return map
    }

    // DW_FORM constants reused in fixtures
    const val FORM_string = 0x08
    const val FORM_strp = 0x0e
    const val FORM_data1 = 0x0b
    const val FORM_data4 = 0x06
    const val FORM_data8 = 0x07
    const val FORM_addr = 0x01
    const val FORM_sec_offset = 0x17
    const val FORM_udata = 0x0f
    const val FORM_ref4 = 0x13
    const val FORM_ref_udata = 0x15
    const val FORM_flag_present = 0x19
    const val FORM_implicit_const = 0x21
    const val FORM_indirect = 0x16
    const val FORM_strx = 0x1a
    const val FORM_addrx = 0x1b
    const val FORM_GNU_addr_index = 0x1f01

    const val AT_name = DW.AT_name
    const val AT_comp_dir = DW.AT_comp_dir
    const val AT_stmt_list = DW.AT_stmt_list
    const val AT_low_pc = DW.AT_low_pc
    const val AT_high_pc = DW.AT_high_pc
    const val AT_ranges = DW.AT_ranges
    const val AT_abstract_origin = DW.AT_abstract_origin
    const val AT_call_file = DW.AT_call_file
    const val AT_call_line = DW.AT_call_line
    const val AT_decl_file = DW.AT_decl_file
    const val AT_decl_line = DW.AT_decl_line
    const val AT_inline = 0x20
    const val AT_dwo_name = DW.AT_dwo_name
    const val AT_addr_base = DW.AT_addr_base
    const val AT_str_offsets_base = DW.AT_str_offsets_base
    const val AT_producer = DW.AT_producer
    const val AT_language = DW.AT_language

    const val TAG_subprogram = DW.TAG_subprogram
    const val TAG_inlined_subroutine = DW.TAG_inlined_subroutine
}
