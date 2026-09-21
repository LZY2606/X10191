package com.compass

import com.compass.dwarf.*

/**
 * DWARF5 fixture: strx/addrx, rnglists with an offset table, and a
 * skeleton(.debug_info)/split(.debug_info.dwo) pair matched by dwo_id.
 */
object Dwarf5Fixtures {
    const val DWO_ID = 0x1122334455667788L
    const val FUNC_LO = 0x501000L
    const val FUNC_HI = 0x501040L
    const val INL_LO = 0x501010L
    const val INL_HI = 0x501030L

    class Shared {
        private val str = Bin().u8(0)
        private val offsets = Bin()
        private val addr = Bin()
        private val sMap = HashMap<String, Int>()
        fun s(v: String): Int {
            val existing = sMap[v]; if (existing != null) return existing
            val o = str.size; sMap[v] = o; str.cstr(v); offsets.u64(o.toLong()); return o
        }
        fun strOffsets(): ByteArray {
            val entries = offsets.bytes()
            val body = Bin().u16(5).u16(0).u32((entries.size / 8).toLong()).raw(entries).bytes()
            return Bin().u32(body.size.toLong()).raw(body).bytes()
        }
        fun addAddr(v: Long): Int { val i = addr.size / 8; addr.u64(v); return i }
        fun strBytes() = str.bytes()
        fun addrBytes() = addr.bytes()
    }

    data class Bundle(val mainSections: Map<String, ByteArray>, val dwoSections: Map<String, ByteArray>)

    /**
     * Abbrev tables are per-unit in DWARF5 but this fixture can reuse one
     * layout because both units have the same root/child declarations (their
     * root tags differ: skeleton_unit vs compile_unit).
     */
    private fun abbrev(rootTag: Int, withInline: Boolean): ByteArray {
        val abbr = Bin()
        abbr.uleb(1).uleb(rootTag.toLong()).u8(DW_CHILDREN_yes)
        abbr.uleb(DW_AT_name.toLong()).uleb(DW_FORM_strx1.toLong())
        abbr.uleb(DW_AT_comp_dir.toLong()).uleb(DW_FORM_strx1.toLong())
        abbr.uleb(DW_AT_low_pc.toLong()).uleb(DW_FORM_addrx1.toLong())
        abbr.uleb(DW_AT_str_offsets_base.toLong()).uleb(DW_FORM_sec_offset.toLong())
        abbr.uleb(DW_AT_addr_base.toLong()).uleb(DW_FORM_sec_offset.toLong())
        abbr.uleb(DW_AT_rnglists_base.toLong()).uleb(DW_FORM_sec_offset.toLong())
        abbr.uleb(DW_AT_stmt_list.toLong()).uleb(DW_FORM_sec_offset.toLong())
        abbr.uleb(DW_AT_dwo_id.toLong()).uleb(DW_FORM_data8.toLong())
        abbr.uleb(0).uleb(0)
        abbr.uleb(2).uleb(DW_TAG_subprogram.toLong())
            .u8(if (withInline) DW_CHILDREN_yes else DW_CHILDREN_no)
        abbr.uleb(DW_AT_name.toLong()).uleb(DW_FORM_strx1.toLong())
        abbr.uleb(DW_AT_ranges.toLong()).uleb(DW_FORM_rnglistx.toLong())
        abbr.uleb(0).uleb(0)
        if (withInline) {
            abbr.uleb(3).uleb(DW_TAG_inlined_subroutine.toLong()).u8(DW_CHILDREN_no)
            abbr.uleb(DW_AT_name.toLong()).uleb(DW_FORM_strx1.toLong())
            abbr.uleb(DW_AT_ranges.toLong()).uleb(DW_FORM_rnglistx.toLong())
            abbr.uleb(DW_AT_call_line.toLong()).uleb(DW_FORM_data2.toLong())
            abbr.uleb(0).uleb(0)
        }
        abbr.uleb(0)
        return abbr.bytes()
    }

    fun buildPair(): Bundle {
        val sh = Shared()
        val sCu = sh.s("src/v5.c")
        val sDir = sh.s("/v5/build")
        val sOuter = sh.s("v5_outer")
        val sInl = sh.s("v5_inline")
        val idxLo = sh.addAddr(FUNC_LO)
        val idxInl = sh.addAddr(INL_LO)

        // rnglists: header + offset array + two lists
        val listOuter = Bin().u8(DW_RLE_startx_length).uleb(idxLo.toLong()).uleb(0x40)
            .u8(DW_RLE_end_of_list).bytes()
        val listInl = Bin().u8(DW_RLE_startx_length).uleb(idxInl.toLong()).uleb((INL_HI - INL_LO))
            .u8(DW_RLE_end_of_list).bytes()
        // DWARF5 offset entries are relative to the first byte after the
        // unit_length field (the version byte). list0 content offset is 16.
        val list0Rel = 16L
        val offArray = Bin().u32(list0Rel).u32(list0Rel + listOuter.size).bytes()
        val rngContent = Bin().u16(5).u8(8).u8(0).u32(2L).raw(offArray)
            .raw(listOuter).raw(listInl).bytes()
        val rngBytes = Bin().u32(rngContent.size.toLong()).raw(rngContent).bytes()

        val lineBytes = lineV5()

        fun rootAttrs(b: Bin) {
            b.uleb(1)
            b.u8(0) // name strx1 -> first offset entry (v5.c)
            b.u8(1) // comp_dir strx1
            b.u8(idxLo) // low_pc addrx1
            b.u32(0L) // str_offsets_base
            b.u32(0L) // addr_base
            b.u32(0L) // rnglists_base -> header start
            b.u32(0L) // stmt_list
            b.u64(DWO_ID)
        }

        val mainBody = Bin().u16(5).u8(4 /*skeleton*/).u8(8).u32(0L)
        rootAttrs(mainBody)
        mainBody.uleb(2).u8(2 /*outer strx index*/).uleb(0 /*rnglistx 0*/)
        mainBody.uleb(0) // subprogram no children
        mainBody.uleb(0) // CU children
        val mainInfo = Bin().u32(mainBody.size.toLong()).raw(mainBody.bytes()).bytes()

        val dwoBody = Bin().u16(5).u8(5 /*split compile*/).u8(8).u32(0L)
        rootAttrs(dwoBody)
        dwoBody.uleb(2).u8(2).uleb(0) // outer, rnglistx 0, has child
        dwoBody.uleb(3).u8(3).uleb(1 /*rnglistx 1*/).u16(77) // inline
        dwoBody.uleb(0) // end subprogram
        dwoBody.uleb(0) // end CU
        val dwoInfo = Bin().u32(dwoBody.size.toLong()).raw(dwoBody.bytes()).bytes()

        val common = linkedMapOf(
            ".debug_str" to sh.strBytes(),
            ".debug_str_offsets" to sh.strOffsets(),
            ".debug_addr" to sh.addrBytes(),
            ".debug_rnglists" to rngBytes
        )
        return Bundle(
            (linkedMapOf(
                ".debug_info" to mainInfo,
                ".debug_abbrev" to abbrev(DW_TAG_skeleton_unit, withInline = false),
                ".debug_line" to lineBytes
            ) + common) as Map<String, ByteArray>,
            (linkedMapOf(
                ".debug_info.dwo" to dwoInfo,
                ".debug_abbrev.dwo" to abbrev(DW_TAG_compile_unit, withInline = true)
            ) + common.mapKeys { if (it.key == ".debug_addr") ".debug_addr.dwo"
                else if (it.key == ".debug_str_offsets") ".debug_str_offsets.dwo"
                else if (it.key == ".debug_rnglists") ".debug_rnglists.dwo" else it.key })
                    as Map<String, ByteArray>
        )
    }

    fun lineV5(): ByteArray {
        val dirs = Bin().uleb(1).u8(1)
            .uleb(DW_LNCT_path.toLong()).uleb(DW_FORM_string.toLong()).cstr("src").bytes()
        val files = Bin().uleb(1).u8(2)
            .uleb(DW_LNCT_path.toLong()).uleb(DW_FORM_string.toLong()).cstr("v5.c")
            .uleb(DW_LNCT_directory_index.toLong()).uleb(DW_FORM_data1.toLong()).u8(0).bytes()
        // opcode argument counts for standard opcodes 1..opcode_base-1
        val standardArgs = intArrayOf(0,1,1,1,1,0,0,0,0,0,0,1)
        val headerTail = Bin().u8(1).u8(1).u8(1).u8(0xfb).u8(14).u8(13)
        for (a in standardArgs) headerTail.u8(a)
        val prog = Bin()
        prog.u8(0); prog.uleb(9); prog.u8(DW_LINE_set_address); prog.u64(FUNC_LO)
        prog.u8(DW_LNS_set_file.toInt()).uleb(0)
        prog.u8(DW_LNS_set_column.toInt()).uleb(3)
        // first row @ FUNC_LO line 10: advance_line then copy (copy emits row
        // with no address/line change, avoiding a special opcode overflow).
        prog.u8(DW_LNS_advance_line.toInt()).sleb(9)
        prog.u8(DW_LNS_copy.toInt())
        // next row @ INL_LO line 30: advance pc via standard opcode, then
        // advance_line 20 and copy (copy emits a row without changing address)
        prog.u8(DW_LNS_advance_pc.toInt()).uleb((INL_LO - FUNC_LO).toInt())
        prog.u8(DW_LNS_advance_line.toInt()).sleb(20)
        prog.u8(DW_LNS_copy.toInt())
        prog.u8(0); prog.uleb(9); prog.u8(DW_LINE_set_address); prog.u64(FUNC_HI)
        prog.u8(0); prog.uleb(1); prog.u8(DW_LINE_end_sequence)
        val entries = dirs + files
        val headerBody = headerTail.raw(entries).bytes()
        // header_length covers version(2) + the 4-byte length field + header body.
        val headerLen = 2 + 4 + headerBody.size
        val unitBody = Bin().u16(5).u32(headerLen.toLong())
            .raw(headerBody).raw(prog.bytes()).bytes()
        return Bin().u32(unitBody.size.toLong()).raw(unitBody).bytes()
    }

    private fun special(b: Bin, pcDelta: Int, rem: Int) {
        val opcode = 13 + 14 * pcDelta + rem
        require(opcode in 13..255)
        b.u8(opcode)
    }
}
