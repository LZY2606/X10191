package com.compass

import com.compass.dwarf.*

/**
 * Factory for synthetic DWARF4/5 section content.
 *
 * The DWARF4 scenario contains:
 *  - compile_unit with low_pc/high_pc(=constant length) — high_pc meaning #2
 *  - outer subprogram via .debug_ranges (two disjoint pieces)
 *  - inlined_subroutine with low_pc/high_pc address form — meaning #1
 *  - a zero-length function (low_pc == high_pc)
 *  - a second subprogram overlapping the inlined body
 *  - a .debug_line program with two sequences and special opcodes
 */
object DwarfFixtures {

    // Addresses chosen inside .text starting at 0x401000.
    const val BASE = 0x401000L
    const val FUNC_LO = 0x401100L
    const val FUNC_HI = 0x401180L
    const val INL_LO = 0x401120L
    const val INL_HI = 0x401150L
    const val OVER_LO = 0x401110L
    const val OVER_HI = 0x401160L
    const val ZERO_PC = 0x401200L

    data class Sections(val map: Map<String, ByteArray>)

    fun dwarf4(): Sections {
        // ---- strings ----
        val str = Bin().u8(0)
        val sCu = str.size; str.cstr("src/main.c")
        val sDir = str.size; str.cstr("/build/proj")
        val sOuter = str.size; str.cstr("outer_func")
        val sInl = str.size; str.cstr("inner_inline")
        val sOver = str.size; str.cstr("overlapping_func")
        val sZero = str.size; str.cstr("zero_func")
        val sCallFile = str.size; str.cstr("include/header.h")
        val strBytes = str.bytes()

        // ---- abbrev ----
        val abbr = Bin()
        var code = 1L
        // 1: compile_unit, children yes
        abbr.uleb(code++).uleb(DW_TAG_compile_unit.toLong()).u8(DW_CHILDREN_yes)
        abbr.uleb(DW_AT_name.toLong()).uleb(DW_FORM_strp.toLong())
        abbr.uleb(DW_AT_comp_dir.toLong()).uleb(DW_FORM_strp.toLong())
        abbr.uleb(DW_AT_stmt_list.toLong()).uleb(DW_FORM_sec_offset.toLong())
        abbr.uleb(DW_AT_low_pc.toLong()).uleb(DW_FORM_addr.toLong())
        abbr.uleb(DW_AT_high_pc.toLong()).uleb(DW_FORM_data4.toLong()) // high_pc = length
        abbr.uleb(0).uleb(0)

        // 2: subprogram with DW_AT_ranges, children yes (to hold inlined)
        abbr.uleb(code++).uleb(DW_TAG_subprogram.toLong()).u8(DW_CHILDREN_yes)
        abbr.uleb(DW_AT_name.toLong()).uleb(DW_FORM_strp.toLong())
        abbr.uleb(DW_AT_ranges.toLong()).uleb(DW_FORM_sec_offset.toLong())
        abbr.uleb(0).uleb(0)

        // 3: inlined_subroutine no children, low/high addr form + call info
        abbr.uleb(code++).uleb(DW_TAG_inlined_subroutine.toLong()).u8(DW_CHILDREN_no)
        abbr.uleb(DW_AT_name.toLong()).uleb(DW_FORM_strp.toLong())
        abbr.uleb(DW_AT_low_pc.toLong()).uleb(DW_FORM_addr.toLong())
        abbr.uleb(DW_AT_high_pc.toLong()).uleb(DW_FORM_addr.toLong()) // high_pc = absolute end
        abbr.uleb(DW_AT_call_file.toLong()).uleb(DW_FORM_data2.toLong())
        abbr.uleb(DW_AT_call_line.toLong()).uleb(DW_FORM_data2.toLong())
        abbr.uleb(DW_AT_call_column.toLong()).uleb(DW_FORM_data1.toLong())
        abbr.uleb(0).uleb(0)
        // end children of subprogram handled later via null

        // 4: overlapping subprogram, no children, low/high
        abbr.uleb(code++).uleb(DW_TAG_subprogram.toLong()).u8(DW_CHILDREN_no)
        abbr.uleb(DW_AT_name.toLong()).uleb(DW_FORM_strp.toLong())
        abbr.uleb(DW_AT_low_pc.toLong()).uleb(DW_FORM_addr.toLong())
        abbr.uleb(DW_AT_high_pc.toLong()).uleb(DW_FORM_addr.toLong())
        abbr.uleb(0).uleb(0)

        // 5: zero-length subprogram
        abbr.uleb(code++).uleb(DW_TAG_subprogram.toLong()).u8(DW_CHILDREN_no)
        abbr.uleb(DW_AT_name.toLong()).uleb(DW_FORM_strp.toLong())
        abbr.uleb(DW_AT_low_pc.toLong()).uleb(DW_FORM_addr.toLong())
        abbr.uleb(DW_AT_high_pc.toLong()).uleb(DW_FORM_addr.toLong())
        abbr.uleb(0).uleb(0)

        abbr.uleb(0) // end abbrev table
        val abbrBytes = abbr.bytes()

        // ---- ranges (v4) for outer_func: two pieces, explicit base ----
        val ranges = Bin()
        val rangesOff0 = 0
        ranges.u64(-1L).u64(0L) // base address selector
        ranges.u64(FUNC_LO).u64(0x401140L)   // piece 1
        ranges.u64(0x401160L - 0L).u64(FUNC_HI) // piece 2 (base-relative)
        ranges.u64(0L).u64(0L)               // end
        // Note second piece uses absolute base 0 with offsets, same span.
        val rangesBytes = ranges.bytes()

        // ---- line program v4, two sequences, special opcodes ----
        val lineBytes = lineProgramV4()

        // ---- info ----
        val infoBody = Bin()
        infoBody.u16(4).u32(0L).u8(8) // version, abbrev offset, address size
        // root DIE (code 1)
        infoBody.uleb(1).u32(sCu.toLong()).u32(sDir.toLong())
        infoBody.u32(0L) // stmt_list offset
        infoBody.u64(BASE).u32((0x401280L - BASE)) // low_pc, high_pc length
        // subprogram code 2
        infoBody.uleb(2).u32(sOuter.toLong()).u32(rangesOff0.toLong())
        // inlined code 3
        infoBody.uleb(3).u32(sInl.toLong()).u64(INL_LO).u64(INL_HI)
        infoBody.u16(1).u16(42).u8(7) // call file/line/col
        infoBody.uleb(0) // end children of subprogram
        // overlapping code 4
        infoBody.uleb(4).u32(sOver.toLong()).u64(OVER_LO).u64(OVER_HI)
        // zero code 5
        infoBody.uleb(5).u32(sZero.toLong()).u64(ZERO_PC).u64(ZERO_PC)
        infoBody.uleb(0) // end children of CU
        val infoBytes = Bin().u32(infoBody.size.toLong()).raw(infoBody.bytes()).bytes()

        val map = linkedMapOf(
            ".debug_info" to infoBytes,
            ".debug_abbrev" to abbrBytes,
            ".debug_str" to strBytes,
            ".debug_ranges" to rangesBytes,
            ".debug_line" to lineBytes
        )
        return Sections(map)
    }

    /**
     * Two sequences. Sequence 0 covers the function body, sequence 1 a far
     * region. Special opcodes are used for most advances; one
     * DW_LNS_advance_pc / advance_line pair and const_add_pc exercise standard
     * opcodes too.
     */
    fun lineProgramV4(lineBase: Int = -5, lineRange: Int = 14, opcodeBase: Int = 13): ByteArray {
        val minInsn = 1; val defaultStmt = 1
        // standard opcode lengths for ops 1..12
        val args = intArrayOf(0,0,1,1,1,1,0,0,0,0,0,0,1)
        val body = Bin()
        body.u16(4)
        body.u8(minInsn)
        body.u8(1) // maximum_operations_per_instruction (v4)
        body.u8(defaultStmt)
        body.u8(lineBase and 0xff)
        body.u8(lineRange)
        body.u8(opcodeBase)
        for (i in 1 until opcodeBase) body.u8(args[i])
        // include dirs: comp dir(0 implicit), one entry
        body.cstr("src")
        body.cstr("")
        // files: file 0 placeholder? v4 file entries start at index 1.
        body.cstr("main.c").uleb(0).uleb(0).uleb(0)
        body.cstr("header.h").uleb(1).uleb(0).uleb(0)
        body.cstr("")

        val program = Bin()
        // sequence 0: start at FUNC_LO, file 1 (main.c), line 10 col 5
        program.u8(0); program.uleb(9); program.u8(DW_LINE_set_address); program.u64(FUNC_LO)
        program.u8(DW_LNS_set_file.toInt()).uleb(1)
        program.u8(DW_LNS_set_column.toInt()).uleb(5)
        program.u8(DW_LNS_advance_line.toInt()).sleb(9) // 1 -> 10
        special(program, opcodeBase, lineBase, lineRange, 0, 0)
        // next row at 0x401110 line 14: advance_line 4 (rem=9) then special pc=16
        program.u8(DW_LNS_advance_line.toInt()).sleb(4)
        special(program, opcodeBase, lineBase, lineRange, 16, 0)
        // row at 0x401118 line 20: advance_pc 8, advance_line 6
        program.u8(DW_LNS_advance_pc.toInt()).uleb(8)
        program.u8(DW_LNS_advance_line.toInt()).sleb(6)
        special(program, opcodeBase, lineBase, lineRange, 0, 0)
        // inlined body header.h:42:7 starts at INL_LO (0x401120)
        program.u8(DW_LNS_set_file.toInt()).uleb(2)
        program.u8(DW_LNS_set_column.toInt()).uleb(7)
        program.u8(DW_LNS_advance_pc.toInt()).uleb((INL_LO - 0x401118).toInt())
        program.u8(DW_LNS_advance_line.toInt()).sleb(22)
        special(program, opcodeBase, lineBase, lineRange, 0, 0)
        // row near inline end 0x401150 line 52
        program.u8(DW_LNS_advance_pc.toInt()).uleb((INL_HI - INL_LO).toInt())
        program.u8(DW_LNS_advance_line.toInt()).sleb(10)
        special(program, opcodeBase, lineBase, lineRange, 0, 0)
        // end sequence at function high 0x401180
        program.u8(0); program.uleb(9); program.u8(DW_LINE_set_address); program.u64(FUNC_HI)
        program.u8(0); program.uleb(1); program.u8(DW_LINE_end_sequence)


        // sequence 1 far away
        program.u8(0); program.uleb(9); program.u8(DW_LINE_set_address); program.u64(0x402000L)
        program.u8(DW_LNS_set_file.toInt()).uleb(1)
        // target line 99 from reset line 1; rem window max is 8 (line 13),
        // so advance_line to line 13 then a special with pcAdv carrying more.
        program.u8(DW_LNS_advance_line.toInt()).sleb(12) // line 13 -> rem 8
        special(program, opcodeBase, lineBase, lineRange, 0, 0) // line 13
        program.u8(DW_LNS_advance_line.toInt()).sleb(86) // -> 99, rem 0 again
        special(program, opcodeBase, lineBase, lineRange, 0, 0) // line 99
        program.u8(0); program.uleb(1); program.u8(DW_LINE_end_sequence)

        val total = body.bytes() + program.bytes()
        return Bin().u32(total.size.toLong()).raw(total).bytes()
    }

    /**
     * Emit a special opcode for a desired (pcDelta, lineDelta). Requires
     * (lineDelta - lineBase) to be representable in [0, lineRange); callers use
     * advance_line first to bring the desired delta into that window.
     */
    private fun special(b: Bin, opcodeBase: Int, lineBase: Int, lineRange: Int,
                        pcDelta: Int, lineDelta: Int) {
        val rem = lineDelta - lineBase
        require(rem in 0 until lineRange) { "special rem out of window: $rem" }
        val opcode = opcodeBase + lineRange * pcDelta + rem
        require(opcode in opcodeBase..255) { "special opcode out of byte: $opcode" }
        b.u8(opcode)
    }
}
