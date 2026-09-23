package compass

/**
 * 标准混合场景（DWARF4）。布局：
 *
 *   CU "main.c"，stmt_list=0
 *     subprogram foo  [0x1000,0x1040)  high_pc = 常量 0x40
 *       inlined bar   [0x1010,0x1020)  call_file=1 call_line=7
 *     subprogram baz  [0x1050,0x1050)  零长度范围（只有 low_pc）
 *     subprogram ovlA [0x1200,0x1240)  high_pc = 地址形式 0x1240（重叠区域）
 *     subprogram ovlB [0x1210,0x1230)  high_pc = 常量 0x20（被 ovlA 包含、更窄）
 *     subprogram rng  DW_AT_ranges：[0x1300,0x1310) 与 [0x1400,0x1420)
 *
 *   line program 含两个 sequence：
 *     seq0: 0x1000..0x1030  main.c 第 10 行起，包含一个 special opcode 与 ADVANCE
 *     seq1: 0x1200..0x1240  main.c 第 100 行起
 */
object ScenarioFixture {

    fun buildV4(): ByteArray {
        val (strBytes, so) = strSection("main.c", "/home/demo", "foo", "bar", "baz", "ovlA", "ovlB", "rng")

        // ---- .debug_line ----
        val line = run {
            val prog = Bin()
            // sequence 0
            prog.u8(0); prog.uleb(9 + 8); prog.u8(2)          // DW_LNE_set_address
            prog.u64(0x1000)
            prog.u8(4); prog.uleb(1)                          // set_file 1
            prog.u8(5); prog.uleb(0)                          // set_column 0
            prog.u8(3); prog.sleb(9)                          // advance_line +9 (to line 10)
            prog.u8(1)                                        // copy
            // special opcode：opcodeBase=13, lineBase=-5, lineRange=14
            // adj=10 -> opAdv=0, lineDelta=10-5=5 => line 15 @ 0x1000
            prog.u8(13 + 10)
            prog.u8(2); prog.uleb(0x10)                       // advance_pc 16 -> 0x1010
            prog.u8(3); prog.sleb(-4)                         // to line 11
            prog.u8(1)                                        // copy  (内联 bar 起点 0x1010)
            prog.u8(2); prog.uleb(0x20)                       // advance_pc to 0x1030
            prog.u8(3); prog.sleb(9)                          // to line 20
            prog.u8(1)
            prog.u8(0); prog.uleb(9); prog.u8(1); prog.u64(0x1030) // end_sequence
            // sequence 1
            prog.u8(0); prog.uleb(9); prog.u8(2); prog.u64(0x1200)
            prog.u8(3); prog.sleb(99)                         // line 100
            prog.u8(1)
            prog.u8(0); prog.uleb(9); prog.u8(1); prog.u64(0x1240) // end_sequence
            // sequence 2: 零长度序列 0x1050（单 end_sequence），验证单地址序列
            prog.u8(0); prog.uleb(9); prog.u8(2); prog.u64(0x1050)
            prog.u8(3); prog.sleb(29)                         // line 30
            prog.u8(1)
            prog.u8(0); prog.uleb(9); prog.u8(1); prog.u64(0x1050)

            val dirsFiles = Bin()
            dirsFiles.str("/home/demo")
            dirsFiles.u8(0)
            dirsFiles.str("main.c"); dirsFiles.uleb(0); dirsFiles.uleb(0); dirsFiles.uleb(0)
            dirsFiles.u8(0)
            val params = Bin()
                .u8(1)                  // min_inst_length
                .u8(1)                  // default_is_stmt
                .u8((-5).and(0xff))     // line_base
                .u8(14)                 // line_range
                .u8(13)                 // opcode_base
                .bytes(byteArrayOf(0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1)) // std opcode lengths
                .build()
            val rest = Bin().bytes(params).bytes(dirsFiles.build()).build()
            val body = Bin()
                .u16(4)                 // version
                .u32(rest.size.toLong()) // header_length
            val inner = Bin().bytes(body.build()).bytes(rest).bytes(prog.build()).build()
            Bin().u32(inner.size.toLong()).bytes(inner).build()
        }

        // ---- .debug_abbrev ----
        val abbrev = abbrevSection(
            AbbrevDeclF.of(D.CU, true,
                D.NAME to D.F_STRP, D.COMP_DIR to D.F_STRP, D.LANGUAGE to D.F_DATA2, D.STMT to D.F_SECOFF),
            AbbrevDeclF.of(D.SUB, false,
                D.NAME to D.F_STRP, D.LOW to D.F_ADDR, D.HIGH to D.F_DATA8, D.DECL_FILE to D.F_DATA2, D.DECL_LINE to D.F_DATA2),
            // code3: subprogram 使用 high_pc = 地址形式（FORM_ADDR），并带 ranges
            AbbrevDeclF.of(D.SUB, false,
                D.NAME to D.F_STRP, D.LOW to D.F_ADDR, D.HIGH to D.F_ADDR, D.DECL_FILE to D.F_DATA2, D.DECL_LINE to D.F_DATA2),
            // code4: ranges 函数（无 low/high）
            AbbrevDeclF.of(D.SUB, false,
                D.NAME to D.F_STRP, D.RANGES to D.F_SECOFF, D.DECL_FILE to D.F_DATA2, D.DECL_LINE to D.F_DATA2),
            // code5: 内联子过程（抽象实例声明，无地址）
            AbbrevDeclF.of(D.SUB, false,
                D.NAME to D.F_STRP, D.INLINE to D.F_DATA1, D.DECL_FILE to D.F_DATA2, D.DECL_LINE to D.F_DATA2),
            // code6: inlined_subroutine（具体实例，带 origin 与调用点）
            AbbrevDeclF.of(D.INL, false,
                D.ORIGIN to D.F_REF4, D.LOW to D.F_ADDR, D.HIGH to D.F_DATA8,
                D.CALL_FILE to D.F_DATA2, D.CALL_LINE to D.F_DATA2)
        )

        // ---- .debug_info ----
        val info = run {
            val bodies = Bin()
            fun ustr(key: String) = bodies.u32(so[key]!!)
            // root CU DIE (abbrev code 1)
            bodies.uleb(1)
            ustr("main.c"); ustr("/home/demo"); bodies.u16(0x0001 /*C89*/); bodies.u32(0)

            // foo 0x1000..0x1040 (high_pc constant)
            bodies.uleb(2); ustr("foo"); bodies.u64(0x1000); bodies.u64(0x40); bodies.u16(1); bodies.u16(10)
            // abstract bar decl（code5）— inline=1
            val barOffsetPlaceholder = bodies.size
            bodies.uleb(5); ustr("bar"); bodies.u8(1); bodies.u16(1); bodies.u16(7)
            // concrete inlined bar 0x1010..0x1020（code6），ref4 指向 section 内绝对偏移
            val inlStart = bodies.size
            bodies.uleb(6)
            // ref4 稍后回填（需要 unit 内偏移 → section 绝对 = headerSize + offset）
            bodies.u32(0xdeadbeef)
            bodies.u64(0x1010); bodies.u64(0x10); bodies.u16(1); bodies.u16(30)
            // baz 零长度（code2，只给 low_pc 后 high_pc 仍由 abbrev 要求 → 给 0 常量更现实；
            // 但“只有 low_pc”需要独立 abbrev，这里额外加 code7）
            // 先写完 inl 的 ref4 回填
            // 零长度函数改用 code7
            bodies.uleb(7); ustr("baz"); bodies.u64(0x1050); bodies.u16(1); bodies.u16(30)
            // ovlA: high_pc 地址形式（code3）
            bodies.uleb(3); ustr("ovlA"); bodies.u64(0x1200); bodies.u64(0x1240); bodies.u16(1); bodies.u16(100)
            // ovlB: 常量形式（code2）
            bodies.uleb(2); ustr("ovlB"); bodies.u64(0x1210); bodies.u64(0x20); bodies.u16(1); bodies.u16(110)
            // rng: DW_AT_ranges offset=0（code4）
            bodies.uleb(4); ustr("rng"); bodies.u32(0); bodies.u16(1); bodies.u16(200)
            bodies.uleb(0) // end children

            val header = Bin().u16(4).u32(0).u8(8) // version, abbrev_off=0, addr_size=8
            val full = Bin().bytes(header.build()).bytes(bodies.build()).build()
            // 回填 inl 的 abstract_origin ref4
            val headerSize = header.size
            val barAbs = headerSize + barOffsetPlaceholder
            val relOff = inlStart + 1 // 跳过 uleb(6) 单字节
            for (i in 0 until 4) full[relOff + i] = ((barAbs.toLong() ushr (8 * i)) and 0xff).toByte()
            Bin().u32(full.size.toLong()).bytes(full).build()
        }

        // 需要在 abbrev 末尾补 code7（只有 low_pc 的函数）。重建 abbrev
        val abbrev2 = abbrevSection(
            AbbrevDeclF.of(D.CU, true,
                D.NAME to D.F_STRP, D.COMP_DIR to D.F_STRP, D.LANGUAGE to D.F_DATA2, D.STMT to D.F_SECOFF),
            AbbrevDeclF.of(D.SUB, false,
                D.NAME to D.F_STRP, D.LOW to D.F_ADDR, D.HIGH to D.F_DATA8, D.DECL_FILE to D.F_DATA2, D.DECL_LINE to D.F_DATA2),
            AbbrevDeclF.of(D.SUB, false,
                D.NAME to D.F_STRP, D.LOW to D.F_ADDR, D.HIGH to D.F_ADDR, D.DECL_FILE to D.F_DATA2, D.DECL_LINE to D.F_DATA2),
            AbbrevDeclF.of(D.SUB, false,
                D.NAME to D.F_STRP, D.RANGES to D.F_SECOFF, D.DECL_FILE to D.F_DATA2, D.DECL_LINE to D.F_DATA2),
            AbbrevDeclF.of(D.SUB, false,
                D.NAME to D.F_STRP, D.INLINE to D.F_DATA1, D.DECL_FILE to D.F_DATA2, D.DECL_LINE to D.F_DATA2),
            AbbrevDeclF.of(D.INL, false,
                D.ORIGIN to D.F_REF4, D.LOW to D.F_ADDR, D.HIGH to D.F_DATA8,
                D.CALL_FILE to D.F_DATA2, D.CALL_LINE to D.F_DATA2),
            AbbrevDeclF.of(D.SUB, false,
                D.NAME to D.F_STRP, D.LOW to D.F_ADDR, D.DECL_FILE to D.F_DATA2, D.DECL_LINE to D.F_DATA2)
        )

        // ---- .debug_ranges: offset 0: base 隐式=CU low_pc(无则0)；这里用显式 base ----
        val ranges = run {
            val b = Bin()
            b.u64(-1L); b.u64(0)       // base address = 0
            b.u64(0x1300); b.u64(0x1310)
            b.u64(0x1400); b.u64(0x1420)
            b.u64(0); b.u64(0)         // end
            b.build()
        }

        return TinyElf()
            .section(".debug_info", info)
            .section(".debug_abbrev", abbrev2)
            .section(".debug_line", line)
            .section(".debug_str", strBytes)
            .section(".debug_ranges", ranges)
            .build()
    }
}
