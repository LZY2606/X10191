package compass.fixture

import compass.dwarf.FORM
import compass.dwarf.LNE
import compass.dwarf.LNS
import compass.dwarf.RLE
import compass.dwarf.DW

object DemoFixtures {
    const val A_MAIN_LOW = 0x1000L; const val A_MAIN_HIGH = 0x1040L
    const val A_HELPER_LOW = 0x2000L; const val A_HELPER_HIGH = 0x2030L
    const val B_FAST_LOW = 0x3000L; const val B_FAST_HIGH = 0x3080L
    const val B_INLINE_LOW = 0x3020L; const val B_INLINE_HIGH = 0x3060L
    const val B_OVERLAP_LOW = 0x3030L; const val B_OVERLAP_HIGH = 0x3050L
    const val C_EMPTY_LOW = 0x4000L
    const val ADDR_IN_MAIN = 0x1010L
    const val ADDR_IN_INLINE = 0x3028L
    const val ADDR_IN_OVERLAP = 0x3040L
    const val ADDR_BETWEEN_SEQ = 0x1900L

    private const val MAIN_C = "main.c"; private const val UTIL_CPP = "util.cpp"
    private const val SKEL_C = "skel.c"; private const val BAD_C = "corrupted.c"

    private fun DwarfBuf.ext(op: Int, block: DwarfBuf.() -> Unit) {
        val body = DwarfBuf().apply { u1b(op); block() }.bytes()
        ulebB(body.size.toLong()); bytesB(body)
    }
    private fun DwarfBuf.setAddr(a: Long, seg: Long = 0L, segSize: Int = 0) {
        ext(LNE.set_address) { if (segSize > 0) u8b(seg); u8b(a) }
    }
    private fun DwarfBuf.endSeq(a: Long) { ext(LNE.end_sequence) { u8b(a) } }
    private fun DwarfBuf.std(op: Int) = u1b(op)
    private fun DwarfBuf.special(opAdv: Int, lineAdv: Int) {
        val op = 13 + opAdv * 14 + (lineAdv + 5)
        require(op in 13..255) { "special opcode 越界 $op" }; u1b(op)
    }

    private fun lineHdrCommon(hdr: DwarfBuf) {
        hdr.u1b(1); hdr.u1b(1); hdr.u1b(-5 and 0xff); hdr.u1b(14); hdr.u1b(13)
        listOf(0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1).forEach { hdr.u1b(it) }
    }

    private fun lineV4(file: String, segSize: Int = 0, block: DwarfBuf.() -> Unit): ByteArray {
        val prog = DwarfBuf().apply(block).bytes()
        val hdr = DwarfBuf().apply { u2b(4); u1b(1); u1b(1); u1b(-5 and 0xff); u1b(14); u1b(13) }
        // version, minimum_instruction_length, default_is_stmt, line_base, line_range, opcode_base
        listOf(0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1).forEach { hdr.u1b(it) }
        hdr.strB("/work"); hdr.strB("")
        hdr.strB(file); hdr.ulebB(0); hdr.ulebB(0); hdr.ulebB(0)
        val payload = hdr.bytes() + prog
        return DwarfBuf().apply { u4b(payload.size); bytesB(payload) }.bytes()
    }

    private fun lineV5(file: String, segSize: Int = 0, block: DwarfBuf.() -> Unit): Pair<ByteArray, ByteArray> {
        val prog = DwarfBuf().apply(block).bytes()
        val hdr = DwarfBuf()
        hdr.u1b(1); hdr.u1b(1); hdr.u1b(1); hdr.u1b(-5 and 0xff); hdr.u1b(14); hdr.u1b(13)
        listOf(0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1).forEach { hdr.u1b(it) }
        // directories: count-format=1, LNCT_path(1)/line_strp(0x1f), count=1, off 0
        hdr.u1b(1); hdr.ulebB(1); hdr.ulebB(FORM.line_strp.toLong()); hdr.ulebB(1); hdr.u4b(0)
        // files: format=1, count=1, name line_strp 偏移 = "/work\0" 长度
        hdr.u1b(1); hdr.ulebB(1); hdr.ulebB(FORM.line_strp.toLong()); hdr.ulebB(1)
        val dirStr = "/work"; val off = dirStr.length + 1
        hdr.u4b(off)
        val programHeader = hdr.bytes()
        val head = DwarfBuf().apply {
            u2b(5); u1b(1); u1b(8); u1b(segSize); u4b(programHeader.size)
        }.bytes() + programHeader + prog
        val unit = DwarfBuf().apply { u4b(head.size); bytesB(head) }.bytes()
        val lineStr = DwarfBuf().apply { strB("/work"); strB(file) }.bytes()
        return unit to lineStr
    }

    fun mainLine(): ByteArray = lineV4(MAIN_C) {
        // 所有 operation advance 保持 <14，必要时用 advance_pc 补齐
        setAddr(A_MAIN_LOW)
        std(LNS.set_file); ulebB(0); std(LNS.set_column); ulebB(4); std(LNS.copy) // 0x1000 main.c:1
        special(1, 9)                      // 0x1001:10
        std(LNS.advance_line); ulebB(2)    // line 12
        std(LNS.advance_pc); ulebB(14)     // 0x100f
        std(LNS.copy)                      // 0x100f:12
        special(1, 1)                      // 0x1010:13 <- ADDR_IN_MAIN
        std(LNS.advance_pc); ulebB(0x2e)   // 跳到 0x103e
        special(0, 0)                      // 0x103e:13
        endSeq(A_MAIN_HIGH)                // 0x1040
        setAddr(A_HELPER_LOW)
        std(LNS.copy)                      // 0x2000
        special(3, 20)                     // 0x2003:33
        std(LNS.advance_pc); ulebB(0x2c)   // 0x202f
        std(LNS.copy)
        endSeq(A_HELPER_HIGH)              // 0x2030
    }

    fun utilLine(): Pair<ByteArray, ByteArray> = lineV5(UTIL_CPP) {
        setAddr(B_FAST_LOW)
        std(LNS.set_file); ulebB(0); std(LNS.copy)        // 0x3000 util.cpp:1
        special(0x20, 4)                                   // 0x3020:5
        std(LNS.set_prologue_end)
        special(7, 10)                                     // 0x3027:15
        special(1, 2)                                      // 0x3028:17 <- ADDR_IN_INLINE
        special(7, 0)                                      // 0x302f
        special(0x10, 13)                                  // 0x303f:30 <- ADDR_IN_OVERLAP 落到此行
        special(0x10, 0)                                   // 0x304f
        special(0x30, 0)                                   // 0x307f
        endSeq(B_FAST_HIGH)
    }

    fun skelLine(): Pair<ByteArray, ByteArray> = lineV5(SKEL_C) {
        setAddr(C_EMPTY_LOW)
        std(LNS.set_file); ulebB(0); std(LNS.copy)
        special(4, 40)
        endSeq(0x4040)
    }

    fun segmented(): ByteArray = lineV4("seg.c", segSize = 8) {
        setAddr(0x5000, seg = 0x2, segSize = 8)
        std(LNS.copy)
        special(2, 3)
        endSeq(0x5020)
    }

    private fun abbrevTable(entries: List<Triple<Long, Int, List<Pair<Int, Int>>>>, hasChildren: Set<Long> = emptySet()): ByteArray {
        val b = DwarfBuf()
        for ((code, tag, attrs) in entries) {
            b.ulebB(code); b.ulebB(tag.toLong()); b.u1b(if (code in hasChildren) 1 else 0)
            for ((at, form) in attrs) { b.ulebB(at.toLong()); b.ulebB(form.toLong()) }
            b.ulebB(0); b.ulebB(0)
        }
        b.ulebB(0)
        return b.bytes()
    }

    private data class BuiltCu(val info: ByteArray, val abbrev: ByteArray, val abbrevOff: Long, val stmtOff: Long)

    private fun cuMain(stmtOff: Long): BuiltCu {
        val abbrev = abbrevTable(listOf(
            Triple(1, DW.TAG_compile_unit, listOf(
                DW.AT_name to FORM.string, DW.AT_comp_dir to FORM.string,
                DW.AT_stmt_list to FORM.sec_offset, DW.AT_low_pc to FORM.addr)),
            Triple(2, DW.TAG_subprogram, listOf(
                DW.AT_name to FORM.string, DW.AT_low_pc to FORM.addr, DW.AT_high_pc to FORM.data8)),
            Triple(3, DW.TAG_subprogram, listOf(
                DW.AT_name to FORM.string, DW.AT_low_pc to FORM.addr, DW.AT_high_pc to FORM.addr)),
            Triple(4, DW.TAG_inlined_subroutine, listOf(
                DW.AT_abstract_origin to FORM.ref4, DW.AT_low_pc to FORM.addr, DW.AT_high_pc to FORM.data8,
                DW.AT_call_file to FORM.data2, DW.AT_call_line to FORM.data2))
        ), hasChildren = setOf(1))
        val die = DwarfBuf()
        die.ulebB(1)
        die.strB(MAIN_C); die.strB("/work"); die.u4b(stmtOff.toInt()); die.u8b(A_MAIN_LOW)
        // main: high_pc 为常量（size 形式）
        die.ulebB(2); die.strB("main"); die.u8b(A_MAIN_LOW); die.u8b(A_MAIN_HIGH - A_MAIN_LOW)
        // helper: high_pc 为地址形式
        die.ulebB(3); die.strB("helper"); die.u8b(A_HELPER_LOW); die.u8b(A_HELPER_HIGH)
        // 一个内联节点，abstract_origin 指向越界地址（用于越界引用检测）
        die.ulebB(4); die.u4b(0xdeadbeef.toInt()); die.u8b(A_HELPER_LOW + 4); die.u8b(8L)
        die.u2b(1); die.u2b(50)
        die.ulebB(0) // 结束 CU 子节点
        die.ulebB(0) // 结束根
        val header = DwarfBuf().apply { u2b(4); u4b(0); u1b(8) }
        val body = header.bytes() + die.bytes()
        val info = DwarfBuf().apply { u4b(body.size); bytesB(body) }.bytes()
        return BuiltCu(info, abbrev, 0L, stmtOff)
    }

    private fun cuUtil(stmtOff: Long, rngOff: Long): BuiltCu {
        val abbrev = abbrevTable(listOf(
            Triple(1, DW.TAG_compile_unit, listOf(
                DW.AT_name to FORM.string, DW.AT_comp_dir to FORM.string,
                DW.AT_stmt_list to FORM.sec_offset, DW.AT_low_pc to FORM.addr)),
            Triple(2, DW.TAG_subprogram, listOf(
                DW.AT_name to FORM.string, DW.AT_low_pc to FORM.addr, DW.AT_high_pc to FORM.data8)),
            Triple(3, DW.TAG_inlined_subroutine, listOf(
                DW.AT_name to FORM.string, DW.AT_low_pc to FORM.addr, DW.AT_high_pc to FORM.data8,
                DW.AT_call_file to FORM.data2, DW.AT_call_line to FORM.data2)),
            Triple(4, DW.TAG_subprogram, listOf(
                DW.AT_name to FORM.string, DW.AT_ranges to FORM.sec_offset))
        ), hasChildren = setOf(1, 2))
        val die = DwarfBuf()
        die.ulebB(1)
        die.strB(UTIL_CPP); die.strB("/work"); die.u4b(stmtOff.toInt()); die.u8b(B_FAST_LOW)
        // fast: 包含内联子例程
        die.ulebB(2); die.strB("fast"); die.u8b(B_FAST_LOW); die.u8b(B_FAST_HIGH - B_FAST_LOW)
        die.ulebB(3); die.strB("tiny_inline"); die.u8b(B_INLINE_LOW); die.u8b(B_INLINE_HIGH - B_INLINE_LOW)
        die.u2b(1); die.u2b(6)
        die.ulebB(0) // fast children end
        // overlapper：通过 .debug_rnglists 的 start_length 条目，与 tiny_inline 重叠
        die.ulebB(4); die.strB("overlapper"); die.u4b(rngOff.toInt())
        die.ulebB(0) // root end
        val header = DwarfBuf().apply {
            u2b(5); u1b(1); u1b(8); u4b(0)
        }
        val body = header.bytes() + die.bytes()
        val info = DwarfBuf().apply { u4b(body.size); bytesB(body) }.bytes()
        return BuiltCu(info, abbrev, 0L, stmtOff)
    }

    private fun cuSkel(stmtOff: Long): BuiltCu {
        val abbrev = abbrevTable(listOf(
            Triple(1, 0x4a /* skeleton_unit */, listOf(
                DW.AT_name to FORM.string, DW.AT_comp_dir to FORM.string,
                DW.AT_stmt_list to FORM.sec_offset, DW.AT_low_pc to FORM.addr,
                0x2013 to FORM.data8, DW.AT_dwo_name to FORM.string)),
            Triple(2, DW.TAG_subprogram, listOf(
                DW.AT_name to FORM.string, DW.AT_low_pc to FORM.addr, DW.AT_high_pc to FORM.data8))
        ), hasChildren = setOf(1))
        val die = DwarfBuf()
        die.ulebB(1)
        die.strB(SKEL_C); die.strB("/work"); die.u4b(stmtOff.toInt()); die.u8b(C_EMPTY_LOW)
        die.u8b(0x1122334455667788L)
        die.strB("skel.dwo")
        // 零长度范围：high_pc const = 0
        die.ulebB(2); die.strB("empty_fn"); die.u8b(C_EMPTY_LOW); die.u8b(0L)
        die.ulebB(0); die.ulebB(0)
        val header = DwarfBuf().apply { u2b(5); u1b(4 /*DW_UT_skeleton*/); u1b(8); u4b(0) }
        val body = header.bytes() + die.bytes()
        val info = DwarfBuf().apply { u4b(body.size); bytesB(body) }.bytes()
        return BuiltCu(info, abbrev, 0L, stmtOff)
    }

    private fun cuCorrupted(stmtOff: Long): BuiltCu {
        // abbrev: subprogram 使用未知 form 0x7e（解析器不可能认识）
        val abbrev = abbrevTable(listOf(
            Triple(1, DW.TAG_compile_unit, listOf(
                DW.AT_name to FORM.string, DW.AT_stmt_list to FORM.sec_offset)),
            Triple(2, DW.TAG_subprogram, listOf(
                DW.AT_name to FORM.string, 0x7e to 0x7e))
        ), hasChildren = setOf(1))
        val die = DwarfBuf()
        die.ulebB(1); die.strB(BAD_C); die.u4b(stmtOff.toInt())
        die.ulebB(2); die.strB("ghost")
        die.u4b(0xaaaaaaaaL.toInt()) // 未知 form 的“伪操作数”——解析器不得据此继续
        die.ulebB(0); die.ulebB(0)
        val header = DwarfBuf().apply { u2b(4); u4b(0); u1b(8) }
        val body = header.bytes() + die.bytes()
        val info = DwarfBuf().apply { u4b(body.size); bytesB(body) }.bytes()
        return BuiltCu(info, abbrev, 0L, stmtOff)
    }

    private fun rngLists(): ByteArray {
        // header + 单个 list（offset 0 即 header 起点）：
        // base_address(0x6)=0x3000, offset_pair(0x4): 0x30..0x50, end
        val list = DwarfBuf().apply {
            u1b(RLE.base_address); u8b(B_FAST_LOW)
            u1b(RLE.offset_pair); ulebB(0x30); ulebB(0x20) // [0x3030,0x3050)
            u1b(RLE.end_of_list)
        }.bytes()
        val header = DwarfBuf().apply {
            u2b(5); u1b(8); u1b(0); u4b(0); u4b(0)
        }.bytes()
        val body = header + list
        return DwarfBuf().apply { u4b(body.size); bytesB(body) }.bytes()
    }

    /** 构建完整多场景 ELF 字节。返回字节 + 可直接查询的相对地址提示。 */
    fun buildFull(): ByteArray {
        val lineMain = mainLine()
        val (lineUtil, lineStrUtil) = utilLine()
        val (lineSkel, lineStrSkel) = skelLine()
        val segLine = segmented()
        val debugLine = lineMain + lineUtil + lineSkel + segLine
        val lineMainOff = 0L
        val lineUtilOff = lineMain.size.toLong()
        val lineSkelOff = lineUtilOff + lineUtil.size
        // lineStr：util 的串表放偏移 0，skel 的串表紧随其后（各自独立 line_strp 基址按 fixture 设定）
        val debugLineStr = lineStrUtil + lineStrSkel

        val rng = rngLists()

        // 先构造 CU（stmtOff 暂定），再拼接 .debug_abbrev 得到 abbrevOff，再回填重造
        // 简化：每个 CU 有自己的 abbrev 表，依次排布
        val cMain0 = cuMain(lineMainOff)
        val cUtil0 = cuUtil(lineUtilOff, 0L)
        val cSkel0 = cuSkel(lineSkelOff)
        val cBad0 = cuCorrupted(0L)

        val abbrevSizes = listOf(cMain0.abbrev.size, cUtil0.abbrev.size, cSkel0.abbrev.size, cBad0.abbrev.size)
        val abbrevOffsets = LongArray(4)
        run { var acc = 0L; for (i in abbrevSizes.indices) { abbrevOffsets[i] = acc; acc += abbrevSizes[i].toLong() } }
        val debugAbbrev = cMain0.abbrev + cUtil0.abbrev + cSkel0.abbrev + cBad0.abbrev

        // 用真实 abbrev 偏移重建
        fun rebuild(cu: BuiltCu, abbrevOff: Long, stmtOff: Long, v5: Boolean, skel: Boolean): ByteArray {
            // unit header 里的 abbrev_offset 位于：4(len)+2(ver)+ (v5? 2:0)
            val bytes = cu.info.copyOf()
            val p = 4 + 2 + (if (v5) 2 else 0)
            bytes[p] = (abbrevOff and 0xff).toByte()
            bytes[p + 1] = ((abbrevOff ushr 8) and 0xff).toByte()
            bytes[p + 2] = ((abbrevOff ushr 16) and 0xff).toByte()
            bytes[p + 3] = ((abbrevOff ushr 24) and 0xff).toByte()
            // stmt_list：root DIE 前两个属性之后。直接在整段中找到旧 4 字节 stmtOff 模式替换更稳妥：
        return patchStmtOff(bytes, cu.stmtOff, stmtOff)
        }

        val cuMainR = rebuild(cMain0, abbrevOffsets[0], lineMainOff, false, false)
        val cuUtilR = rebuild(cUtil0, abbrevOffsets[1], lineUtilOff, true, false)
        val cuSkelR = rebuild(cSkel0, abbrevOffsets[2], lineSkelOff, true, true)
        val cuBadR = rebuild(cBad0, abbrevOffsets[3], 0L, false, false)
        val debugInfo = cuMainR + cuUtilR + cuSkelR + cuBadR

        val debugStr = DwarfBuf().apply { strB("") }.bytes()

        return FixtureBuilder()
            .section(".debug_info", debugInfo)
            .section(".debug_abbrev", debugAbbrev)
            .section(".debug_line", debugLine)
            .section(".debug_line_str", debugLineStr)
            .section(".debug_str", debugStr)
            .section(".debug_rnglists", rng)
            .build()
    }

    private fun patchStmtOff(info: ByteArray, old: Long, new: Long): ByteArray {
        // 在 CU 体内找 old 的 4 字节小端模式（跳过 unit header），替换为 new。
        val target = byteArrayOf((old and 0xff).toByte(), ((old ushr 8) and 0xff).toByte(),
            ((old ushr 16) and 0xff).toByte(), ((old ushr 24) and 0xff).toByte())
        val rep = byteArrayOf((new and 0xff).toByte(), ((new ushr 8) and 0xff).toByte(),
            ((new ushr 16) and 0xff).toByte(), ((new ushr 24) and 0xff).toByte())
        var idx = -1
        outer@ for (i in 4 until info.size - 4) {
            for (j in 0..3) if (info[i + j] != target[j]) continue@outer
            idx = i; break
        }
        if (idx < 0) return info
        System.arraycopy(rep, 0, info, idx, 4)
        return info
    }

    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
}
