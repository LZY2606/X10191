package compass.dwarf

import compass.elf.ByteReader
import compass.elf.ParseException

/**
 * .debug_line parser for DWARF v2..v5: multiple line sequences, v5 file
 * tables, segment selectors and special opcodes. Unknown standard opcodes are
 * skipped using standard_opcode_lengths, so corrupt/unknown forms cannot
 * desynchronise the cursor into bogus rows.
 */
object LinePrograms {

internal class Ctx(val sections: DebugSections, val dwarf64: Boolean)

    fun parse(sections: DebugSections, cu: CuInfo, stmtListOffset: Long): LineProgram? {
        val src = sections.line ?: sections.lineDwo ?: return null
        val startAbs = src.off + stmtListOffset
        if (stmtListOffset < 0 || stmtListOffset >= src.len) return null
        val r = ByteReader(src.data, startAbs.toInt())
        val ul = readUnitLength(r)
        val version = r.u16(true, "line version")
        if (version < 2 || version > 5) throw ParseException("不支持的 line 版本: $version")

        var addressSize = cu.addressSize
        var segmentSelectorSize = 0
        if (version >= 5) {
            addressSize = r.u8("line address_size")
            segmentSelectorSize = r.u8("line segment_selector_size")
        }
        r.u64Compat(ul.dwarf64, "header_length")
        val minInsnLen = r.u8("minimum_instruction_length")
        var maxOps = 1
        // maximum_operations_per_instruction only exists in DWARF5
        if (version >= 5) maxOps = r.u8("maximum_operations_per_instruction").coerceAtLeast(1)
        val defaultIsStmt = r.u8("default_is_stmt")
        val lineBase = r.u8("line_base").toByte().toInt()
        val lineRange = r.u8("line_range").coerceAtLeast(1)
        val opcodeBase = r.u8("opcode_base").coerceAtLeast(2)
        val stdLengths = IntArray(opcodeBase - 1) { r.u8("standard_opcode_length") }

        val directories = ArrayList<String>()
        val files = ArrayList<LineFile>()
        val ctx = Ctx(sections, ul.dwarf64)
        if (version <= 4) {
            while (true) { val d = readNulString(r) ?: break; if (d.isEmpty()) break; directories.add(d) }
            while (true) {
                val name = readNulString(r) ?: break
                if (name.isEmpty()) break
                val dir = Leb.uleb(r, "v4 dir").toInt()
                Leb.uleb(r, "v4 mtime"); Leb.uleb(r, "v4 size")
                files.add(LineFile(name, dir))
            }
        } else {
            val dirFormats = readContentFormats(r)
            val dirCount = Leb.uleb(r, "directories count").toInt()
            repeat(dirCount) { directories.add(readPathEntry(r, dirFormats, ctx)) }
            val fileFormats = readContentFormats(r)
            val fileCount = Leb.uleb(r, "file_names count").toInt()
            repeat(fileCount) {
                var path = ""; var dir = 0
                for ((content, form) in fileFormats) {
                    val v = readLineForm(r, form, ctx)
                    if (content == DW_LNCT_path) path = v.text ?: ""
                    if (content == DW_LNCT_directory_index) dir = v.num.toInt()
                }
                files.add(LineFile(path, dir))
            }
        }

        // Absolute end of this line-number unit (all cursors use file-absolute positions).
        val unitEndAbs = ul.afterLength + ul.length.toInt()
        if (System.getenv("LP_DEBUG") != null)
            println("LPDBG bodyRpos=${r.pos} startAbs=$startAbs dirs=${directories.size} files=${files.size}")
        val sequences = runStateMachine(
            r, unitEndAbs, version, addressSize, segmentSelectorSize,
            minInsnLen, maxOps, defaultIsStmt, lineBase, lineRange, opcodeBase, stdLengths
        )
        if (System.getenv("LP_DEBUG") != null)
            println("LPDBG bodyStart=${r.pos.let { it }} unitEnd=$unitEndAbs")
        return LineProgram(version, files, directories, sequences, addressSize, segmentSelectorSize)
    }

    private fun readContentFormats(r: ByteReader): List<Pair<Int, Int>> {
        val n = r.u8("entry_format_count")
        return List(n) { Leb.uleb(r, "LNCT").toInt() to Leb.uleb(r, "form").toInt() }
    }

    private fun readPathEntry(r: ByteReader, formats: List<Pair<Int, Int>>, ctx: Ctx): String {
        var path = ""
        for ((content, form) in formats) {
            val v = readLineForm(r, form, ctx)
            if (content == DW_LNCT_path) path = v.text ?: ""
        }
        return path
    }
}

private class LineFormVal(val text: String?, val num: Long)

private fun readLineForm(r: ByteReader, form: Int, ctx: LinePrograms.Ctx): LineFormVal = when (form) {
    DW_FORM_string -> LineFormVal(readNulString(r) ?: "", 0)
    DW_FORM_line_strp -> {
        val off = r.u64Compat(ctx.dwarf64, "line_strp").toInt()
        LineFormVal(ctx.sections.resolveLineString(off) ?: "", 0)
    }
    DW_FORM_strp -> {
        val off = r.u64Compat(ctx.dwarf64, "strp").toInt()
        LineFormVal(ctx.sections.resolveString(off) ?: "", 0)
    }
    DW_FORM_strx1 -> LineFormVal(null, r.u8().toLong())
    DW_FORM_strx2 -> LineFormVal(null, r.u16(true).toLong())
    DW_FORM_strx3 -> LineFormVal(null, (r.u8() or (r.u8() shl 8) or (r.u8() shl 16)).toLong() and 0xffffffL)
    DW_FORM_strx4 -> LineFormVal(null, r.u32(true))
    DW_FORM_strx, DW_FORM_udata -> LineFormVal(null, Leb.uleb(r))
    DW_FORM_data1 -> LineFormVal(null, r.u8().toLong())
    DW_FORM_data2 -> LineFormVal(null, r.u16(true).toLong())
    DW_FORM_data4, DW_FORM_sec_offset -> LineFormVal(null, r.u32(true))
    DW_FORM_data8 -> LineFormVal(null, r.u64(true))
    DW_FORM_sdata -> LineFormVal(null, Leb.sleb(r))
    DW_FORM_flag_present -> LineFormVal(null, 1)
    else -> throw ParseException("line 头未知 form=0x${form.toString(16)}, 已隔离该 unit")
}

private fun readNulString(r: ByteReader): String? {
    if (r.pos >= r.size) return null
    val start = r.pos
    while (r.pos < r.size && r.data[r.pos] != 0.toByte()) r.pos++
    if (r.pos >= r.size) return null
    val s = String(r.data, start, r.pos - start, Charsets.UTF_8)
    r.pos++
    return s
}

// ---- state machine ----

private class LState(d: Int) {
    var address = 0L; var opIndex = 0; var file = 1; var line = 1; var column = 0
    var isStmt = d != 0; var basicBlock = false; var endSequence = false
    var prologueEnd = false; var epilogueBegin = false; var isa = 0; var discriminator = 0
    fun reset(d: Int) {
        address = 0; opIndex = 0; file = 1; line = 1; column = 0
        isStmt = d != 0; basicBlock = false; endSequence = false
        prologueEnd = false; epilogueBegin = false; isa = 0; discriminator = 0
    }
    fun row() = LineRow(address, file, line, column, endSequence, isStmt, basicBlock,
        prologueEnd, epilogueBegin, isa, discriminator, opIndex)
}

private fun runStateMachine(
    r: ByteReader, bodyEnd: Int, version: Int, addressSize: Int, segmentSize: Int,
    minInsnLen: Int, maxOps: Int, defaultIsStmt: Int,
    lineBase: Int, lineRange: Int, opcodeBase: Int, stdLengths: IntArray
): List<LineSequence> {
    val st = LState(defaultIsStmt)
    val sequences = ArrayList<LineSequence>()
    var rows = ArrayList<LineRow>()
    var total = 0L

    fun append() { rows.add(st.row()); total++ }
    fun flush() { if (rows.isNotEmpty()) { sequences.add(LineSequence(rows)); rows = ArrayList() } }
    fun advance(opAdvance: Int) {
        st.address += minInsnLen.toLong() * (st.opIndex + opAdvance) / maxOps
        st.opIndex = 0
    }
    fun resetRegs() {
        st.basicBlock = false; st.prologueEnd = false; st.epilogueBegin = false; st.discriminator = 0
    }

    val end = bodyEnd.coerceAtMost(r.size)
        while (r.pos < end) {
            val opcode = r.u8("line opcode")
            if (System.getenv("LP_DEBUG") != null)
                println("  op at ${r.pos-1} = 0x${opcode.toString(16)} (opcodeBase=$opcodeBase)")
            when {
            opcode == 0 -> {
                val length = Leb.uleb(r, "ext length").toInt()
                if (System.getenv("LP_DEBUG") != null)
                    println("  ext at ${r.pos-1} len=$length end=$end")
                if (length < 1 || r.pos + length > end) {
                    if (System.getenv("LP_DEBUG") != null)
                        println("  BAD ext: rpos=${r.pos} + $length > $end")
                    throw ParseException("扩展 opcode 长度越界: $length")
                }
                val after = r.pos + length
                when (r.u8("ext opcode")) {
                    DW_LNE_end_sequence -> { st.endSequence = true; append(); flush(); st.reset(defaultIsStmt) }
                    DW_LNE_set_address -> {
                        if (segmentSize > 0) repeat(segmentSize) { r.u8() }
                        if (System.getenv("LP_DEBUG") != null)
                            println("    set_address before=${r.pos} addrSize=$addressSize")
                        st.address = r.readAddr(addressSize, "set_address"); st.opIndex = 0
                        if (System.getenv("LP_DEBUG") != null)
                            println("    set_address after=${r.pos} seekAfter=$after")
                    }
                    DW_LNE_define_file -> if (version <= 4) {
                        readNulString(r); Leb.uleb(r); Leb.uleb(r); Leb.uleb(r)
                    }
                    DW_LNE_set_discriminator -> st.discriminator = Leb.uleb(r, "disc").toInt()
                }
                r.seek(after)
            }
            opcode < opcodeBase -> when (opcode) {
                DW_LNS_copy -> { append(); resetRegs() }
                DW_LNS_advance_pc -> advance(Leb.uleb(r).toInt())
                DW_LNS_advance_line -> st.line += Leb.sleb(r).toInt()
                DW_LNS_set_file -> st.file = Leb.uleb(r).toInt()
                DW_LNS_set_column -> st.column = Leb.uleb(r).toInt()
                DW_LNS_negate_stmt -> st.isStmt = !st.isStmt
                DW_LNS_set_basic_block -> st.basicBlock = true
                DW_LNS_const_add_pc -> advance((255 - opcodeBase) / lineRange)
                DW_LNS_fixed_advance_pc -> { st.address += r.u16(true).toLong(); st.opIndex = 0 }
                DW_LNS_set_prologue_end -> st.prologueEnd = true
                DW_LNS_set_isa -> st.isa = Leb.uleb(r).toInt()
                0x0a -> if (version >= 5) st.epilogueBegin = true else skipStd(r, opcode, stdLengths)
                else -> skipStd(r, opcode, stdLengths)
            }
            else -> {
                val adj = opcode - opcodeBase
                st.line += lineBase + adj % lineRange
                advance(adj / lineRange)
                append(); resetRegs()
            }
        }
        if (total > Limits.MAX_LINE_ROWS) throw ParseException("line row 超上限")
        if (sequences.size > Limits.MAX_LINE_SEQUENCES) throw ParseException("line sequence 过多")
    }
    flush()
    return sequences
}

private fun skipStd(r: ByteReader, opcode: Int, lengths: IntArray) {
    val n = lengths.getOrElse(opcode - 1) { 0 }
    repeat(n) { Leb.uleb(r, "unknown std operand") }
}
