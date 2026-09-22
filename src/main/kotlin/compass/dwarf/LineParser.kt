package compass.dwarf

/**
 * .debug_line 解析器，支持 DWARF4 与 DWARF5 两种头部和同一套行号状态机。
 * 输出：
 *  - files/directories（路径表）
 *  - rows：每个 emit 的矩阵行（含 end_sequence 标记行）
 *  - events：每个状态改变操作码一条事件（供页面展示状态机轨迹）
 *  - sequences：按 end_sequence 切分的地址序列（起点/终点/行数/表版本）
 */
class LineParser {
    private class Header(
        val totalLength: Int,
        val version: Int,
        val minInsnLen: Int,
        val maxOps: Int,
        val defaultIsStmt: Boolean,
        val lineBase: Int,
        val lineRange: Int,
        val opcodeBase: Int,
        val stdLengths: List<Int>,
        val dirs: MutableList<String>,
        val files: MutableList<LineFile>,
        val segmentSize: Int,
        val addressSize: Int
    )

    fun parse(
        sections: Map<String, ByteArray>,
        offset: Long,
        cuVersion: Int,
        cuAddrSize: Int,
        cuIndex: Int,
        cuDiags: MutableList<Diagnostic>
    ): LineProgram? {
        val bytes = sections[".debug_line"] ?: run {
            cuDiags += Diagnostic("ERROR", "cu:$cuIndex", "DW_AT_stmt_list 但缺 .debug_line")
            return null
        }
        val diags = mutableListOf<Diagnostic>()
        return try {
            val hdrView = ByteView(bytes, offset.toInt())
            val hc = Cursor(hdrView)
            val lenWord = hc.u32()
            val is64 = lenWord == 0xffffffffL
            val unitLen: Long = if (is64) hc.u64() else lenWord
            val start = if (is64) 12 else 4
            val bodyStart = offset.toInt() + start
            val endOff = (offset + start - (if (is64) 8 else 0) + unitLen).toInt()
            val prog = ByteView(bytes, bodyStart, endOff - bodyStart)
            val pc = Cursor(prog)
            val version = pc.u16()
            if (version !in 2..5) throw CursorException("line 版本 $version 不支持")

            var addressSize = cuAddrSize
            var segmentSize = 0
            var maxOps = 1
            if (version >= 5) {
                addressSize = pc.u8()
                segmentSize = pc.u8()
            }
            val minInsnLen = pc.u8()
            if (version >= 5) {
                // maxOps / segment 已在前面读取
            }
            val defaultIsStmtByte = pc.u8()
            val defaultIsStmt = if (version <= 3) defaultIsStmtByte.let { true } else defaultIsStmtByte != 0
            val lineBase = pc.s8()
            val lineRange = pc.u8()
            val opcodeBase = pc.u8()
            val stdLengths = (1 until opcodeBase).map { pc.u8() }

            val dirs = mutableListOf<String>()
            val files = mutableListOf<LineFile>()
            when {
                version >= 5 -> parseV5Paths(pc, prog, sections, dirs, files, addressSize, diags, cuIndex)
                else -> parseV4Paths(pc, dirs, files)
            }

            val programStart = pc.pos
            val built = runProgram(prog, programStart, version, minInsnLen, maxOps,
                defaultIsStmt, lineBase, lineRange, opcodeBase, stdLengths,
                files, segmentSize, addressSize, diags, cuIndex)
            LineProgram(
                version = version, minInstructionLength = minInsnLen, maxOpsPerInstruction = maxOps,
                defaultIsStmt = defaultIsStmt, lineBase = lineBase, lineRange = lineRange,
                opcodeBase = opcodeBase, standardOpcodeLengths = stdLengths,
                directories = dirs, files = files, segmentSelectorSize = segmentSize,
                addressSize = addressSize, rows = built.rows, events = built.events,
                sequences = built.sequences, diagnostics = diags
            )
        } catch (e: CursorException) {
            cuDiags += Diagnostic("ERROR", "cu:$cuIndex", ".debug_line@$offset 解析失败: ${e.message}")
            null
        }
    }

    /** v4：目录表与文件表均为 NUL 结尾字符串，以空串结束。 */
    private fun parseV4Paths(c: Cursor, dirs: MutableList<String>, files: MutableList<LineFile>) {
        while (true) {
            val s = readNulString(c)
            if (s.isEmpty()) break
            dirs += s
        }
        var idx = 0
        while (true) {
            val name = readNulString(c)
            if (name.isEmpty()) break
            val dirIdx = c.uleb().toInt()
            c.uleb() // mtime
            c.uleb() // size
            val dir = dirIdx.let { if (it == 0) "" else dirs.getOrNull(it - 1) ?: "" }
            files += LineFile(idx++, dir, name)
        }
    }

    private fun readNulString(c: Cursor): String {
        val s = c.pos
        val v = c.view.cstring(s)
        c.seek(s + v.toByteArray(Charsets.UTF_8).size + 1)
        return v
    }

    /** v5：directory_entry_format / file_name_entry_format，支持 LNCT path / index 常见 form。 */
    private fun parseV5Paths(
        c: Cursor, prog: ByteView, sections: Map<String, ByteArray>,
        dirs: MutableList<String>, files: MutableList<LineFile>,
        addrSize: Int, diags: MutableList<Diagnostic>, cuIndex: Int
    ) {
        val dirFormat = readEntryFormat(c)
        val dirCount = c.uleb()
        for (i in 0 until dirCount) dirs += readPathEntry(c, dirFormat, sections, diags, cuIndex, null, i) ?: ""
        val fileFormat = readEntryFormat(c)
        val fileCount = c.uleb()
        var pathIdx = 0
        for (i in 0 until fileCount) {
            var name: String? = null
            var dirIndex = 0L
            for ((content, form) in fileFormat) {
                val raw = readLineForm(c, form, addrSize)
                when (content) {
                    0x1L -> name = interpretLineString(raw, sections, diags, cuIndex) // path
                    0x2L -> dirIndex = asLong(raw) // directory index
                    0x3L -> { /* timestamp */ }
                    0x4L -> { /* size */ }
                }
            }
            val dir = if (dirIndex == 0L) "" else dirs.getOrNull((dirIndex - 1).toInt()) ?: ""
            files += LineFile(pathIdx++, dir, name ?: "<file-$i>")
        }
    }

    private fun readEntryFormat(c: Cursor): List<Pair<Long, Int>> {
        val count = c.u8()
        return (0 until count).map { c.uleb() to c.uleb().toInt() }
    }

    private fun readPathEntry(
        c: Cursor, format: List<Pair<Long, Int>>, sections: Map<String, ByteArray>,
        diags: MutableList<Diagnostic>, cuIndex: Int, @Suppress("UNUSED_PARAMETER") dummy: Any?, ordinal: Int
    ): String? {
        var result: String? = null
        for ((content, form) in format) {
            val raw = readLineForm(c, form, 4)
            if (content == 0x1L) result = interpretLineString(raw, sections, diags, cuIndex)
        }
        return result
    }

    private fun readLineForm(c: Cursor, form: Int, addrSize: Int): Any = when (form) {
        DW.FORM_STRING -> readNulString(c)
        DW.FORM_LINE_STRP -> Raw.StrPtr(-(readFixed(c, 4)) - 1)
        DW.FORM_STRP -> Raw.StrPtr(readFixed(c, 4))
        DW.FORM_UDATA, DW.FORM_REF_UDATA -> c.uleb()
        DW.FORM_DATA1 -> c.u8().toLong()
        DW.FORM_DATA2 -> c.u16().toLong()
        DW.FORM_DATA4, DW.FORM_SEC_OFFSET -> c.u32()
        DW.FORM_DATA8 -> c.u64()
        else -> throw CursorException("line 路径表不支持的 form=0x${form.toString(16)}")
    }

    private fun readFixed(c: Cursor, size: Int): Long = when (size) {
        1 -> c.u8().toLong(); 2 -> c.u16().toLong(); 4 -> c.u32(); 8 -> c.u64()
        else -> throw CursorException("bad size")
    }

    private fun interpretLineString(raw: Any, sections: Map<String, ByteArray>, diags: MutableList<Diagnostic>, cuIndex: Int): String? {
        if (raw is String) return raw
        if (raw is Raw.StrPtr) {
            val off = -raw.offset - 1
            val sec = sections[".debug_line_str"] ?: sections[".debug_str"] ?: run {
                diags += Diagnostic("ERROR", "cu:$cuIndex", "line 字符串 section 缺失"); return null
            }
            return try { ByteView(sec).cstring(off.toInt()) } catch (e: CursorException) {
                diags += Diagnostic("ERROR", "cu:$cuIndex", "line 字符串越界 off=$off"); null
            }
        }
        return raw.toString()
    }

    private fun asLong(v: Any): Long = (v as? Long) ?: 0L
}

/** 行号状态机内部状态。 */
private class LMState(
    var address: Long = 0,
    var segment: Long = 0,
    var file: Int = 1,
    var line: Int = 1,
    var column: Int = 0,
    var isStmt: Boolean,
    var basicBlock: Boolean = false,
    var endSequence: Boolean = false,
    var prologueEnd: Boolean = false,
    var isa: Int = 0,
    var discriminator: Int = 0
)

private class ProgramBuild(
    val rows: List<LineRow>,
    val events: List<LineEvent>,
    val sequences: List<LineSequence>
)

private fun LineParser.runProgram(
    prog: ByteView, start: Int, version: Int, minInsn: Int, maxOps: Int,
    defaultStmt: Boolean, lineBase: Int, lineRange: Int, opcodeBase: Int,
    stdLengths: List<Int>, dirs: List<LineFile>,
    segmentSize: Int, addrSize: Int, diags: MutableList<Diagnostic>, cuIndex: Int
): ProgramBuild {
    val c = Cursor(prog)
    c.seek(start)
    val rows = mutableListOf<LineRow>()
    val events = mutableListOf<LineEvent>()
    var order = 0
    fun reset(): LMState = LMState(isStmt = defaultStmt)
    var s = reset()
    var seqStart = 0L
    var seqSegment = 0L
    var seqRows = 0
    val sequences = mutableListOf<LineSequence>()

    fun emit(end: Boolean) {
        rows += LineRow(order, s.segment, s.address, s.file, s.line, s.column, s.isa,
            s.discriminator, s.isStmt, s.basicBlock, end, s.prologueEnd)
        seqRows++
        order++
    }

    fun event(name: String, note: String = "") {
        events += LineEvent(events.size, name, s.segment, s.address, s.file, s.line, s.column,
            s.isStmt, s.endSequence, note)
    }

    while (c.remaining > 0) {
        val op = c.u8()
        when {
            op == 0 -> {
                val extLen = c.uleb().toInt()
                val sub = c.pos
                val extOp = c.u8()
                when (extOp) {
                    DW.LNE_END_SEQUENCE -> {
                        if (version >= 5 && segmentSize > 0) s.segment = readFixed(c, segmentSize)
                        s.address = readFixed(c, addrSize)
                        s.endSequence = true
                        emit(true)
                        event("DW_LNE_end_sequence", "end=0x${java.lang.Long.toUnsignedString(s.address, 16)}")
                        sequences += LineSequence(sequences.size, s.segment, seqStart, s.address, seqRows)
                        s = reset()
                        seqRows = 0
                    }
                    DW.LNE_SET_ADDRESS -> {
                        if (version >= 5 && segmentSize > 0) s.segment = readFixed(c, segmentSize)
                        s.address = readFixed(c, addrSize)
                        seqStart = s.address
                        seqSegment = s.segment
                        event("DW_LNE_set_address", "addr=0x${java.lang.Long.toUnsignedString(s.address, 16)}")
                    }
                    DW.LNE_DEFINE_FILE -> {
                        if (version < 5) {
                            val name = readNulStringExternal(c)
                            c.uleb(); c.uleb()
                            event("DW_LNE_define_file", name)
                        }
                    }
                    DW.LNE_SET_DISCRIMINATOR -> s.discriminator = c.uleb().toInt()
                    else -> {
                        diags += Diagnostic("WARNING", "cu:$cuIndex", "未知扩展行操作码 ext=$extOp，按长度跳过")
                        event("unknown_ext_$extOp")
                    }
                }
                // 扩展操作码整体按 extLen 对齐，保证游标绝不错位
                c.seek(sub + extLen)
            }
            op < opcodeBase -> {
                val argc = stdLengths.getOrElse(op - 1) { 0 }
                when (op) {
                    DW.LN_COPY -> { emit(false); event("DW_LNS_copy"); s.basicBlock = false; s.prologueEnd = false; s.discriminator = 0 }
                    DW.LN_ADVANCE_PC -> { s.address = Util.unsignedAdd(s.address, c.uleb()); event("DW_LNS_advance_pc") }
                    DW.LN_ADVANCE_LINE -> { s.line += c.sleb().toInt(); event("DW_LNS_advance_line") }
                    DW.LN_SET_FILE -> { s.file = c.uleb().toInt(); event("DW_LNS_set_file", "file=$s.file") }
                    DW.LN_SET_COLUMN -> { s.column = c.uleb().toInt(); event("DW_LNS_set_column") }
                    DW.LN_NEGATE_STMT -> { s.isStmt = !s.isStmt; event("DW_LNS_negate_stmt") }
                    DW.LN_SET_BASIC_BLOCK -> { s.basicBlock = true; event("DW_LNS_set_basic_block") }
                    DW.LN_CONST_ADD_PC -> {
                        val adj = (255 - opcodeBase) / lineRange * minInsn * maxOps
                        s.address = Util.unsignedAdd(s.address, adj.toLong())
                        event("DW_LNS_const_add_pc")
                    }
                    DW.LN_FIXED_ADVANCE_PC -> { s.address = Util.unsignedAdd(s.address, c.u16().toLong()); event("DW_LNS_fixed_advance_pc") }
                    DW.LN_SET_PROLOGUE_END -> { s.prologueEnd = true; event("DW_LNS_set_prologue_end") }
                    0x0b -> { if (version >= 5) s.isa = c.u8() else s.isa = c.uleb().toInt(); event("DW_LNS_set_isa") }
                    else -> {
                        // 未知标准操作码：按标准操作码长度参数表跳过对应 ULEB 数
                        repeat(argc) { c.uleb() }
                        diags += Diagnostic("WARNING", "cu:$cuIndex", "未知标准行操作码 op=$op，按 arglen=$argc 跳过")
                        event("unknown_std_$op")
                    }
                }
            }
            else -> {
                val adjusted = op - opcodeBase
                val advOp = adjusted / lineRange
                val advLine = lineBase + (adjusted % lineRange)
                if (advOp != 0) s.address = Util.unsignedAdd(s.address, (advOp * minInsn * maxOps).toLong())
                s.line += advLine
                emit(false)
                event("special", "opcode=$op line+=$advLine pcAdv=$advOp")
                s.basicBlock = false; s.prologueEnd = false; s.discriminator = 0
            }
        }
    }
    if (seqRows > 0) diags += Diagnostic("WARNING", "cu:$cuIndex", "行程序列缺少 end_sequence，丢弃尾部 $seqRows 行")
    return ProgramBuild(rows, events, sequences)
}

private fun readNulStringExternal(c: Cursor): String {
    val s = c.pos
    val v = c.view.cstring(s)
    c.seek(s + v.toByteArray(Charsets.UTF_8).size + 1)
    return v
}
