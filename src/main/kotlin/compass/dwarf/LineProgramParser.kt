package compass.dwarf

import compass.BinReader

/**
 * .debug_line 解析（DWARF v2-v5）。
 * 损坏/截断数据抛 [DwarfParseError] 或记录 error 后安全停止，游标不会错位继续产生伪行。
 */
object LineProgramParser {

    private const val MAX_OPS = 200_000
    private const val MAX_ROWS = 100_000
    private const val MAX_ENTRIES = 50_000

    fun parse(d: SectionData, cuOffset: Long, fallbackAddrSize: Int): LineProgram {
        val section = d.debugLine ?: throw DwarfParseError("缺少 .debug_line section")
        val errors = mutableListOf<String>()
        val traces = mutableListOf<StateTrace>()
        val sequences = mutableListOf<LineSequence>()
        val start = cuOffset.toIntSafe()
        val r = BinReader(section, start)
        val unitLen = r.u4().toLong() and 0xffffffffL
        val dwarf64: Boolean
        val headerEnd: Int
        if (unitLen == 0xffffffffL) {
            dwarf64 = true
            headerEnd = (start + 12L + r.u8()).toIntSafe()
        } else {
            dwarf64 = false
            headerEnd = (start + 4L + unitLen).toIntSafe()
        }
        if (headerEnd > section.size || headerEnd < r.pos)
            throw DwarfParseError(".debug_line 单元长度非法")
        val version = r.u2()
        if (version !in 2..5) throw DwarfParseError(".debug_line 未知版本 $version")

        var addressSize = fallbackAddrSize
        var segmentSelectorSize = 0
        if (version >= 5) {
            addressSize = r.u1()
            segmentSelectorSize = r.u1()
        }
        val headerLength = readLen(r, dwarf64)
        val programStart = (r.pos + headerLength).toIntSafe()
        if (programStart > headerEnd) throw DwarfParseError(".debug_line header_length 越过单元末尾")

        val minInsnLen = r.u1()
        var maxOpsPerInsn = 1
        if (version >= 5) maxOpsPerInsn = r.u1().coerceAtLeast(1)
        val defaultIsStmt = r.u1() != 0
        val lineBase = r.u1().toByte().toInt()
        val lineRange = r.u1()
        if (lineRange == 0) throw DwarfParseError(".debug_line line_range 为 0")
        val opcodeBase = r.u1()
        if (opcodeBase < 2) throw DwarfParseError(".debug_line opcode_base 非法: $opcodeBase")
        val stdOpcodeLengths = IntArray(opcodeBase - 1)
        for (i in stdOpcodeLengths.indices) stdOpcodeLengths[i] = r.u1()

        val directories = mutableListOf<String>()
        val files = mutableListOf<LineFileEntry>()
        if (version <= 4) parseV4Tables(r, section, directories, files)
        else parseV5Tables(r, d, directories, files)
        if (r.pos > programStart) errors.add(".debug_line 文件表超过 header_length")
        r.seek(programStart)

        val ctx = ExecCtx(
            d, r, headerEnd, version, minInsnLen, maxOpsPerInsn, defaultIsStmt,
            lineBase, lineRange, opcodeBase, stdOpcodeLengths,
            addressSize, segmentSelectorSize, directories, files,
            sequences, traces, errors
        )
        runProgram(ctx)

        return LineProgram(
            version = version,
            tableVersion = if (version >= 5) LineTableVersion.DWARF5 else LineTableVersion.DWARF2_4,
            cuOffset = cuOffset,
            headerLength = headerLength,
            minInstructionLength = minInsnLen,
            maxOpsPerInstruction = maxOpsPerInsn,
            defaultIsStmt = defaultIsStmt,
            lineBase = lineBase,
            lineRange = lineRange,
            opcodeBase = opcodeBase,
            addressSize = addressSize,
            segmentSelectorSize = segmentSelectorSize,
            directories = directories.toList(),
            files = files.toList(),
            sequences = sequences.mapIndexed { i, s -> s.copy(index = i) },
            traces = traces.toList(),
            errors = errors.toList()
        )
    }

    private fun readLen(r: BinReader, dwarf64: Boolean): Long =
        if (dwarf64) r.u8() else r.u4().toLong() and 0xffffffffL

    internal fun Long.toIntSafe(): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseError("长度超出 32 位范围: $this")
        return toInt()
    }

    private fun parseV4Tables(
        r: BinReader, line: ByteArray, dirs: MutableList<String>, files: MutableList<LineFileEntry>
    ) {
        while (true) {
            val s = readInlineCString(r, line)
            if (s.isEmpty()) break
            if (dirs.size >= MAX_ENTRIES) throw DwarfParseError("include_directories 过多")
            dirs.add(s)
        }
        var id = 1L
        while (true) {
            val name = readInlineCString(r, line)
            if (name.isEmpty()) break
            if (files.size >= MAX_ENTRIES) throw DwarfParseError("file_names 过多")
            val dirIdx = r.uleb128().toLong()
            r.uleb128(); r.uleb128() // mtime, length
            files.add(LineFileEntry(id++, name, dirIdx, null))
        }
    }

    private fun readInlineCString(r: BinReader, section: ByteArray): String {
        val start = r.pos
        var end = start
        while (end < section.size && section[end].toInt() != 0) end++
        if (end >= section.size) throw DwarfParseError("行表字符串未终止")
        val s = String(section, start, end - start, Charsets.UTF_8)
        r.seek(end + 1)
        return s
    }
}

// ---------- DWARF 5 目录/文件表 ----------

private const val DW_LNCT_path = 1
private const val DW_LNCT_directory_index = 2
private const val DW_LNCT_timestamp = 3
private const val DW_LNCT_size = 4
private const val DW_LNCT_MD5 = 5

private fun parseV5Tables(
    r: BinReader, d: SectionData, dirs: MutableList<String>, files: MutableList<LineFileEntry>
) {
    val dirFormatCount = r.u1()
    if (dirFormatCount > 16) throw DwarfParseError("directory_entry_format_count 过大")
    val dirFormats = ArrayList<Pair<Int, Int>>(dirFormatCount)
    repeat(dirFormatCount) { dirFormats.add(r.uleb128().toInt() to r.uleb128().toInt()) }
    val dirsCount = r.uleb128().toLong()
    if (dirsCount > MAX_ENTRIES) throw DwarfParseError("directories 数量过大")
    dirs.add("")
    for (i in 0 until dirsCount) {
        var path = ""
        for ((ct, form) in dirFormats) {
            if (ct == DW_LNCT_path) path = readPathValue(r, d, form)
            else skipTableForm(r, form)
        }
        dirs.add(path)
    }

    val fileFormatCount = r.u1()
    if (fileFormatCount > 16) throw DwarfParseError("file_name_entry_format_count 过大")
    val fileFormats = ArrayList<Pair<Int, Int>>(fileFormatCount)
    repeat(fileFormatCount) { fileFormats.add(r.uleb128().toInt() to r.uleb128().toInt()) }
    val fileCount = r.uleb128().toLong()
    if (fileCount > MAX_ENTRIES) throw DwarfParseError("file_names 数量过大")
    var id = 0L
    for (i in 0 until fileCount) {
        var name = ""
        var dirIdx = 0L
        var md5: String? = null
        for ((ct, form) in fileFormats) {
            when (ct) {
                DW_LNCT_path -> name = readPathValue(r, d, form)
                DW_LNCT_directory_index -> dirIdx = readIndex(r, form)
                DW_LNCT_MD5 -> if (form == DW_FORM_data16) {
                    r.require(16); md5 = r.bytes(16).joinToString("") { "%02x".format(it) }
                } else skipTableForm(r, form)
                else -> skipTableForm(r, form)
            }
        }
        files.add(LineFileEntry(++id, name, dirIdx, md5))
    }
}

private fun readPathValue(r: BinReader, d: SectionData, form: Int): String = when (form) {
    DW_FORM_string -> readTableCString(r)
    DW_FORM_line_strp -> {
        val off = r.u4().toLong() and 0xffffffffL
        d.readString(d.debugLineStr, off) ?: ("<line_str+0x${off.toString(16)}?>")
    }
    DW_FORM_strp -> {
        val off = r.u4().toLong() and 0xffffffffL
        d.readString(d.debugStr, off) ?: ("<str+0x${off.toString(16)}?>")
    }
    DW_FORM_strx, DW_FORM_strx1, DW_FORM_strx2, DW_FORM_strx3, DW_FORM_strx4 ->
        d.resolveStrx(readIndex(r, form), 0L, false) ?: "<strx?>"
    else -> throw DwarfParseError("路径使用不支持的 form 0x${form.toString(16)}")
}

private fun skipTableForm(r: BinReader, form: Int) {
    when (form) {
        DW_FORM_string -> readTableCString(r)
        DW_FORM_line_strp, DW_FORM_strp, DW_FORM_data4, DW_FORM_sec_offset -> r.pos += 4
        DW_FORM_data8, DW_FORM_data16 -> r.pos += if (form == DW_FORM_data16) 16 else 8
        DW_FORM_data1 -> r.pos += 1
        DW_FORM_data2 -> r.pos += 2
        DW_FORM_udata -> r.uleb128()
        DW_FORM_strx, DW_FORM_strx1, DW_FORM_strx2, DW_FORM_strx3, DW_FORM_strx4,
        DW_FORM_addrx, DW_FORM_addrx1, DW_FORM_addrx2, DW_FORM_addrx3, DW_FORM_addrx4 ->
            readIndex(r, form)
        else -> throw DwarfParseError("v5 文件表未知 form 0x${form.toString(16)}，无法安全跳过")
    }
}

private fun readTableCString(r: BinReader): String {
    val start = r.pos
    while (r.pos < r.size && r.data[r.pos].toInt() != 0) r.pos++
    if (r.pos >= r.size) throw DwarfParseError("v5 表字符串未终止")
    val s = String(r.data, start, r.pos - start, Charsets.UTF_8)
    r.pos++
    return s
}

// ---------- 状态机 ----------

private class ExecCtx(
    val d: SectionData,
    val r: BinReader,
    val end: Int,
    val version: Int,
    val minInsnLen: Int,
    val maxOpsPerInsn: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val stdOpcodeLengths: IntArray,
    val addressSize: Int,
    val segmentSize: Int,
    val dirs: List<String>,
    val files: List<LineFileEntry>,
    val sequences: MutableList<LineSequence>,
    val traces: MutableList<StateTrace>,
    val errors: MutableList<String>
)

private class LineState(var isStmtDefault: Boolean) {
    var address = 0L
    var segment = 0L
    var file = 1L
    var line = 1L
    var column = 0L
    var isStmt = isStmtDefault
    var basicBlock = false
    var endSequence = false
    var prologueEnd = false
    var epilogueBegin = false
    var isa = 0L
    var discriminator = 0L
}

private fun runProgram(ctx: ExecCtx) {
    val r = ctx.r
    var state = LineState(ctx.defaultIsStmt)
    var rows = mutableListOf<LineRow>()
    var seqStart = 0L
    var seqSegment = 0L
    var step = 0

    fun reset() {
        state = LineState(ctx.defaultIsStmt)
        rows = mutableListOf()
    }

    fun fileName(id: Long): Pair<String?, String?> {
        if (ctx.version <= 4) {
            val f = ctx.files.firstOrNull { it.id == id }
            val dir = f?.dirIndex?.let { if (it == 0L) null else ctx.dirs.getOrNull((it - 1).toInt()) }
            return f?.name to dir
        }
        val f = ctx.files.getOrNull((id - 1).toInt())
        val dir = f?.dirIndex?.let { ctx.dirs.getOrNull(it.toInt()) }
        return f?.name to dir
    }

    fun emitRow(opName: String) {
        if (rows.size >= MAX_ROWS) throw DwarfParseError("line rows 过多")
        val (name, dir) = fileName(state.file)
        rows.add(
            LineRow(
                address = state.address, segment = state.segment,
                file = name, fileId = state.file, directory = dir,
                line = state.line.toInt(), column = state.column.toInt(),
                endSequence = state.endSequence, isa = state.isa,
                discriminator = state.discriminator
            )
        )
        ctx.traces.add(
            StateTrace(
                step = step++, opcode = opName,
                address = "0x${state.address.toString(16)}",
                file = name, line = state.line.toInt(),
                column = state.column.toInt(), emitted = true
            )
        )
        state.basicBlock = false
        state.prologueEnd = false
        state.epilogueBegin = false
        state.discriminator = 0
    }

    while (r.pos < ctx.end) {
        if (step > MAX_OPS) {
            ctx.errors.add("line program 操作数超过上限 $MAX_OPS，安全停止")
            break
        }
        val op = r.u1()
        when {
            op == 0 -> {
                val len = r.uleb128().toInt()
                if (len <= 0) { ctx.errors.add("DW_LNE 长度为 0，停止"); break }
                if (r.pos + len > ctx.end) { ctx.errors.add("DW_LNE 越过单元末尾，停止"); break }
                val eop = r.u1()
                val operandLen = len - 1
                when (eop) {
                    1 -> { // DW_LNE_end_sequence
                        state.endSequence = true
                        emitRow("DW_LNE_end_sequence")
                        if (rows.isNotEmpty()) {
                            ctx.sequences.add(
                                LineSequence(
                                    index = ctx.sequences.size, startAddress = seqStart,
                                    endAddress = state.address, section = seqSegment, rows = rows.toList()
                                )
                            )
                        }
                        reset()
                    }
                    2 -> { // DW_LNE_set_address
                        if (ctx.segmentSize > 0) {
                            state.segment = readN(r, ctx.segmentSize)
                            state.address = readN(r, operandLen - ctx.segmentSize)
                        } else {
                            state.address = readN(r, operandLen)
                        }
                        seqStart = state.address
                        seqSegment = state.segment
                    }
                    3 -> { // DW_LNE_define_file (v4)
                        // name, dir, mtime, len — name 是 inline C 字符串
                        val s0 = r.pos
                        while (r.pos < ctx.end && r.data[r.pos].toInt() != 0) r.pos++
                        r.pos++
                        r.uleb128(); r.uleb128(); r.uleb128()
                    }
                    4 -> { // DW_LNE_set_discriminator
                        state.discriminator = r.uleb128().toLong()
                    }
                    else -> r.pos += operandLen
                }
            }
            op < ctx.opcodeBase -> {
                when (op) {
                    1 -> { // DW_LNS_copy
                        emitRow("DW_LNS_copy")
                    }
                    2 -> { // DW_LNS_advance_pc
                        val a = r.uleb128().toLong()
                        state.address += a * ctx.minInsnLen / ctx.maxOpsPerInsn
                    }
                    3 -> state.line = r.uleb128().toLong() // DW_LNS_advance_line
                    4 -> state.file = r.uleb128().toLong() // DW_LNS_set_file
                    5 -> state.column = r.uleb128().toLong() // DW_LNS_set_column
                    6 -> state.isStmt = !state.isStmt // DW_LNS_negate_stmt
                    7 -> state.basicBlock = true // DW_LNS_set_basic_block
                    8 -> { // DW_LNS_const_add_pc
                        val opAdvance = (255 - ctx.opcodeBase) / ctx.lineRange
                        state.address += opAdvance.toLong() * ctx.minInsnLen / ctx.maxOpsPerInsn
                    }
                    9 -> { // DW_LNS_fixed_advance_pc: uhalf operand
                        state.address += r.u2().toLong()
                    }
                    10 -> state.prologueEnd = true // DW_LNS_set_prologue_end
                    11 -> state.epilogueBegin = true // DW_LNS_set_epilogue_begin
                    12 -> state.isa = r.uleb128().toLong() // DW_LNS_set_isa
                    else -> {
                        val argCount = ctx.stdOpcodeLengths.getOrNull(op - 1)
                        if (argCount == null) {
                            ctx.errors.add("未知标准 opcode=$op 超出 opcode_base，无法跳过，停止该程序")
                            break
                        }
                        // 标准 opcode 的操作数在 v2-v5 中均为 LEB128
                        repeat(argCount) { r.uleb128() }
                    }
                }
            }
            else -> { // special opcode
                val adjusted = op - ctx.opcodeBase
                val opAdvance = adjusted / ctx.lineRange
                state.address += opAdvance.toLong() * ctx.minInsnLen / ctx.maxOpsPerInsn
                state.line += (ctx.lineBase + adjusted % ctx.lineRange).toLong()
                emitRow("special($op)")
            }
        }
    }
}
