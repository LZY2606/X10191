package compass.dwarf

import compass.core.ByteCursor
import compass.core.CursorException

data class LineHeader5Entry(val contentType: Int, val form: Int)

class LineProgramParser(private val sections: DebugSections, private val formReader: FormReader) {

    /** 解析 .debug_line 中从 sectionOffset 开始的一个 line program unit。 */
    fun parseAt(sectionOffset: Long): LineProgram? {
        val c = sections.cursor(".debug_line") ?: return null
        return try {
            c.jump(sectionOffset, 0)
            parseCurrent(c)
        } catch (e: CursorException) {
            truncatedProgram(sectionOffset, 0L, 0, 5, false, 0, 0, listOf(issue(e)))
        }
    }

    /** 顺序解析整个 .debug_line（section 地图页展示全部 sequence）。 */
    fun parseAll(): List<LineProgram> {
        val c = sections.cursor(".debug_line") ?: return emptyList()
        val out = ArrayList<LineProgram>()
        c.pos = 0
        while (c.remaining() > 0) {
            val off = c.pos.toLong()
            try {
                val lp = parseCurrent(c)
                out += lp
                // 精确定位到下一 unit，容错游标已错位时也按 unit_length 推进
                c.pos = (off + if (lp.dwarf64) 12 else 4 + lp.unitLength).toInt()
            } catch (e: CursorException) {
                out += truncatedProgram(off, 0L, 0, 4, false, 0, 0, listOf(issue(e)))
                break
            }
        }
        return out
    }

    private fun issue(e: CursorException) =
        ParseIssue(ParseIssue.Severity.ERROR, "line.truncated", "line program 解析中断: ${e.message}", ".debug_line")

    private fun truncatedProgram(
        off: Long, len: Long, ver: Int, dummy: Int, dwarf64: Boolean, addrSize: Int, segSize: Int,
        issues: List<ParseIssue>
    ) = LineProgram(off, len, ver, dwarf64, addrSize, segSize, 1, 1, true, -5, 14, 13,
        emptyList(), emptyList(), emptyList(), emptyList(), issues, true)

    private fun parseCurrent(c: ByteCursor): LineProgram {
        val startPos = c.pos
        val issues = ArrayList<ParseIssue>()
        val first = c.u32()
        val dwarf64: Boolean
        val unitLength: Long
        when {
            first == 0xffffffffL -> { dwarf64 = true; unitLength = c.i64() }
            first > 0xfffffff0L -> throw CursorException("保留的 unit length: 0x${first.toString(16)}")
            else -> { dwarf64 = false; unitLength = first }
        }
        val unitEnd = c.pos - (if (dwarf64) 12 else 4) + unitLength.toInt()
        if (unitEnd > c.limit) throw CursorException("line unit 长度超出 section")
        val version = c.u16()
        var addressSize = 8
        var segmentSelectorSize = 0
        var headerLength: Long
        if (version >= 5) {
            addressSize = c.u8()
            segmentSelectorSize = c.u8()
            headerLength = if (dwarf64) c.i64() else c.u32()
        } else {
            headerLength = if (dwarf64) c.i64() else c.u32()
        }
        val minInstLen = c.u8()
        val maxOpsPerInst = if (version >= 5) c.u8() else 1
        val defaultIsStmt = c.u8() != 0
        val lineBase = c.i8()
        val lineRange = c.u8()
        val opcodeBase = c.u8()
        val stdLen = IntArray(maxOf(0, opcodeBase - 1))
        for (i in stdLen.indices) stdLen[i] = c.u8()

        val dirs = ArrayList<String>()
        val files = ArrayList<LineFile>()
        val ctx = FormContext(version, dwarf64, addressSize, startPos.toLong(), null, null, null, issues)

        if (version < 5) {
            // directories: NUL 分隔，空串结束
            while (true) {
                val s = readDirV4(c)
                if (s.isEmpty()) break
                dirs += s
            }
            // files: name(uleb dir)(uleb time)(uleb size)，name 空串结束
            var fid = 1
            while (true) {
                val name = readDirV4(c)
                if (name.isEmpty()) break
                val dirIdx = c.uleb128().toInt()
                c.uleb128(); c.uleb128() // mtime, length 丢弃
                files += LineFile(fid++, resolvePath(name, dirIdx, dirs), dirIdx)
            }
        } else {
            val directoryEntryFormatCount = c.u8()
            val dirFmt = ArrayList<LineHeader5Entry>()
            repeat(directoryEntryFormatCount) { dirFmt += LineHeader5Entry(c.u8(), c.uleb128().toInt()) }
            val directoriesCount = if (dwarf64) c.i64() else c.u32()
            repeat(directoriesCount.toInt()) {
                dirs += readPathEntry(c, dirFmt, ctx, dirs, files, ".")
            }
            val fileEntryFormatCount = c.u8()
            val fileFmt = ArrayList<LineHeader5Entry>()
            repeat(fileEntryFormatCount) { fileFmt += LineHeader5Entry(c.uleb128().toInt(), c.uleb128().toInt()) }
            val filesCount = if (dwarf64) c.i64() else c.u32()
            var fid = 0
            repeat(filesCount.toInt()) {
                var path = "?"; var dirIdx = 0
                for (e in fileFmt) {
                    val v = formReader.read(c, e.form, ctx)
                    when (e.contentType) {
                        LineContentType.PATH -> path = (v as? AttrValue.Str)?.value ?: "?"
                        LineContentType.DIRECTORY_INDEX -> dirIdx = v.asLong()?.toInt() ?: 0
                    }
                }
                files += LineFile(fid++, resolvePath(path, dirIdx, dirs), dirIdx)
            }
        }

        // header 之后到 unitEnd 是程序体（DWARF5 用 headerLength，v4 直接已读到头尾）
        val rows = ArrayList<LineRow>()
        val seqs = ArrayList<LineSequence>()
        runStateMachine(c, unitEnd, version, addressSize, segmentSelectorSize, minInstLen,
            maxOpsPerInst, defaultIsStmt, lineBase, lineRange, opcodeBase, stdLen, files, rows, seqs, issues)

        return LineProgram(startPos.toLong(), unitLength, version, dwarf64, addressSize, segmentSelectorSize,
            minInstLen, maxOpsPerInst, defaultIsStmt, lineBase, lineRange, opcodeBase,
            files, dirs, rows, seqs, issues, false)
    }

    private fun readDirV4(c: ByteCursor): String {
        val sb = StringBuilder()
        while (true) {
            val b = c.u8()
            if (b == 0) break
            sb.append(b.toInt().toChar())
        }
        return sb.toString()
    }

    private fun resolvePath(name: String, dirIdx: Int, dirs: List<String>): String {
        if (name.startsWith('/') || dirIdx == 0) return name
        val d = dirs.getOrNull(dirIdx - 1) ?: return name
        return if (d.endsWith('/')) d + name else "$d/$name"
    }

    private fun readPathEntry(
        c: ByteCursor, fmt: List<LineHeader5Entry>, ctx: FormContext,
        dirs: List<String>, files: List<LineFile>, @Suppress("UNUSED_PARAMETER") fallback: String
    ): String {
        var path: String? = null
        for (e in fmt) {
            val v = formReader.read(c, e.form, ctx)
            if (e.contentType == LineContentType.PATH) path = (v as? AttrValue.Str)?.value
        }
        return path ?: fallback
    }

    private class S(
        var seg: Long = 0, var addr: Long = 0, var file: Int = 1, var line: Int = 1,
        var col: Int = 0, var stmt: Boolean, var bb: Boolean = false, var prologue: Boolean = false,
        var epilogue: Boolean = false, var isa: Int = 0, var discr: Int = 0
    )

    @Suppress("LongParameterList")
    private fun runStateMachine(
        c: ByteCursor, unitEnd: Int, version: Int, addressSize: Int, segSize: Int,
        minInst: Int, maxOps: Int, defaultStmt: Boolean, lineBase: Int, lineRange: Int,
        opcodeBase: Int, stdLen: IntArray, files: List<LineFile>,
        rows: MutableList<LineRow>, seqs: MutableList<LineSequence>, issues: MutableList<ParseIssue>
    ) {
        var st = S(stmt = defaultStmt)
        var seqIndex = 0
        var seqStart: SegAddr? = null
        var rowCount = 0

        fun emit(endSeq: Boolean) {
            if (++rowCount > MAX_ROWS) throw CursorException("line program 行数超过上限 $MAX_ROWS")
            val fid = st.file
            val fileOk = files.getOrNull(if (version >= 5) fid else fid - 1) != null
            if (!fileOk) issues += ParseIssue(ParseIssue.Severity.WARNING, "line.bad_file",
                "行引用文件号 $fid 不存在", ".debug_line", c.pos.toLong())
            rows += LineRow(seqIndex, SegAddr(st.seg, st.addr), fid, st.line, st.col, st.stmt,
                st.bb, st.prologue, st.epilogue, st.isa, st.discr, endSeq)
            st.bb = false; st.prologue = false; st.epilogue = false; st.discr = 0
        }

        while (c.pos < unitEnd) {
            val op = c.u8()
            when {
                op == 0 -> {
                    val extLen = c.uleb128().toInt()
                    val extEnd = c.pos + extLen
                    val sub = c.u8()
                    when (sub) {
                        LineOp.EXT_END_SEQUENCE -> {
                            if (segSize > 0) {
                                if (c.pos + segSize + addressSize > extEnd) throw CursorException("DW_LNE_end_sequence 地址不足")
                                st.seg = readAddrN(c, segSize)
                            }
                            st.addr = readAddrN(c, addressSize)
                            emit(true)
                            val start = seqStart
                            if (start != null) seqs += LineSequence(seqIndex, start, SegAddr(st.seg, st.addr))
                            seqIndex++
                            st = S(stmt = defaultStmt)
                            seqStart = null
                        }
                        LineOp.EXT_SET_ADDRESS -> {
                            if (segSize > 0) st.seg = readAddrN(c, segSize)
                            st.addr = readAddrN(c, addressSize)
                        }
                        LineOp.EXT_DEFINE_FILE -> {
                            // v4 在程序体内追加文件：跳过 name/dir/mtime/size
                            skipV4String(c); c.uleb128(); c.uleb128(); c.uleb128()
                        }
                        LineOp.EXT_SET_DISCRIMINATOR -> st.discr = c.uleb128().toInt()
                        else -> { /* 未知扩展 opcode：按 extLen 安全跳过，记录 NOTICE */
                            issues += ParseIssue(ParseIssue.Severity.NOTICE, "line.unknown_extended",
                                "未知扩展 opcode $sub，按长度跳过", ".debug_line", c.pos.toLong())
                        }
                    }
                    c.pos = extEnd
                }
                op < opcodeBase -> {
                    when (op) {
                        LineOp.COPY -> {
                            if (seqStart == null) seqStart = SegAddr(st.seg, st.addr)
                            emit(false)
                        }
                        LineOp.ADVANCE_PC -> { val a = c.uleb128(); st.addr += minInst.toLong() * (maxOps.coerceAtLeast(1)) * a }
                        LineOp.ADVANCE_LINE -> st.line += c.sleb128().toInt()
                        LineOp.SET_FILE -> st.file = c.uleb128().toInt()
                        LineOp.SET_COLUMN -> st.col = c.uleb128().toInt()
                        LineOp.NEGATE_STMT -> st.stmt = !st.stmt
                        LineOp.SET_BASIC_BLOCK -> st.bb = true
                        LineOp.CONST_ADD_PC -> {
                            val adj = 255 - opcodeBase
                            st.addr += minInst.toLong() * (maxOps.coerceAtLeast(1)) * (adj / lineRange)
                        }
                        LineOp.FIXED_ADVANCE_PC -> st.addr += c.u16().toLong()
                        LineOp.SET_PROLOGUE_END -> st.prologue = true
                        LineOp.SET_ISA -> st.isa = c.uleb128().toInt()
                        else -> {
                            // 未知标准 opcode：按 header 的操作数长度表安全跳过
                            val nops = stdLen.getOrElse(op - 1) { 0 }
                            repeat(nops) { c.uleb128() }
                            issues += ParseIssue(ParseIssue.Severity.NOTICE, "line.unknown_standard",
                                "未知标准 opcode $op，跳过 $nops 个操作数", ".debug_line", c.pos.toLong())
                        }
                    }
                }
                else -> {
                    // special opcode
                    val adj = op - opcodeBase
                    val opAdvance = adj / lineRange
                    st.addr += minInst.toLong() * (maxOps.coerceAtLeast(1)) * opAdvance
                    st.line += lineBase + (adj % lineRange)
                    if (seqStart == null) seqStart = SegAddr(st.seg, st.addr)
                    emit(false)
                }
            }
        }
        if (seqStart != null) {
            issues += ParseIssue(ParseIssue.Severity.WARNING, "line.unterminated_sequence",
                "line program 结束前未见 end_sequence，丢弃未闭合 sequence", ".debug_line")
        }
    }

    private fun readAddrN(c: ByteCursor, n: Int): Long = when (n) {
        1 -> c.u8().toLong(); 2 -> c.u16().toLong(); 4 -> c.u32(); 8 -> c.i64()
        else -> throw CursorException("不支持的地址字节数 $n")
    }

    private fun skipV4String(c: ByteCursor) { while (c.u8() != 0) Unit }

    companion object { const val MAX_ROWS = 2_000_000 }
}
