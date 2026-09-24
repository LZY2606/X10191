package com.luopan.dwarf

/** line program 头信息（供 UI 展示表版本）。 */
class LineHeader(
    val offset: Int,
    val version: Int,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val directories: List<LineFile>,
    val fileNames: List<LineFile>,
)

/** 状态机的一步变化（供“line program 状态变化”视图）。 */
class LineTransition(
    val opName: String,
    val address: Long,
    val fileIdx: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val endSequence: Boolean,
)

class LineParseResult(
    val sequences: List<LineSequence>,
    val headers: List<LineHeader>,
    val transitions: List<LineTransition>,
    val diagnostics: List<Diagnostic>,
)

object LineProgramParser {
    private const val DW_LNS_COPY = 1
    private const val DW_LNS_ADVANCE_PC = 2
    private const val DW_LNS_ADVANCE_LINE = 3
    private const val DW_LNS_SET_FILE = 4
    private const val DW_LNS_SET_COLUMN = 5
    private const val DW_LNS_NEGATE_STMT = 6
    private const val DW_LNS_SET_BASIC_BLOCK = 7
    private const val DW_LNS_CONST_ADD_PC = 8
    private const val DW_LNS_FIXED_ADVANCE_PC = 9
    private const val DW_LNS_SET_PROLOGUE_END = 10
    private const val DW_LNS_SET_EPILOGUE_BEGIN = 11
    private const val DW_LNS_SET_ISA = 12

    private const val DW_LINE_PATH = 1
    private const val DW_LINE_DIRECTORY_INDEX = 2
    private const val DW_LINE_TIMESTAMP = 3
    private const val DW_LINE_SIZE = 4
    private const val DW_LINE_MD5 = 5

    private const val DW_LNE_END_SEQUENCE = 1
    private const val DW_LNE_SET_ADDRESS = 2
    private const val DW_LNE_DEFINE_FILE = 3
    private const val DW_LNE_SET_DISCRIMINATOR = 4
    private const val DW_LNE_SET_FILE = 5

    fun parseAll(sections: DwarfSections, cus: List<CompileUnit>, useDwo: Boolean): LineParseResult {
        val data = (if (useDwo) sections.lineDwo else sections.line)
            ?: return LineParseResult(emptyList(), emptyList(), emptyList(),
                listOf(Diagnostic("WARNING", "line", if (useDwo) ".debug_line.dwo missing" else ".debug_line missing")))
        val diag = mutableListOf<Diagnostic>()
        val seqs = mutableListOf<LineSequence>()
        val headers = mutableListOf<LineHeader>()
        val transitions = mutableListOf<LineTransition>()
        val seen = HashSet<Long>()
        for (cu in cus) {
            val stmt = cu.stmtList ?: continue
            if (!seen.add(stmt)) continue
            try {
                parseOne(data, stmt.toInt(), cu, sections, useDwo, seqs, headers, transitions, diag)
            } catch (ex: DwarfReadException) {
                diag.add(Diagnostic("ERROR", "line",
                    "line program at offset $stmt unreadable: ${ex.message}", cu.name))
            }
        }
        return LineParseResult(seqs, headers, transitions, diag)
    }

    private class State(
        var address: Long = 0, var segment: Long = 0, var fileIdx: Int = 1,
        var line: Int = 1, var column: Int = 0, var isStmt: Boolean = false,
        var basicBlock: Boolean = false, var endSequence: Boolean = false,
        var isa: Int = 0, var discriminator: Int = 0, var opIndex: Int = 0,
    )

    private fun parseOne(
        data: ByteArray, offset: Int, cu: CompileUnit, sections: DwarfSections,
        useDwo: Boolean, seqsOut: MutableList<LineSequence>, headersOut: MutableList<LineHeader>,
        transOut: MutableList<LineTransition>, diag: MutableList<Diagnostic>,
    ) {
        val b = Binary(data, 0, data.size)
        b.seek(offset)
        val progStart = b.pos
        val lengthField = b.u4().toLong() and 0xffffffffL
        val dwarf64: Boolean
        val unitLen: Int
        when {
            lengthField < 0xfffffff0L -> { dwarf64 = false; unitLen = lengthField.toInt() }
            lengthField == 0xffffffffL -> { dwarf64 = true; unitLen = b.u8().toInt() }
            else -> throw DwarfReadException("reserved line program length")
        }
        val offsetSize = if (dwarf64) 8 else 4
        val headerEnd = progStart + (if (dwarf64) 12 else 4) + unitLen
        if (headerEnd > b.end) throw DwarfReadException("line program overruns section")
        val version = b.u2()
        if (version !in 2..5) throw DwarfReadException("unsupported line program version $version")

        var segSel = 0
        if (version >= 5) {
            b.u1() // address_size
            segSel = b.u1()
        }
        if (dwarf64) b.uint(8) else b.u4() // header_length
        val minInsnLen = b.u1()
        var maxOps = 1
        if (version >= 4) maxOps = b.u1()
        val defaultStmt = b.u1() != 0
        val lineBase = b.s1()
        val lineRange = b.u1()
        val opcodeBase = b.u1()
        val stdArgCount = IntArray(maxOf(0, opcodeBase - 1))
        for (i in stdArgCount.indices) stdArgCount[i] = b.u1()

        val dirs = ArrayList<LineFile>()
        val files = ArrayList<LineFile>()
        val fileIndexBase: Int
        if (version < 5) {
            fileIndexBase = 1
            files.add(LineFile("", "")) // DWARF<5 文件索引 1 基
            dirs.add(LineFile("", cu.compDir ?: ""))
            while (true) {
                val d = b.cstring(); if (d.isEmpty()) break
                b.uleb(); b.uleb(); b.uleb() // dir timestamp/size ignored
                dirs.add(LineFile(d, cu.compDir ?: ""))
            }
            while (true) {
                val name = b.cstring(); if (name.isEmpty()) break
                val dirIdx = b.uleb().toInt()
                b.uleb(); b.uleb()
                val dir = dirs.getOrNull(dirIdx)?.path ?: ""
                files.add(LineFile(dir, name))
            }
        } else {
            fileIndexBase = 0
            val dirEntryFormatCount = b.u1()
            val dirFormCount = IntArray(dirEntryFormatCount)
            val dirFormList = ArrayList<Pair<Int, Int>>()
            for (i in 0 until dirEntryFormatCount) {
                val ct = b.u1(); val form = b.uleb().toInt()
                dirFormList.add(ct to form)
            }
            val dirCount = b.uleb().toInt()
            for (i in 0 until dirCount) {
                var path = ""
                for ((ct, form) in dirFormList) {
                    val v = readEntry(b, form, sections, useDwo, null)
                    if (ct == DW_LINE_PATH) path = v
                }
                dirs.add(LineFile("", path))
            }
            val fileEntryFormatCount = b.u1()
            val fileFormList = ArrayList<Pair<Int, Int>>()
            for (i in 0 until fileEntryFormatCount) {
                val ct = b.u1(); val form = b.uleb().toInt()
                fileFormList.add(ct to form)
            }
            val fileCount = b.uleb().toInt()
            for (i in 0 until fileCount) {
                var name = ""; var dirIdx = 0
                for ((ct, form) in fileFormList) {
                    val v = readEntry(b, form, sections, useDwo, null)
                    when (ct) {
                        DW_LINE_PATH -> name = v
                        DW_LINE_DIRECTORY_INDEX -> dirIdx = v.toIntOrNull() ?: 0
                    }
                }
                val dir = dirs.getOrNull(dirIdx)?.path ?: ""
                files.add(LineFile(dir, name))
            }
        }

        val header = LineHeader(offset, version, minInsnLen, maxOps, defaultStmt, lineBase, lineRange,
            opcodeBase, cu.addressSize, segSel, dirs.toList(), files.toList())
        headersOut.add(header)

        val initialFileIdx = if (version < 5) 1 else 0
        val state = State(isStmt = defaultStmt, fileIdx = initialFileIdx)
        val rows = ArrayList<LineRow>()
        fun resetState() {
            state.address = 0; state.segment = 0; state.fileIdx = initialFileIdx
            state.line = 1; state.column = 0; state.isStmt = defaultStmt
            state.basicBlock = false; state.endSequence = false; state.isa = 0
            state.discriminator = 0; state.opIndex = 0
        }
        fun emit(endSeq: Boolean, opName: String) {
            val lookupIdx = state.fileIdx - fileIndexBase
            val file = files.getOrNull(lookupIdx)
                ?: dirs.getOrNull(0)?.let { LineFile(it.path, "") }
            rows.add(LineRow(state.address, state.segment, file, state.line, state.column,
                endSeq, state.isStmt, state.isa, state.discriminator, state.opIndex))
            transOut.add(LineTransition(opName, state.address, state.fileIdx, state.line,
                state.column, state.isStmt, endSeq))
        }

        while (b.pos < headerEnd) {
            val opcode = b.u1()
            when {
                opcode == 0 -> {
                    val len = b.uleb().toInt()
                    val end = b.pos + len
                    if (end > headerEnd) throw DwarfReadException("extended opcode overruns program")
                    val sub = b.u1()
                    when (sub) {
                        DW_LNE_END_SEQUENCE -> {
                            state.endSequence = true
                            emit(true, "DW_LNE_end_sequence")
                            val startAddr = rows.firstOrNull()?.address ?: state.address
                            seqsOut.add(LineSequence(cu.name, cu.sectionOffset, version, segSel,
                                cu.addressSize, startAddr, state.address, rows.toList()))
                            rows.clear()
                            resetState()
                        }
                        DW_LNE_SET_ADDRESS -> {
                            if (segSel > 0) state.segment = b.uint(segSel)
                            state.address = b.uint(cu.addressSize)
                        }
                        DW_LNE_DEFINE_FILE -> {
                            if (version < 5) {
                                val nm = b.cstring(); b.uleb(); b.uleb(); b.uleb()
                                files.add(LineFile("", nm))
                            }
                        }
                        DW_LNE_SET_DISCRIMINATOR -> state.discriminator = b.uleb().toInt()
                        else -> b.seek(end)
                    }
                    b.seek(end)
                }
                opcode < opcodeBase -> {
                    val opName: String
                    when (opcode) {
                        DW_LNS_COPY -> { emit(false, "DW_LNS_copy"); opName = "DW_LNS_copy" }
                        DW_LNS_ADVANCE_PC -> {
                            state.address += b.uleb() * minInsnLen.toLong(); opName = "DW_LNS_advance_pc"
                        }
                        DW_LNS_ADVANCE_LINE -> { state.line += b.sleb().toInt(); opName = "DW_LNS_advance_line" }
                        DW_LNS_SET_FILE -> { state.fileIdx = b.uleb().toInt(); opName = "DW_LNS_set_file" }
                        DW_LNS_SET_COLUMN -> { state.column = b.uleb().toInt(); opName = "DW_LNS_set_column" }
                        DW_LNS_NEGATE_STMT -> { state.isStmt = !state.isStmt; opName = "DW_LNS_negate_stmt" }
                        DW_LNS_SET_BASIC_BLOCK -> { state.basicBlock = true; opName = "DW_LNS_set_basic_block" }
                        DW_LNS_CONST_ADD_PC -> {
                            state.address += ((255 - opcodeBase) / lineRange).toLong() * minInsnLen
                            opName = "DW_LNS_const_add_pc"
                        }
                        DW_LNS_FIXED_ADVANCE_PC -> {
                            state.address += b.u2().toLong() and 0xffffL; state.opIndex = 0
                            opName = "DW_LNS_fixed_advance_pc"
                        }
                        DW_LNS_SET_PROLOGUE_END -> opName = "DW_LNS_set_prologue_end"
                        DW_LNS_SET_EPILOGUE_BEGIN -> opName = "DW_LNS_set_epilogue_begin"
                        DW_LNS_SET_ISA -> { state.isa = b.uleb().toInt(); opName = "DW_LNS_set_isa" }
                        13 -> { b.u1(); opName = "DW_LNS_set_address_size" }
                        else -> {
                            // 未知标准 opcode：按头声明的参数个数跳过 uleb，游标不错位
                            val args = stdArgCount.getOrNull(opcode - 1) ?: 0
                            repeat(args) { b.uleb() }
                            opName = "DW_LNS_unknown_$opcode"
                        }
                    }
                }
                else -> {
                    val adjusted = opcode - opcodeBase
                    val advLine = lineBase + (adjusted % lineRange)
                    val advAddr = adjusted / lineRange
                    state.line += advLine
                    state.address += advAddr * minInsnLen.toLong()
                    emit(false, "special(0x%02x)".format(opcode))
                    state.basicBlock = false; state.discriminator = 0; state.opIndex = 0
                }
            }
        }
        if (rows.isNotEmpty()) {
            diag.add(Diagnostic("WARNING", "line",
                "line program at offset $offset has ${rows.size} rows without end_sequence", cu.name))
            seqsOut.add(LineSequence(cu.name, cu.sectionOffset, version, segSel,
                cu.addressSize, rows.first().address, rows.last().address, rows.toList()))
        }
    }

    /** v5 头 content descriptor 使用的 form（数据/字符串）。返回展示用字符串。 */
    private fun readEntry(
        b: Binary, form: Int, sections: DwarfSections, useDwo: Boolean, ctx: UnitContext?,
    ): String {
        return when (form) {
            DwarfForm.STRING -> b.cstring()
            DwarfForm.LINE_STRP -> {
                val data = (if (useDwo) sections.lineStrDwo else sections.lineStr)
                    ?: throw DwarfReadException("line_strp without .debug_line_str")
                val off = b.u4()
                FormDecoder.cstringAt(data, off)
            }
            DwarfForm.DATA1 -> b.u1().toString()
            DwarfForm.DATA2 -> b.u2().toString()
            DwarfForm.DATA4 -> b.u4().toString()
            DwarfForm.DATA8 -> b.u8().toString()
            DwarfForm.DATA_UDATA -> b.uleb().toString()
            DwarfForm.DATA_SDATA -> b.sleb().toString()
            else -> throw DwarfReadException("unsupported line content form 0x%x".format(form))
        }
    }

}
