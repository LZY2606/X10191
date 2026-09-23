package compass.dwarf

import compass.util.*

data class LineRow(
    val address: Long,
    val endAddress: Long,
    val fileIndex: Int,
    val fileName: String,
    val line: Long,
    val column: Long,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Long,
    val discriminator: Long,
    val endSequence: Boolean,
    val sequence: Int,
    val rowIndex: Int
)

data class LineProgram(
    val sectionOffset: Long,
    val version: Int,
    val defaultIsStmt: Boolean,
    val dirs: List<String>,
    val files: List<String>,
    val rows: List<LineRow>,
    val degraded: Boolean,
    val notes: List<String>
) {
    /** Resolve the row whose half-open range [address, endAddress) contains [addr]. */
    fun rowsAt(addr: Long): List<LineRow> =
        rows.filter { !it.endSequence && addrInRange(addr, it.address, it.endAddress) }
}

private class LineState(
    var address: Long = 0L,
    var opIndex: Int = 0,
    var file: Int = 1,
    var line: Long = 1L,
    var column: Long = 0L,
    var isStmt: Boolean,
    var basicBlock: Boolean = false,
    var endSequence: Boolean = false,
    var prologueEnd: Boolean = false,
    var epilogueBegin: Boolean = false,
    var isa: Long = 0L,
    var discriminator: Long = 0L
)

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

private const val DW_LNE_END_SEQUENCE = 1
private const val DW_LNE_SET_ADDRESS = 2
private const val DW_LNE_DEFINE_FILE = 3
private const val DW_LNE_SET_DISCRIMINATOR = 4

// path entry content types (DWARF5)
private const val DW_LNCT_PATH = 1
private const val DW_LNCT_DIRECTORY_INDEX = 2

object LineProgramParser {
    private const val MAX_OPS = 2_000_000

    /** Parse one line program from .debug_line at [offset]. [compDir] is the CU DW_AT_comp_dir. */
    fun parse(
        lineSection: ByteArray,
        offset: Long,
        compDir: String?,
        sections: DwarfSections,
        cuVersion: Int,
        cuAddrSize: Int
    ): LineProgram {
        val notes = mutableListOf<String>()
        var degraded = false
        if (offset < 0 || offset >= lineSection.size) {
            return LineProgram(offset, cuVersion, true, emptyList(), emptyList(), emptyList(), true,
                listOf("DW_AT_stmt_list 偏移 ${offset.hex()} 越出 .debug_line（长度 ${lineSection.size.hex()}）"))
        }
        val c = Cursor(lineSection, offset.toInt(), lineSection.size, "debug_line")
        val unitStart = c.pos
        val unitLength = c.u32()
        val is64: Boolean
        val bodyLen: Long
        if (unitLength == 0xffffffffL) {
            is64 = true
            bodyLen = c.u64()
        } else {
            is64 = false
            bodyLen = unitLength
        }
        val unitEnd = c.pos + bodyLen.toInt()
        if (bodyLen <= 0 || unitEnd > lineSection.size) {
            return LineProgram(offset, cuVersion, true, emptyList(), emptyList(), emptyList(), true,
                listOf("行号程序 @${offset.hex()} unit_length 越界（结束 ${unitEnd.hex()} > section ${lineSection.size.hex()}）"))
        }
        c.limit.let { } // no-op
        val prog = Cursor(lineSection, c.pos, unitEnd, "line-prog@$offset")
        c.pos = unitEnd

        val version = prog.u16()
        var headerAddrSize = cuAddrSize
        if (version >= 5) {
            headerAddrSize = prog.u8()
            prog.u8() // segment_selector_size
        }
        val headerLength = prog.offset(is64)
        val headerEnd = prog.pos + headerLength.toInt()
        if (headerEnd > unitEnd) {
            return LineProgram(offset, version, true, emptyList(), emptyList(), emptyList(), true,
                listOf("行号程序 @${offset.hex()} header_length 越界"))
        }
        val hc = prog.fork(prog.pos, headerEnd)
        val minInstLen = hc.u8()
        var maxOps = 1
        if (version >= 4) maxOps = hc.u8()
        if (maxOps == 0) maxOps = 1
        val defaultIsStmt = hc.u8() != 0
        val lineBase = hc.i8()
        val lineRange = hc.u8()
        val opcodeBase = hc.u8()
        if (lineRange == 0) {
            return LineProgram(offset, version, defaultIsStmt, emptyList(), emptyList(), emptyList(), true,
                listOf("行号程序 @${offset.hex()} line_range=0，无法解码 special opcode"))
        }
        val stdLengths = IntArray(maxOf(0, opcodeBase - 1)) { hc.u8() }

        val dirs = mutableListOf<String>()
        val files = mutableListOf<String>()

        fun readPathForm(form: Int): Any? {
            when (form) {
                F.STRING -> return hc.cstring()
                F.LINE_STRP -> {
                    val off = hc.offset(is64)
                    val s = sections.lineStr?.let { readStr(it, off) }
                        ?: sections.str?.let { readStr(it, off) }
                    if (s == null) notes += "line_strp 偏移 ${off.hex()} 无法在字符串表中解析"
                    return s ?: "?"
                }
                F.STRP -> {
                    val off = hc.offset(is64)
                    val s = sections.str?.let { readStr(it, off) }
                    if (s == null) notes += "strp 偏移 ${off.hex()} 无法解析"
                    return s ?: "?"
                }
                F.DATA1 -> return hc.u8().toLong()
                F.DATA2 -> return hc.u16().toLong()
                F.DATA4 -> return hc.u32()
                F.DATA8, F.REF8 -> return hc.u64()
                F.UDATA -> return hc.uleb()
                F.SDATA -> return hc.sleb()
                else -> throw UnknownFormException(form)
            }
        }

        if (version >= 5) {
            val formats = mutableListOf<Pair<Int, Int>>()
            val dirCount = hc.u8()
            repeat(dirCount) { formats += hc.uleb().toInt() to hc.uleb().toInt() }
            val dirEntryCount = hc.uleb().toInt()
            repeat(dirEntryCount) {
                var path = "?"
                repeat(formats.size) { fi ->
                    val (type, form) = formats[fi]
                    val v = readPathForm(form)
                    if (type == DW_LNCT_PATH && v is String) path = v
                }
                dirs += path
            }
            val fileFormats = mutableListOf<Pair<Int, Int>>()
            val fileFmtCount = hc.u8()
            repeat(fileFmtCount) { fileFormats += hc.uleb().toInt() to hc.uleb().toInt() }
            val fileEntryCount = hc.uleb().toInt()
            repeat(fileEntryCount) {
                var path = "?"
                repeat(fileFormats.size) { fi ->
                    val (type, form) = fileFormats[fi]
                    val v = readPathForm(form)
                    if (type == DW_LNCT_PATH && v is String) path = v
                }
                files += path
            }
        } else {
            // DWARF 2-4: include directories, then file names; both zero-terminated.
            while (true) {
                val d = hc.cstring()
                if (d.isEmpty()) break
                dirs += d
            }
            while (true) {
                val name = hc.cstring()
                if (name.isEmpty()) break
                hc.uleb() // directory index
                hc.uleb() // mtime
                hc.uleb() // size
                files += name
            }
        }
        // DWARF <=4: file index 0 means comp dir; shift semantics handled by resolveFile.
        val fileNames: List<String> = if (version >= 5) files else listOf("<comp_dir>") + files
        if (compDir != null && dirs.isEmpty()) dirs += compDir

        // ---- state machine ----
        val body = prog.fork(headerEnd, unitEnd)
        val rawRows = mutableListOf<LineRow>()
        var state = LineState(isStmt = defaultIsStmt)
        var sequence = 0
        var opCount = 0

        fun advancePc(operationAdvance: Int) {
            val newOp = state.opIndex + operationAdvance
            state.address += (newOp / maxOps).toLong() * minInstLen.toLong()
            state.opIndex = newOp % maxOps
        }

        fun emit(endSeq: Boolean) {
            state.endSequence = endSeq
            var fname = "<unknown>"
            val idx = state.file
            if (idx in fileNames.indices) fname = fileNames[idx]
            else notes += "行号引用文件索引 $idx，但文件表只有 ${fileNames.size} 项 @${state.address.hex()}"
            rawRows += LineRow(
                address = state.address, endAddress = state.address, fileIndex = idx, fileName = fname,
                line = state.line, column = state.column, isStmt = state.isStmt,
                basicBlock = state.basicBlock, prologueEnd = state.prologueEnd,
                epilogueBegin = state.epilogueBegin, isa = state.isa,
                discriminator = state.discriminator, endSequence = endSeq,
                sequence = sequence, rowIndex = rawRows.size
            )
        }

        try {
            while (!body.exhausted()) {
                if (++opCount > MAX_OPS) {
                    notes += "行号程序操作数超过上限 $MAX_OPS，截断剩余程序"
                    degraded = true
                    break
                }
                val op = body.u8()
                when {
                    op == 0 -> {
                        val len = body.uleb().toInt()
                        val start = body.pos
                        if (len <= 0 || start + len > body.limit) {
                            notes += "扩展操作码长度 $len 越界，停止该程序"
                            degraded = true
                            break
                        }
                        val sub = body.u8()
                        when (sub) {
                            DW_LNE_END_SEQUENCE -> {
                                emit(true)
                                sequence++
                                state = LineState(isStmt = defaultIsStmt)
                            }
                            DW_LNE_SET_ADDRESS -> {
                                state.address = body.addr(headerAddrSize)
                                state.opIndex = 0
                            }
                            DW_LNE_DEFINE_FILE -> {
                                if (version < 5) {
                                    val name = body.cstring()
                                    body.uleb(); body.uleb(); body.uleb()
                                    if (fileNames is MutableList) (fileNames as MutableList<String>) += name
                                }
                            }
                            DW_LNE_SET_DISCRIMINATOR -> state.discriminator = body.uleb()
                        }
                        body.pos = start + len
                    }
                    op < opcodeBase -> {
                        when (op) {
                            DW_LNS_COPY -> { emit(false) }
                            DW_LNS_ADVANCE_PC -> advancePc(body.uleb().toInt())
                            DW_LNS_ADVANCE_LINE -> state.line += body.sleb()
                            DW_LNS_SET_FILE -> state.file = body.uleb().toInt()
                            DW_LNS_SET_COLUMN -> state.column = body.uleb()
                            DW_LNS_NEGATE_STMT -> state.isStmt = !state.isStmt
                            DW_LNS_SET_BASIC_BLOCK -> state.basicBlock = true
                            DW_LNS_CONST_ADD_PC -> {
                                val adjusted = 255 - opcodeBase
                                advancePc(adjusted / lineRange)
                            }
                            DW_LNS_FIXED_ADVANCE_PC -> {
                                state.address += body.u16().toLong()
                                state.opIndex = 0
                            }
                            DW_LNS_SET_PROLOGUE_END -> state.prologueEnd = true
                            DW_LNS_SET_EPILOGUE_BEGIN -> state.epilogueBegin = true
                            DW_LNS_SET_ISA -> state.isa = body.uleb()
                            else -> {
                                val n = stdLengths.getOrElse(op - 1) { 0 }
                                repeat(n) { body.uleb() }
                                if (op - 1 !in stdLengths.indices) notes += "未知标准操作码 $op，按长度表跳过失败，已忽略"
                            }
                        }
                        if (op == DW_LNS_COPY) {
                            state.basicBlock = false; state.prologueEnd = false
                            state.epilogueBegin = false; state.discriminator = 0
                        }
                    }
                    else -> {
                        val adjusted = op - opcodeBase
                        val opAdvance = adjusted / lineRange
                        state.line += lineBase + (adjusted % lineRange)
                        advancePc(opAdvance)
                        emit(false)
                        state.basicBlock = false; state.prologueEnd = false
                        state.epilogueBegin = false; state.discriminator = 0
                    }
                }
            }
        } catch (e: DwarfException) {
            notes += "行号程序解析中止于 0x${body.pos.toString(16)}: ${e.message}"
            degraded = true
        } catch (e: UnknownFormException) {
            notes += "行号程序路径表使用未知 form 0x${e.formCode.toString(16)}，文件名为占位符"
            degraded = true
        }

        // Compute each row's half-open end address from the following row in the same sequence.
        val rows = rawRows.toMutableList()
        for (i in rows.indices) {
            if (rows[i].endSequence) continue
            val curAddr = rows[i].address
            var end = curAddr
            for (j in i + 1 until rows.size) {
                if (rows[j].sequence != rows[i].sequence) break
                if (rows[j].address != curAddr) { end = rows[j].address; break }
            }
            rows[i] = rows[i].copy(endAddress = end)
        }
        return LineProgram(offset, version, defaultIsStmt, dirs, fileNames, rows, degraded, notes)
    }

    private fun readStr(data: ByteArray, offset: Long): String? {
        if (offset < 0 || offset >= data.size) return null
        var e = offset.toInt()
        while (e < data.size && data[e] != 0.toByte()) e++
        return String(data, offset.toInt(), e - offset.toInt(), Charsets.UTF_8)
    }
}
