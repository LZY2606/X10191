package compass.dwarf

import compass.elf.Cursor
import compass.elf.SliceOutOfBoundsException
import compass.elf.sleb128
import compass.elf.uleb128

/** A file/directory entry from the line program header. */
data class LineFile(val name: String, val dirIndex: Int, val timestamp: Long, val size: Long, val md5: String?)

data class LineRow(
    val address: ULong,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val endSequence: Boolean,
    val isa: Int,
    val discriminator: Int,
    val prologueEnd: Boolean,
    val opIndex: Int,
)

data class LineSequence(
    val index: Int,
    val rows: List<LineRow>,
    val startAddress: ULong,
    val endAddress: ULong,
)

data class LineProgram(
    val cuVersion: Int,
    val tableVersion: Int,
    val files: List<LineFile>,
    val directories: List<String>,
    val sequences: List<LineSequence>,
    /** Every state-machine transition, for the browser "state changes" view. */
    val trace: List<TraceEvent>,
    val minimumInstructionLength: Int,
    val maximumOperationsPerInstruction: Int,
    val defaultIsStatement: Boolean,
)

data class TraceEvent(
    val address: ULong,
    val file: Int,
    val line: Int,
    val column: Int,
    val emitted: Boolean,
    val endSequence: Boolean,
    val opcode: String,
    val opIndex: Int,
)

class LineProgramParser(private val data: DwarfData) {

    fun parse(stmtListOffset: Long, cuVersion: Int, isDwo: Boolean = false): LineProgram? {
        val bytes = if (isDwo) data.debugLineDwo ?: data.debugLine else data.debugLine
        if (bytes == null) {
            data.warnings += ".debug_line missing for stmt_list=$stmtListOffset"
            return null
        }
        if (stmtListOffset < 0 || stmtListOffset >= bytes.size) {
            data.warnings += "stmt_list offset $stmtListOffset out of .debug_line"
            return null
        }
        return try {
            parseTableAt(bytes, stmtListOffset.toInt(), cuVersion)
        } catch (e: SliceOutOfBoundsException) {
            data.warnings += "line program truncated at $stmtListOffset: ${e.message}"
            null
        } catch (e: DwarfParseException) {
            data.warnings += "line program unparseable at $stmtListOffset: ${e.message}"
            null
        }
    }

    private fun parseTableAt(bytes: ByteArray, start: Int, cuVersion: Int): LineProgram {
        val c = Cursor(bytes, start, bytes.size - start, data.littleEndian)
        val lengthField = c.u32()
        val is64 = lengthField == 0xFFFFFFFFL
        val unitLength = if (is64) c.u64().toLong() else lengthField
        val endExclusive = start + (if (is64) 12 else 4) + unitLength
        if (unitLength <= 0 || endExclusive > bytes.size) {
            throw DwarfParseException("line program length out of bounds")
        }
        val version = c.u16().toInt()
        if (version !in 2..5) throw DwarfParseException("unsupported line version $version")

        var addressSize = cuVersion.let { 8 }
        if (version >= 5) {
            addressSize = c.u8()
            c.u8() // segment_selector_size (unsupported beyond skipping)
        }
        val prologueLength = if (is64) c.u32() else c.u32()
        val prologueStart = c.offset
        val minInstrLen = c.u8()
        val maxOps = if (version >= 4) c.u8().coerceAtLeast(1) else 1
        val defaultIsStmt = c.u8() == 1
        val lineBase = c.u8().toInt().toByte().toInt()
        val lineRange = c.u8().coerceAtLeast(1)
        val opcodeBase = c.u8().coerceAtLeast(2)
        val standardOpcodeLengths = IntArray(opcodeBase - 1)
        for (i in standardOpcodeLengths.indices) standardOpcodeLengths[i] = c.u8()

        val directories = ArrayList<String>()
        val files = ArrayList<LineFile>()
        if (version <= 4) {
            while (true) {
                val s = c.zeroString()
                if (s.isEmpty()) break
                directories.add(s)
            }
            while (true) {
                val namePos = c.offset
                val name = c.zeroString()
                if (name.isEmpty()) break
                val dir = c.uleb128().toInt()
                val mtime = c.uleb128().toLong()
                val size = c.uleb128().toLong()
                files.add(LineFile(name, dir, mtime, size, null))
            }
        } else {
            parseV5Entries(c) { name, _, _ -> directories.add(name) }
            parseV5Entries(c) { name, dirIndex, extra ->
                files.add(LineFile(name, dirIndex, extra.timestamp, extra.size, extra.md5))
            }
        }

        return execute(c, endExclusive.toInt(), cuVersion, version, files, directories,
            minInstrLen, maxOps, defaultIsStmt, lineBase, lineRange,
            opcodeBase, standardOpcodeLengths, addressSize)
    }

    private class V5Extra(var timestamp: Long = 0, var size: Long = 0, var md5: String? = null)

    private fun parseV5Entries(c: Cursor, emit: (name: String, dirIndex: Int, extra: V5Extra) -> Unit) {
        val formatCount = c.u8()
        val formats = ArrayList<Pair<Int, Int>>()
        repeat(formatCount) { formats.add(c.u16().toInt() to c.u16().toInt()) }
        val count = c.uleb128().toInt()
        repeat(count) {
            var name = ""
            var dirIndex = 0
            val extra = V5Extra()
            for ((contentType, form) in formats) {
                val value = readHeaderForm(c, form)
                when (contentType) {
                    LineContentType.PATH -> if (value is FormValue.Str) name = value.v
                    LineContentType.DIRECTORY_INDEX -> dirIndex = (value as? FormValue.Number)?.v?.toInt() ?: 0
                    LineContentType.TIMESTAMP -> extra.timestamp = (value as? FormValue.Number)?.v ?: 0L
                    LineContentType.SIZE -> extra.size = (value as? FormValue.Number)?.v ?: 0L
                    LineContentType.MD5 -> if (value is FormValue.Block) {
                        extra.md5 = value.bytes.joinToString("") { "%02x".format(it) }
                    }
                }
            }
            emit(name, dirIndex, extra)
        }
    }

    private fun readHeaderForm(c: Cursor, form: Int): FormValue = when (form) {
        Form.STRING -> FormValue.Str(c.zeroString())
        Form.LINE_STRP -> {
            val off = c.u32()
            data.readString(data.debugLineStr, off.toInt())?.let { FormValue.Str(it) }
                ?: FormValue.Unknown(form, 4)
        }
        Form.DATA1 -> FormValue.Number(c.u8().toLong())
        Form.DATA2 -> FormValue.Number(c.u16().toLong())
        Form.DATA4 -> FormValue.Number(c.u32())
        Form.DATA8 -> FormValue.Number(c.u64().toLong())
        Form.UDATA -> FormValue.Number(c.uleb128().toLong())
        else -> {
            val n = when (form) {
                Form.BLOCK1 -> c.u8()
                Form.BLOCK2 -> c.u16()
                Form.BLOCK4 -> c.u32().toInt()
                Form.BLOCK -> c.uleb128().toInt()
                else -> throw DwarfParseException("unsupported line header form 0x${form.toString(16)}")
            }
            FormValue.Block(c.bytes(n))
        }
    }

    @Suppress("UNUSED_PARAMETER")
    private fun execute(
        c: Cursor,
        end: Int,
        cuVersion: Int,
        tableVersion: Int,
        files: List<LineFile>,
        directories: List<String>,
        minInstrLen: Int,
        maxOps: Int,
        defaultStmt: Boolean,
        lineBase: Int,
        lineRange: Int,
        opcodeBase: Int,
        stdLengths: IntArray,
        addressSize: Int,
    ): LineProgram {
        val rows = ArrayList<LineRow>()
        val sequences = ArrayList<LineSequence>()
        val trace = ArrayList<TraceEvent>()

        var address = 0UL
        var file = 1
        var line = 1
        var column = 0
        var basicBlock = false
        var isStmt = defaultStmt
        var endSequence = false
        var prologueEnd = false
        var isa = 0
        var discriminator = 0
        var opIndex = 0
        var seqStartRow = 0
        var seqStartAddr = 0UL

        fun reset() {
            address = 0UL; file = 1; line = 1; column = 0
            basicBlock = false; endSequence = false; prologueEnd = false; isStmt = defaultStmt
            isa = 0; discriminator = 0; opIndex = 0
        }

        fun advanceAddress(operationAdvance: Int) {
            address += (minInstrLen * ((opIndex + operationAdvance) / maxOps)).toULong()
            opIndex = (opIndex + operationAdvance) % maxOps
        }

        fun emitRow(opcode: String) {
            val row = LineRow(address, file, line, column, endSequence, isa, discriminator, prologueEnd, opIndex)
            rows.add(row)
            trace.add(TraceEvent(address, file, line, column, true, endSequence, opcode, opIndex))
            if (endSequence) {
                val seqRows = rows.subList(seqStartRow, rows.size).toList()
                sequences.add(LineSequence(sequences.size, seqRows, seqStartAddr, address))
                seqStartRow = rows.size
                reset()
            } else {
                basicBlock = false; prologueEnd = false; discriminator = 0; opIndex = 0
            }
        }

        var guard = 0
        while (c.base + c.offset < end) {
            if (++guard > MAX_OPCODES) throw DwarfParseException("line opcode limit exceeded")
            val opcode = c.u8()
            if (opcode == 0) {
                val length = c.uleb128().toInt()
                if (length <= 0) throw DwarfParseException("bad extended opcode length")
                val bodyEnd = c.offset + length - 1
                val sub = c.u8()
                when (sub) {
                    0x01 -> address = when (addressSize) {
                        1 -> c.u8().toULong(); 2 -> c.u16().toULong()
                        4 -> c.u32().toULong(); else -> c.u64()
                    }
                    0x02 -> {
                        endSequence = true
                        emitRow("DW_LNE_end_sequence")
                    }
                    0x04 -> {
                        // DW_LNE_define_file (v4): name, dir uleb, mtime uleb, size uleb
                        val name = c.zeroString()
                        val dir = c.uleb128().toInt()
                        c.uleb128(); c.uleb128()
                        trace.add(TraceEvent(address, dir, line, column, false, false,
                            "DW_LNE_define_file($name)", opIndex))
                    }
                    0x05 -> address += c.sleb128().toULong()
                    else -> c.bytes((bodyEnd - c.offset).coerceAtLeast(0))
                }
                // Align to declared extended-opcode body end.
                if (c.offset < bodyEnd) c.bytes(bodyEnd - c.offset)
            } else if (opcode < opcodeBase) {
                val label = "DW_LNS_$opcode"
                when (opcode) {
                    1 -> Unit // copy
                    2 -> advanceAddress(c.uleb128().toInt()) // advance_pc
                    3 -> line += c.sleb128().toInt() // advance_line
                    4 -> file = c.uleb128().toInt() // set_file
                    5 -> column = c.uleb128().toInt() // set_column
                    6 -> isStmt = !isStmt // negate_stmt
                    7 -> basicBlock = true // set_basic_block
                    8 -> advanceAddress((255 - opcodeBase) / lineRange) // const_add_pc
                    9 -> {
                        // fixed_advance_pc: uhalf instruction delta, resets op_index
                        address += c.u16().toULong()
                        opIndex = 0
                    }
                    10 -> isa = c.uleb128().toInt() // set_isa
                    12 -> if (tableVersion >= 5) prologueEnd = true else Unit // set_prologue_end
                    13 -> if (tableVersion >= 5) discriminator = c.uleb128().toInt() else Unit // set_discriminator
                    else -> {
                        val operands = stdLengths.getOrElse(opcode - 1) { 0 }
                        repeat(operands) { c.uleb128() }
                    }
                }
                trace.add(TraceEvent(address, file, line, column, false, false, label, opIndex))
            } else {
                val adjusted = opcode - opcodeBase
                advanceAddress(adjusted / lineRange)
                line += lineBase + adjusted % lineRange
                if (seqStartRow == rows.size && sequences.isEmpty()) seqStartAddr = address
                emitRow("special($opcode)")
            }
            if (sequences.isEmpty() && rows.isEmpty()) seqStartAddr = address
        }

        return LineProgram(cuVersion, tableVersion, files, directories, sequences, trace,
            minInstrLen, maxOps, defaultStmt)
    }

    companion object {
        const val MAX_OPCODES = 1_000_000
    }
}
