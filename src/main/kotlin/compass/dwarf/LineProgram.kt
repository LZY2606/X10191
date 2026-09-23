package compass.dwarf

/** DWARF line number program parser (versions 2-5, with v5 segmented-address awareness). */
class LineProgramParser(
    private val sections: DebugSections,
    private val cu: CompilationUnit,
    private val resolver: CuAttributeResolver?,
) {
    private val notes = ArrayList<String>()
    private val little = sections.littleEndian

    fun parse(stmtListOffset: Long): LineProgram? {
        val bytes = sections.get(".debug_line")
        if (bytes == null) {
            cu.notes.add("DW_AT_stmt_list present but .debug_line section is missing")
            return null
        }
        if (stmtListOffset < 0 || stmtListOffset >= bytes.size) {
            cu.notes.add("stmt_list offset 0x${stmtListOffset.toString(16)} outside .debug_line")
            return null
        }
        return try {
            val r = ByteReader(bytes, stmtListOffset.toInt(), bytes.size, little)
            val header = parseHeader(r, stmtListOffset)
            val sequences = runProgram(bytes, header)
            LineProgram(header, sequences, notes.toList())
        } catch (e: Exception) {
            cu.notes.add("line program at 0x${stmtListOffset.toString(16)} failed: ${e.message}")
            null
        }
    }

    private inner class HeaderParse(
        var version: Int = 0,
        var addressSize: Int = 8,
        var segmentSelectorSize: Int = 0,
        var minInst: Int = 1,
        var maxOps: Int = 1,
        var defaultIsStmt: Boolean = true,
        var lineBase: Int = -5,
        var lineRange: Int = 14,
        var opcodeBase: Int = 13,
        var stdLengths: IntArray = IntArray(0),
        var directories: List<String> = emptyList(),
        var files: List<LineFile> = emptyList(),
        var programStart: Int = 0,
        var programEnd: Int = 0,
    )

    private fun parseHeader(r: ByteReader, unitStart: Long): LineHeader {
        val h = HeaderParse()
        var length = r.u32()
        val is64 = length == 0xFFFFFFFFL
        if (is64) length = r.u64()
        val lengthField = if (is64) 12 else 4
        if (length <= 0 || unitStart + lengthField + length > r.end) {
            throw DwarfParseException("bad line program unit length $length")
        }
        h.programEnd = (unitStart + lengthField + length).toInt()
        h.version = r.u16()
        if (h.version < 2 || h.version > 5) throw DwarfParseException("unsupported line program version ${h.version}")
        if (h.version >= 5) {
            h.addressSize = r.u8()
            h.segmentSelectorSize = r.u8()
        }
        val headerLength = if (is64) r.u64() else r.u32()
        val headerEnd = r.pos + headerLength.toInt()
        if (headerEnd > h.programEnd) throw DwarfParseException("line header length exceeds program")
        h.minInst = r.u8()
        if (h.version >= 4) h.maxOps = r.u8() else h.maxOps = 1
        if (h.maxOps < 1) h.maxOps = 1
        h.defaultIsStmt = r.u8() != 0
        h.lineBase = r.u8().toByte().toInt()
        h.lineRange = r.u8()
        if (h.lineRange == 0) throw DwarfParseException("line_range is zero")
        h.opcodeBase = r.u8()
        h.stdLengths = IntArray(h.opcodeBase - 1) { r.u8() }
        if (h.version >= 5) {
            h.directories = parseV5Entries(r, is64, isDirectory = true).map { it.getOrNull(0) ?: "" }
            h.files = parseV5Entries(r, is64, isDirectory = false).map { spec ->
                // spec entries carry raw form values; index 0 = path, 1 = directory_index
                val name = spec.getOrNull(0) ?: "<unnamed>"
                val dirIdx = spec.getOrNull(1)?.toLongOrNull() ?: 0L
                val dirName = h.directories.getOrNull(dirIdx.toInt())
                LineFile(name, dirIdx, dirName)
            }
        } else {
            val dirs = ArrayList<String>()
            while (true) {
                if (r.pos >= headerEnd) break
                if (r.cloneAt(r.pos).u8() == 0) { r.u8(); break }
                dirs.add(r.cstring())
            }
            val files = ArrayList<LineFile>()
            while (true) {
                if (r.pos >= headerEnd) break
                if (r.cloneAt(r.pos).u8() == 0) { r.u8(); break }
                val name = r.cstring()
                val dirIdx = r.uleb()
                r.uleb() // mtime
                r.uleb() // size
                val dirName = if (dirIdx == 0L) null else dirs.getOrNull((dirIdx - 1).toInt())
                files.add(LineFile(name, dirIdx, dirName))
            }
            h.directories = dirs
            h.files = files
        }
        h.programStart = headerEnd
        return LineHeader(
            h.version, h.addressSize, h.segmentSelectorSize, h.minInst, h.maxOps,
            h.defaultIsStmt, h.lineBase, h.lineRange, h.opcodeBase, h.stdLengths,
            h.directories, h.files, h.programStart, h.programEnd,
        )
    }

    /** Parses one v5 directory/file entry table; returns entries as lists of stringified values. */
    private fun parseV5Entries(r: ByteReader, is64: Boolean, isDirectory: Boolean): List<List<String>> {
        val formatCount = r.u8()
        val formats = ArrayList<Pair<Int, Int>>()
        repeat(formatCount) {
            val content = r.uleb().toInt()
            val form = r.uleb().toInt()
            formats.add(content to form)
        }
        val count = r.uleb()
        if (count > 1_000_000) throw DwarfParseException("unreasonable v5 line table entry count $count")
        val out = ArrayList<List<String>>()
        for (i in 0 until count) {
            val values = ArrayList<String>()
            for ((content, form) in formats) {
                values.add(readV5EntryValue(r, form, is64, content))
            }
            out.add(values)
        }
        return out
    }

    private fun readV5EntryValue(r: ByteReader, form: Int, is64: Boolean, content: Int): String {
        val offsetSize = if (is64) 8 else 4
        return when (form) {
            Form.LINE_STRP -> {
                val off = r.uN(offsetSize)
                resolver?.readCString(".debug_line_str", off)
                    ?: sections.get(".debug_line_str")?.let {
                        if (off < it.size) {
                            var e = off.toInt(); while (e < it.size && it[e].toInt() != 0) e++
                            String(it, off.toInt(), e - off.toInt(), Charsets.UTF_8)
                        } else null
                    } ?: "<unresolved line_strp 0x${off.toString(16)}>"
            }
            Form.STRP -> {
                val off = r.uN(offsetSize)
                resolver?.readCString(".debug_str", off) ?: "<unresolved strp 0x${off.toString(16)}>"
            }
            Form.STRP_SUP -> { r.uN(offsetSize); "<sup>" }
            Form.STRING -> r.cstring()
            Form.STRX, Form.STRX1, Form.STRX2, Form.STRX3, Form.STRX4 -> {
                val index = when (form) {
                    Form.STRX -> r.uleb()
                    Form.STRX1 -> r.u8().toLong()
                    Form.STRX2 -> r.u16().toLong()
                    Form.STRX3 -> { val b = r.bytes(3); (b[0].toLong() and 0xFF) or ((b[1].toLong() and 0xFF) shl 8) or ((b[2].toLong() and 0xFF) shl 16) }
                    else -> r.u32()
                }
                // Resolve via the CU's str_offsets base if available.
                val table = sections.get(".debug_str_offsets")
                val base = cu.strOffsetsBase
                if (table != null && base + index * 4 + 4 <= table.size) {
                    val tr = ByteReader(table, (base + index * 4).toInt(), table.size, little)
                    val off = tr.u32()
                    resolver?.readCString(".debug_str", off) ?: "<strx $index>"
                } else "<strx $index>"
            }
            Form.DATA1 -> r.u8().toString()
            Form.DATA2 -> r.u16().toString()
            Form.DATA4 -> r.u32().toString()
            Form.DATA8 -> r.u64().toString()
            Form.UDATA -> r.uleb().toString()
            Form.SDATA -> r.sleb().toString()
            Form.DATA16 -> { r.bytes(16); "<data16>" }
            Form.BLOCK, Form.EXPRLOC -> { val n = r.uleb(); r.bytes(n.toInt()); "<block $n>" }
            Form.BLOCK1 -> { val n = r.u8(); r.bytes(n); "<block $n>" }
            Form.BLOCK2 -> { val n = r.u16(); r.bytes(n); "<block $n>" }
            Form.BLOCK4 -> { val n = r.u32(); r.bytes(n.toInt()); "<block $n>" }
            Form.SEC_OFFSET -> r.uN(offsetSize).toString()
            Form.FLAG -> r.u8().toString()
            Form.FLAG_PRESENT -> "1"
            else -> throw DwarfParseException("unsupported form 0x${form.toString(16)} in v5 line header (content $content)")
        }
    }

    private class State {
        var address: Long = 0
        var opIndex: Long = 0
        var file: Int = 1
        var line: Long = 1
        var column: Long = 0
        var isStmt: Boolean = true
        var basicBlock = false
        var endSequence = false
        var prologueEnd = false
        var epilogueBegin = false
        var isa: Long = 0
        var discriminator: Long = 0
        fun reset(defaultIsStmt: Boolean) {
            address = 0; opIndex = 0; file = 1; line = 1; column = 0
            isStmt = defaultIsStmt; basicBlock = false; endSequence = false
            prologueEnd = false; epilogueBegin = false; isa = 0; discriminator = 0
        }
    }

    private fun runProgram(bytes: ByteArray, header: LineHeader): List<LineSequence> {
        val sequences = ArrayList<LineSequence>()
        var rows = ArrayList<LineRow>()
        val state = State()
        state.isStmt = header.defaultIsStmt
        val r = ByteReader(bytes, header.programStart, header.programEnd, little)
        var sequenceIndex = 0
        var rowCount = 0

        fun appendRow(endSeq: Boolean) {
            if (rowCount >= Limits.MAX_LINE_ROWS) throw DwarfParseException("line program row limit exceeded")
            rowCount++
            rows.add(
                LineRow(
                    state.address, state.file, state.line, state.column, state.isStmt,
                    state.basicBlock, endSeq, state.prologueEnd, state.epilogueBegin,
                    state.isa, state.discriminator, state.opIndex, sequenceIndex,
                )
            )
            state.basicBlock = false
            state.prologueEnd = false
            state.epilogueBegin = false
            state.discriminator = 0
        }

        while (r.hasRemaining()) {
            val opcode = r.u8()
            if (opcode == 0) {
                // Extended opcode.
                val len = r.uleb()
                if (len > r.remaining) throw DwarfParseException("extended opcode length $len exceeds program")
                val sub = r.slice(len.toInt())
                if (!sub.hasRemaining()) continue
                when (sub.u8()) {
                    LineExt.END_SEQUENCE -> {
                        state.endSequence = true
                        appendRow(true)
                        sequences.add(LineSequence(sequenceIndex, rows))
                        rows = ArrayList()
                        sequenceIndex++
                        state.reset(header.defaultIsStmt)
                    }
                    LineExt.SET_ADDRESS -> {
                        var segment = 0L
                        if (header.segmentSelectorSize > 0 && sub.remaining >= header.segmentSelectorSize + header.addressSize) {
                            segment = sub.uN(header.segmentSelectorSize)
                        }
                        val relocatable = sub.uN(header.addressSize)
                        if (segment != 0L) notes.add("non-zero segment selector $segment in set_address; offset part used")
                        state.address = relocatable
                        state.opIndex = 0
                    }
                    LineExt.DEFINE_FILE -> {
                        notes.add("DW_LNE_define_file encountered; entry ignored (deprecated)")
                        while (sub.hasRemaining()) sub.u8()
                    }
                    LineExt.SET_DISCRIMINATOR -> {
                        if (sub.hasRemaining()) state.discriminator = sub.uleb()
                    }
                    else -> notes.add("unknown extended line opcode skipped")
                }
                continue
            }
            if (opcode < header.opcodeBase) {
                // Standard opcode.
                when (opcode) {
                    LineOp.COPY -> appendRow(false)
                    LineOp.ADVANCE_PC -> {
                        val advance = r.uleb()
                        advanceAddress(state, header, advance)
                    }
                    LineOp.ADVANCE_LINE -> state.line += r.sleb()
                    LineOp.SET_FILE -> state.file = r.uleb().toInt()
                    LineOp.SET_COLUMN -> state.column = r.uleb()
                    LineOp.NEGATE_STMT -> state.isStmt = !state.isStmt
                    LineOp.SET_BASIC_BLOCK -> state.basicBlock = true
                    LineOp.CONST_ADD_PC -> {
                        val adjusted = 255 - header.opcodeBase
                        val advance = adjusted / header.lineRange
                        advanceAddress(state, header, advance.toLong())
                    }
                    LineOp.FIXED_ADVANCE_PC -> {
                        state.address += r.u16()
                        state.opIndex = 0
                    }
                    LineOp.SET_PROLOGUE_END -> state.prologueEnd = true
                    LineOp.SET_EPILOGUE_BEGIN -> state.epilogueBegin = true
                    LineOp.SET_ISA -> state.isa = r.uleb()
                    else -> {
                        // Unknown standard opcode: skip declared operands to stay aligned.
                        val operandCount = header.standardOpcodeLengths.getOrNull(opcode - 1) ?: 0
                        repeat(operandCount) { r.uleb() }
                        notes.add("unknown standard line opcode $opcode skipped ($operandCount operands)")
                    }
                }
                continue
            }
            // Special opcode.
            val adjusted = opcode - header.opcodeBase
            val opAdvance = adjusted / header.lineRange
            advanceAddress(state, header, opAdvance.toLong())
            state.line += header.lineBase + (adjusted % header.lineRange)
            appendRow(false)
        }
        if (rows.isNotEmpty()) {
            notes.add("line program ended without DW_LNE_end_sequence; trailing rows kept as open sequence")
            sequences.add(LineSequence(sequenceIndex, rows))
        }
        return sequences
    }

    private fun advanceAddress(state: State, header: LineHeader, operationAdvance: Long) {
        state.address += header.minInstructionLength *
            ((state.opIndex + operationAdvance) / header.maxOpsPerInstruction)
        state.opIndex = (state.opIndex + operationAdvance) % header.maxOpsPerInstruction
    }
}
