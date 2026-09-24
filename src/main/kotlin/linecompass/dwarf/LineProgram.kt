package linecompass.dwarf

/**
 * DWARF 2/3/4 and 5 line-number program decoder. Produces one
 * [LineSequence] per DW_LNE_end_sequence, preserving zero-length sequences
 * (start == end) so the UI can show them while address matching excludes
 * them. Unknown standard opcodes are skipped by their declared argument
 * count; unknown extended opcodes are skipped by their length, so the cursor
 * never desynchronises.
 */
object LineProgram {
    // standard opcodes
    private const val OP_COPY = 1
    private const val OP_ADVANCE_PC = 2
    private const val OP_LINE = 3
    private const val OP_FILE = 4
    private const val OP_SET_COLUMN = 5
    private const val OP_NEGATE_STMT = 6
    private const val OP_SET_BASIC_BLOCK = 7
    private const val OP_CONST_ADD_PC = 8
    private const val OP_FIXED_ADVANCE_PC = 9
    private const val OP_SET_PROLOGUE_END = 10
    private const val OP_SET_ISA = 11

    fun parseAll(sections: SectionBundle, maxRowsPerSeq: Int = 200_000): List<LineSequence> {
        val data = sections.get(".debug_line") ?: return emptyList()
        val out = ArrayList<LineSequence>()
        val section = BoundedReader(data, 0, data.size, "debug_line")
        while (section.remaining > 0) {
            val unitStart = section.pos
            try {
                val seq = parseOne(section, sections, maxRowsPerSeq)
                out.addAll(seq)
            } catch (e: DwarfFormatException) {
                // Keep what preceded the corrupt program; stop scanning the section.
                break
            }
            if (section.pos <= unitStart) {
                // Defensive: a corrupt length could stall the loop.
                section.skip(1)
            }
        }
        return out
    }

    private fun parseOne(
        section: BoundedReader, sections: SectionBundle, maxRows: Int
    ): List<LineSequence> {
        val len = readInitialLength(section)
        val r = BoundedReader(
            section.data, len.start, len.end - len.start, "line-program",
            if (len.is64bit) 8 else 4
        )
        val version = r.u16()
        if (version < 2 || version > 5) throw DwarfFormatException("unsupported line program version $version")

        var segSize = 0
        if (version >= 5) {
            r.u8() // address_size
            segSize = r.u8() // segment_selector_size
        }
        if (version >= 4) r.u32() // header_length (prologue_length)
        else r.u32() // prologue_length (same encoding)

        val minInsnLen = r.u8()
        val maxOpsPerInsn = if (version >= 4) r.u8() else 1
        val defaultIsStmt = r.u8()
        val lineBase = r.s8()
        val lineRange = r.u8()
        if (lineRange == 0) throw DwarfFormatException("line_range == 0")
        val opcodeBase = r.u8()
        val stdArgCount = IntArray(opcodeBase) { if (it == 0) 0 else r.u8() }
        val directories = ArrayList<String>()
        val files = ArrayList<LineFile>()

        if (version < 5) {
            // include_directories
            while (true) {
                val s = r.cString()
                if (s.isEmpty()) break
                directories.add(s)
            }
            // file_names: name, dir idx (ULEB), time, size
            while (true) {
                val name = r.cString()
                if (name.isEmpty()) break
                val dir = r.uleb().toInt()
                r.uleb(); r.uleb()
                files.add(LineFile(name, dir))
            }
        } else {
            val dirFormatCount = r.u8()
            val dirFormats = ArrayList<Pair<Int, Int>>()
            repeat(dirFormatCount) { dirFormats.add(r.uleb().toInt() to r.uleb().toInt()) }
            val dirsCount = r.uleb().toInt()
            if (dirsCount > 1_000_000) throw DwarfFormatException("absurd directory count $dirsCount")
            repeat(dirsCount) {
                var path = ""
                var index = 0
                for ((content, form) in dirFormats) {
                    val v = readHeaderForm(r, form, sections)
                    when (content) {
                        LineContent.PATH -> path = v.asString ?: ""
                        LineContent.DIRECTORY_INDEX -> index = v.asLong?.toInt() ?: 0
                    }
                }
                directories.add(path)
            }
            val fileFormatCount = r.u8()
            val fileFormats = ArrayList<Pair<Int, Int>>()
            repeat(fileFormatCount) { fileFormats.add(r.uleb().toInt() to r.uleb().toInt()) }
            val filesCount = r.uleb().toInt()
            if (filesCount > 5_000_000) throw DwarfFormatException("absurd file count $filesCount")
            repeat(filesCount) {
                var name = ""
                var dir = 0
                var md5: ByteArray? = null
                for ((content, form) in fileFormats) {
                    val v = readHeaderForm(r, form, sections)
                    when (content) {
                        LineContent.PATH -> name = v.asString ?: ""
                        LineContent.DIRECTORY_INDEX -> dir = v.asLong?.toInt() ?: 0
                        LineContent.MD5 -> md5 = v.asBytes
                    }
                }
                files.add(LineFile(name, dir, md5))
            }
        }

        // ---- state machine ----
        val sequences = ArrayList<LineSequence>()
        var rows = ArrayList<LineRow>()
        var rowCount = 0
        val s = LineState(defaultIsStmt != 0)

        fun emit(endSeq: Boolean) {
            rows.add(
                LineRow(
                    s.address, s.file, s.line, s.column, endSeq, s.prologueEnd,
                    s.isStmt, s.isa, s.discriminator, s.opIndex
                )
            )
        }

        fun closeSequence() {
            val end = s.address
            val start = rows.filter { !it.endSequence }.minOfOrNull { it.address } ?: end
            sequences.add(
                LineSequence(
                    start, end, version, r.addressSize, segSize,
                    ArrayList(rows), ArrayList(files), ArrayList(directories), cuName = ""
                )
            )
            rows = ArrayList()
            s.reset(defaultIsStmt != 0)
        }

        while (r.remaining > 0) {
            if (++rowCount > maxRows) throw DwarfFormatException("line program exceeds $maxRows rows")
            val opcode = r.u8()
            when {
                opcode == 0 -> { // extended
                    val insnLen = r.uleb().toInt()
                    if (insnLen == 0) throw DwarfFormatException("zero-length extended opcode")
                    val sub = r.u8()
                    when (sub) {
                        1 -> { } // DW_LNE_end_sequence
                        2 -> { // set_address
                            s.address = if (r.addressSize == 4) r.u32() else r.u64()
                            s.opIndex = 0
                        }
                        3 -> { // define_file (v2-4)
                            val name = r.cString()
                            val dir = r.uleb().toInt()
                            r.uleb(); r.uleb()
                            files.add(LineFile(name, dir))
                        }
                        4 -> { // set_discriminator
                            s.discriminator = r.uleb().toInt()
                        }
                        else -> r.skip(insnLen - 1)
                    }
                    if (sub == 1) {
                        emit(true)
                        closeSequence()
                    }
                }
                opcode < opcodeBase -> {
                    when (opcode) {
                        OP_COPY -> emit(false)
                        OP_ADVANCE_PC -> {
                            val advance = r.uleb()
                            applyAdvance(s, advance, minInsnLen, maxOpsPerInsn)
                        }
                        OP_LINE -> s.line += r.sleb().toInt()
                        OP_FILE -> s.file = r.uleb().toInt()
                        OP_SET_COLUMN -> s.column = r.uleb().toInt()
                        OP_NEGATE_STMT -> s.isStmt = !s.isStmt
                        OP_SET_BASIC_BLOCK -> s.basicBlock = true
                        OP_CONST_ADD_PC -> {
                            val adjusted = (255 - opcodeBase) / lineRange
                            applyAdvance(s, adjusted.toLong(), minInsnLen, maxOpsPerInsn)
                        }
                        OP_FIXED_ADVANCE_PC -> {
                            s.address += r.u16().toLong() and 0xffff
                            s.opIndex = 0
                        }
                        OP_SET_PROLOGUE_END -> s.prologueEnd = true
                        OP_SET_ISA -> s.isa = r.uleb().toInt()
                        else -> {
                            // unknown standard opcode: consume declared args
                            val args = stdArgCount.getOrElse(opcode) { 0 }
                            repeat(args) { r.uleb() }
                        }
                    }
                }
                else -> { // special opcode
                    val adjusted = opcode - opcodeBase
                    val addrAdvance = adjusted / lineRange
                    val lineIncr = lineBase + (adjusted % lineRange)
                    applyAdvance(s, addrAdvance.toLong(), minInsnLen, maxOpsPerInsn)
                    s.line += lineIncr
                    emit(false)
                    s.basicBlock = false
                    s.prologueEnd = false
                    s.discriminator = 0
                    s.prologueEndPushed = false
                }
            }
        }
        // Section ended without DW_LNE_end_sequence (tolerated, non-standard)
        if (rows.isNotEmpty()) {
            // materialize implicit end at last emitted address
            emit(true)
            closeSequence()
        }
        section.seek(len.end, counted = false)
        return sequences
    }

    private fun applyAdvance(s: LineState, opAdvance: Long, minInsnLen: Int, maxOps: Int) {
        if (maxOps <= 1) {
            s.address += opAdvance * minInsnLen
            s.opIndex = 0
        } else {
            val newOp = s.opIndex + opAdvance
            s.address += (newOp / maxOps) * minInsnLen
            s.opIndex = (newOp % maxOps).toInt()
        }
    }

    private fun BoundedReader.s8(): Int {
        val v = u8()
        return if (v and 0x80 != 0) v - 256 else v
    }

    private fun readHeaderForm(r: BoundedReader, form: Int, sections: SectionBundle): DwarfValue {
        return when (form) {
            Form.STRING -> DwarfValue(form, r.cString())
            Form.LINE_STRP -> {
                val off = r.u32()
                DwarfValue(form, sections.lineStringAt(off.toInt()))
            }
            Form.UDATA, Form.DATA1, Form.DATA2, Form.DATA4, Form.DATA8 ->
                DwarfValue(form, when (form) {
                    Form.DATA1 -> r.u8().toLong()
                    Form.DATA2 -> r.u16().toLong()
                    Form.DATA4 -> r.u32()
                    Form.DATA8 -> r.u64()
                    else -> r.uleb()
                })
            Form.BLOCK -> DwarfValue(form, r.bytes(r.uleb().toInt()))
            Form.BLOCK1 -> DwarfValue(form, r.bytes(r.u8()))
            Form.BLOCK2 -> DwarfValue(form, r.bytes(r.u16()))
            else -> throw DwarfFormatException("unsupported file/directory form 0x${form.toString(16)}")
        }
    }

    private class LineState(isStmt: Boolean) {
        var address = 0L
        var opIndex = 0
        var file = 1
        var line = 1
        var column = 0
        var isStmt = isStmt
        var basicBlock = false
        var endSequence = false
        var prologueEnd = false
        var prologueEndPushed = false
        var isa = 0
        var discriminator = 0
        fun reset(isStmt: Boolean) {
            address = 0L; opIndex = 0; file = 1; line = 1; column = 0
            this.isStmt = isStmt; basicBlock = false; endSequence = false
            prologueEnd = false; prologueEndPushed = false; isa = 0; discriminator = 0
        }
    }
}
