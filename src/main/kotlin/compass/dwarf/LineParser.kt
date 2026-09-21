package compass.dwarf

/**
 * .debug_line parser for DWARF 2/3/4 and 5.
 * Produces independent [LineSequence]s so overlapping sequences stay separate.
 * Every emitted row is preceded by an event describing the opcode that changed state,
 * so the UI can show the line-program state machine step by step.
 */
class LineProgramParser(
    private val bundle: SectionBundle,
    private val diagnostics: MutableList<ParseDiagnostic>
) {
    private var seqCounter = 0

    fun parseAll(cus: List<CompUnit>): List<LineSequence> {
        val out = mutableListOf<LineSequence>()
        for (cu in cus) {
            val root = cu.root ?: continue
            val stmtOff = when (val v = root.attr(DW_AT.STMT_LIST)?.value) {
                is AttrValue.SecOffset -> v.v
                is AttrValue.Number -> v.v
                else -> continue
            }
            try {
                out.addAll(parseOne(stmtOff, cu))
            } catch (e: DwarfBoundsException) {
                diagnostics.add(ParseDiagnostic("ERROR", "LINE_TRUNCATED",
                    "CU @${cu.offset} 的 line program @$stmtOff 截断: ${e.message}", ".debug_line", stmtOff))
            }
        }
        return out
    }

    private class Header(
        val il: InitialLength,
        val version: Int,
        val minInsnLen: Int,
        val maxOpsPerInsn: Int,
        val defaultIsStmt: Int,
        val lineBase: Int,
        val lineRange: Int,
        val opcodeBase: Int,
        val standardLengths: IntArray,
        val dirs: MutableList<String>,
        val files: MutableList<LineFile>,
        val addressSize: Int,
        val segmentSize: Int,
        val programStart: Int,
        val programEnd: Int,
        val lineStringsPresent: Boolean
    )

    private fun parseOne(offset: Long, cu: CompUnit): List<LineSequence> {
        val pair = bundle.bytesFromAny(".debug_line") ?: return emptyList()
        val (bytes, fromSplit) = pair
        val le = if (fromSplit) bundle.split!!.littleEndian else bundle.le
        if (offset < 0 || offset >= bytes.size) {
            diagnostics.add(ParseDiagnostic("WARNING", "STMT_LIST_OOB",
                "stmt_list 偏移 0x${offset.toString(16)} 越界", ".debug_line", offset))
            return emptyList()
        }
        val r = SectionReader(bytes, ".debug_line", le, offset.toInt())
        val h = readHeader(r)
        r.seek(h.programStart)
        return runProgram(r, h, cu)
    }

    private fun readHeader(r: SectionReader): Header {
        val unitStart = r.pos
        val il = r.readInitialLength()
        val programEnd = il.headerEndPos + il.unitLength
        val version = r.u16()
        var addressSize = bundle.addrSize
        var segmentSize = 0
        if (version >= 5) {
            addressSize = r.u8()
            segmentSize = r.u8()
        }
        r.u32() // header_length (prologue length)
        val minInsnLen = r.u8()
        var maxOps = 1
        if (version >= 5) maxOps = r.u8()
        val defaultIsStmt = r.u8()
        val lineBase = r.i8()
        val lineRange = r.u8()
        val opcodeBase = r.u8()
        val standardLengths = IntArray(opcodeBase)
        standardLengths[0] = 0
        for (i in 1 until opcodeBase) standardLengths[i] = r.u8()

        val dirs = mutableListOf<String>()
        val files = mutableListOf<LineFile>()
        if (version >= 5) {
            readV5DirectoriesAndFiles(r, dirs, files, addressSize)
        } else {
            dirs.add("") // dir index 0 = comp dir implicit
            while (true) {
                val d = r.cString(); if (d.isEmpty()) break
                dirs.add(d)
            }
            while (true) {
                val name = r.cString(); if (name.isEmpty()) break
                val dirIdx = r.uleb().toInt()
                r.uleb(); r.uleb() // mtime, length
                files.add(LineFile(files.size, name, dirIdx))
            }
        }
        val programStart = r.pos
        return Header(il, version, minInsnLen, maxOps, defaultIsStmt, lineBase, lineRange,
            opcodeBase, standardLengths, dirs, files, addressSize, segmentSize,
            programStart, programEnd, version >= 5)
    }

    private fun readV5DirectoriesAndFiles(
        r: SectionReader, dirs: MutableList<String>, files: MutableList<LineFile>,
        addressSize: Int
    ) {
        data class EntryFormat(val content: Int, val form: Int)

        fun readFormats(count: Int): List<EntryFormat> =
            (0 until count).map { EntryFormat(r.u16(), r.u16()) }

        fun readEntryString(formats: List<EntryFormat>): Pair<String, Int> {
            var name = "?"
            var index = 0
            for (fmt in formats) {
                val raw = readLineHeaderForm(r, fmt.form)
                when (fmt.content) {
                    0x01, 0x04 -> if (raw is AttrValue.Str) name = raw.v // DW_LNCT_path / DW_LNCT_directory_index? no: name
                    0x02 -> if (raw is AttrValue.Number) index = raw.v.toInt() // directory_index
                    else -> {}
                }
                if (fmt.content == 0x01 && raw is AttrValue.Str) name = raw.v
            }
            return name to index
        }

        // DW_LNCT: path=1, directory_index=2, timestamp=3, size=4, MD5=5
        val dirFormatCount = r.u8()
        val dirFormats = readFormats(dirFormatCount)
        val dirCount = r.u32().toInt()
        dirs.add("")
        for (i in 0 until dirCount) {
            var path = ""
            for (fmt in dirFormats) {
                val raw = readLineHeaderForm(r, fmt.form)
                if (fmt.content == 0x01 && raw is AttrValue.Str) path = raw.v
            }
            dirs.add(path)
        }

        val fileFormatCount = r.u8()
        val fileFormats = readFormats(fileFormatCount)
        val fileCount = r.u32().toInt()
        for (i in 0 until fileCount) {
            var name = "?"
            var dirIdx = 0
            for (fmt in fileFormats) {
                val raw = readLineHeaderForm(r, fmt.form)
                when (fmt.content) {
                    0x01 -> if (raw is AttrValue.Str) name = raw.v
                    0x02 -> if (raw is AttrValue.Number) dirIdx = raw.v.toInt()
                }
            }
            files.add(LineFile(i, name, dirIdx))
        }
    }

    /** Read one form value as it appears inside a .debug_line v5 header. */
    private fun readLineHeaderForm(r: SectionReader, form: Int): AttrValue {
        return when (form) {
            DW_FORM.STRING -> AttrValue.Str(r.cString())
            DW_FORM.STRP -> {
                val off = r.dwarfOffset()
                AttrValue.Str(StrTables.readString(bundle, ".debug_str", off, true) ?: "?")
            }
            DW_FORM.LINE_STRP -> {
                val off = r.dwarfOffset()
                AttrValue.Str(StrTables.readString(bundle, ".debug_line_str", off, true) ?: "?")
            }
            DW_FORM.UDATA -> AttrValue.Number(r.uleb())
            DW_FORM.SDATA -> AttrValue.Number(r.sleb())
            DW_FORM.DATA1 -> AttrValue.Number(r.u8().toLong())
            DW_FORM.DATA2 -> AttrValue.Number(r.u16().toLong())
            DW_FORM.DATA4 -> AttrValue.Number(r.u32())
            DW_FORM.DATA8 -> AttrValue.Number(r.u64())
            else -> {
                diagnostics.add(ParseDiagnostic("WARNING", "LINE_HEADER_UNKNOWN_FORM",
                    "line 表头含不支持 form 0x${form.toString(16)}，无法确定剩余布局", ".debug_line", r.pos.toLong()))
                throw DwarfBoundsException("line 表头未知 form 0x${form.toString(16)}")
            }
        }
    }

    private fun runProgram(r: SectionReader, h: Header, cu: CompUnit): List<LineSequence> {
        val sequences = mutableListOf<LineSequence>()
        var rows = mutableListOf<LineRow>()
        var events = mutableListOf<LineEvent>()
        var seqStart = -1L

        var address = 0L
        var opIndex = 0
        var fileId = if (h.version >= 5) 0 else 1
        var line = 1
        var column = if (h.version >= 5) 0 else 0
        var isStmt = h.defaultIsStmt != 0
        var basicBlock = false
        var endSeq = false
        var prologueEnd = false
        var epilogueBegin = false
        var isa = 0
        var discriminator = 0
        var eventPos = 0

        fun snapshot(kind: String, detail: String) {
            val file = h.files.firstOrNull { it.id == fileId }?.name ?: ""
            events.add(LineEvent(eventPos++, address, file, line, column, isStmt, kind, detail))
        }

        fun emitRow(end: Boolean) {
            rows.add(LineRow(address, opIndex, fileId, line, column, isStmt, basicBlock,
                end, prologueEnd, epilogueBegin, isa, discriminator, seqCounter))
        }

        fun reset() {
            address = 0; opIndex = 0
            fileId = if (h.version >= 5) 0 else 1
            line = 1; column = 0
            isStmt = h.defaultIsStmt != 0
            basicBlock = false; endSeq = false; prologueEnd = false
            epilogueBegin = false; isa = 0; discriminator = 0
        }

        var guard = 0
        while (r.pos < h.programEnd) {
            if (++guard > MAX_LINE_OPCODES) {
                diagnostics.add(ParseDiagnostic("WARNING", "LINE_PROGRAM_TOO_LONG",
                    "line program opcode 超过 $MAX_LINE_OPCODES", ".debug_line", r.pos.toLong()))
                break
            }
            val opcodePos = r.pos
            val op = r.u8()
            if (op == 0) {
                val extLen = r.uleb().toInt()
                val extEnd = r.pos + extLen
                val sub = if (r.pos < r.size) r.u8() else 0
                when (sub) {
                    DW_LNE.END_SEQUENCE -> {
                        endSeq = true
                        emitRow(true)
                        snapshot("DW_LNE_end_sequence", "end pc=0x${address.toString(16)}")
                        val endAddr = address
                        val seq = LineSequence(seqCounter++, cu.offset,
                            rows.firstOrNull()?.address ?: endAddr, endAddr,
                            rows.toList(), events.toList(), h.files.toList(), h.dirs.toList(),
                            h.version, h.segmentSize > 0)
                        sequences.add(seq)
                        rows = mutableListOf(); events = mutableListOf(); eventPos = 0
                        reset()
                    }
                    DW_LNE.SET_ADDRESS -> {
                        address = r.u(h.addressSize)
                        opIndex = 0
                        snapshot("DW_LNE_set_address", "pc=0x${address.toString(16)}")
                    }
                    DW_LNE.DEFINE_FILE -> {
                        if (h.version < 5) {
                            val name = r.cString(); val dirIdx = r.uleb().toInt()
                            r.uleb(); r.uleb()
                            h.files.add(LineFile(h.files.size, name, dirIdx))
                            snapshot("DW_LNE_define_file", name)
                        }
                    }
                    DW_LNE.SET_DISCRIMINATOR -> {
                        discriminator = r.uleb().toInt()
                        snapshot("DW_LNE_set_discriminator", discriminator.toString())
                    }
                    else -> snapshot("DW_LNE_unknown(0x${sub.toString(16)})", "len=$extLen")
                }
                r.seek(extEnd) // never let unknown extended opcodes drift the cursor
            } else if (op < h.opcodeBase) {
                when (op) {
                    DW_LNS.COPY -> {
                        emitRow(false)
                        snapshot("DW_LNS_copy", "")
                        basicBlock = false; prologueEnd = false; epilogueBegin = false
                        discriminator = 0
                    }
                    DW_LNS.ADVANCE_PC -> {
                        val adv = r.uleb().toInt()
                        val adjusted = opIndex + adv
                        address += (adjusted / h.maxOpsPerInsn) * h.minInsnLen
                        opIndex = adjusted % h.maxOpsPerInsn
                        snapshot("DW_LNS_advance_pc", "+$adv")
                    }
                    DW_LNS.ADVANCE_LINE -> {
                        val adv = r.sleb(); line += adv.toInt()
                        snapshot("DW_LNS_advance_line", adv.toString())
                    }
                    DW_LNS.SET_FILE -> { fileId = r.uleb().toInt(); snapshot("DW_LNS_set_file", "file=$fileId") }
                    DW_LNS.SET_COLUMN -> { column = r.uleb().toInt(); snapshot("DW_LNS_set_column", column.toString()) }
                    DW_LNS.NEGATE_STMT -> { isStmt = !isStmt; snapshot("DW_LNS_negate_stmt", "") }
                    DW_LNS.SET_BASIC_BLOCK -> { basicBlock = true; snapshot("DW_LNS_set_basic_block", "") }
                    DW_LNS.CONST_ADD_PC -> {
                        val adjusted = 255 - h.opcodeBase
                        val addPc = (adjusted / h.lineRange) * h.minInsnLen
                        address += addPc.toLong()
                        snapshot("DW_LNS_const_add_pc", "+$addPc")
                    }
                    DW_LNS.FIXED_ADVANCE_PC -> {
                        val adv = r.u16(); address += adv; opIndex = 0
                        snapshot("DW_LNS_fixed_advance_pc", "+$adv")
                    }
                    DW_LNS.SET_PROLOGUE_END -> { prologueEnd = true; snapshot("DW_LNS_set_prologue_end", "") }
                    DW_LNS.SET_ISA -> { isa = r.uleb().toInt(); snapshot("DW_LNS_set_isa", isa.toString()) }
                    else -> {
                        // unknown standard opcode: consume operands via opcode_lengths table
                        val len = h.standardLengths.getOrElse(op) { 0 }
                        repeat(len) { r.uleb() }
                        snapshot("DW_LNS_unknown(0x${op.toString(16)})", "operands=$len")
                    }
                }
            } else {
                val adjusted = op - h.opcodeBase
                val advOp = adjusted % h.lineRange
                val advLine = h.lineBase + adjusted / h.lineRange
                address += ((opIndex + advOp) / h.maxOpsPerInsn) * h.minInsnLen.toLong()
                opIndex = (opIndex + advOp) % h.maxOpsPerInsn
                line += advLine
                emitRow(false)
                snapshot("special", "opcode=$op line+$advLine -> L$line")
                basicBlock = false; prologueEnd = false; epilogueBegin = false
                discriminator = 0
            }
        }
        return sequences
    }

    companion object {
        const val MAX_LINE_OPCODES = 5_000_000
    }
}
