package compass

class LineParseException(message: String) : RuntimeException(message)

/**
 * Parse .debug_line / .debug_line.dwo. Returns the program starting exactly at [sectionOffset]
 * (DW_AT_stmt_list points there), so v4 offsets between CUs are supported.
 */
class LineProgramParser(private val ctx: ParseContext) {

    fun parse(sectionName: String, section: ByteArray, sectionOffset: Long, warnings: MutableList<ParseWarning>): LineProgram? {
        return try {
            val c = ByteCursor(section, sectionOffset.toInt(), section.size, sectionName)
            parseAt(c, sectionName, sectionOffset, warnings)
        } catch (e: Exception) {
            warnings.add(ParseWarning("line", "error", "$sectionName@$sectionOffset: ${e.message}"))
            null
        }
    }

    private fun parseAt(c: ByteCursor, sectionName: String, sectionOffset: Long, warnings: MutableList<ParseWarning>): LineProgram {
        val programStart = c.pos
        val (_, unitEnd) = RangeReader.readInitialLength(c)
        val version = c.u16()
        if (version !in 2..5) throw LineParseException("unsupported line program version $version")
        val dwarf5 = version >= 5

        var addressSize = 8
        var segmentSelectorSize = 0
        var headerLength = 0
        var minInsLen = 1
        var maxOpsPerIns = 1
        var defaultIsStmt = 1
        var lineBase = 0
        var lineRange = 1
        var opcodeBase = 13L

        if (dwarf5) {
            addressSize = c.u8()
            segmentSelectorSize = c.u8()
            headerLength = c.u32().toInt()
            val headerEnd = c.pos + headerLength
            minInsLen = c.u8()
            maxOpsPerIns = c.u8()
            defaultIsStmt = c.s8()
            lineBase = c.s8()
            lineRange = c.u8()
            opcodeBase = c.u8().toLong()
            val stdOps = Array(opcodeBase.toInt()) { IntArray(0) }
            for (si in 1 until opcodeBase.toInt()) {
                val n = c.u8()
                stdOps[si] = IntArray(n) { c.u8() }
            }
            val directories = parseV5FileList(c, isFile = false)
            val files = parseV5FileList(c, isFile = true, directories)
            if (c.pos != headerEnd) {
                warnings.add(ParseWarning("line", "warning", "line header length mismatch: pos=${c.pos} end=$headerEnd"))
            }
            c.seek(headerEnd)
            val seqs = runProgram(c, unitEnd, version, addressSize, segmentSelectorSize, minInsLen, maxOpsPerIns, defaultIsStmt, lineBase, lineRange, opcodeBase, stdOps, files)
            return LineProgram(version, true, addressSize, segmentSelectorSize, defaultIsStmt != 0, segmentSelectorSize, files, directories.map { it.fullPath }, seqs, sectionOffset)
        } else {
            headerLength = c.u32().toInt()
            val headerEnd = c.pos + headerLength
            minInsLen = c.u8()
            if (version >= 4) defaultIsStmt = c.s8()
            lineBase = c.s8()
            lineRange = c.u8()
            opcodeBase = c.u8().toLong()
            val stdOps = Array(opcodeBase.toInt()) { IntArray(0) }
            for (si in 1 until opcodeBase.toInt()) {
                val n = c.u8()
                stdOps[si] = IntArray(n) { c.u8() }
            }
            val directories = mutableListOf("") // index 0 = comp_dir convention
            while (true) {
                val s = c.cString()
                if (s.isEmpty()) break
                directories.add(s)
                if (directories.size > Limits.MAX_LINE_FILES) throw LineParseException("too many directories")
            }
            val files = mutableListOf(LineFile(0, "", ctx.cu?.compDir ?: ""))
            var idx = 1L
            while (true) {
                if (c.remaining == 0 || c.pos >= headerEnd) break
                if (c.peek() == 0) { c.u8(); break }
                val name = c.cString()
                val dirIdx = c.uleb()
                c.uleb(); c.uleb() // timestamp, length (ignored)
                val dir = directories.getOrNull(dirIdx.toInt()) ?: ""
                files.add(LineFile(idx, name, if (dir.isEmpty()) name else "$dir/$name"))
                idx++
                if (files.size > Limits.MAX_LINE_FILES) throw LineParseException("too many files")
            }
            if (c.pos != headerEnd) {
                warnings.add(ParseWarning("line", "warning", "v4 line header length mismatch: pos=${c.pos} end=$headerEnd (resyncing)"))
                c.seek(headerEnd)
            }
            val seqs = runProgram(c, unitEnd, version, addressSize, segmentSelectorSize, minInsLen, maxOpsPerIns, defaultIsStmt, lineBase, lineRange, opcodeBase, stdOps, files)
            return LineProgram(version, false, addressSize, segmentSelectorSize, defaultIsStmt != 0, segmentSelectorSize, files, directories, seqs, sectionOffset)
        }
    }

    private fun parseV5FileList(c: ByteCursor, isFile: Boolean, directories: List<LineFile> = emptyList()): List<LineFile> {
        val count = c.uleb().toInt()
        val out = ArrayList<LineFile>(count)
        if (!isFile) out.add(LineFile(0, "", ctx.cu?.compDir ?: ""))
        else out.add(LineFile(0, "", ctx.cu?.compDir ?: ""))
        var idx = 0L
        repeat(count) {
            val entryIdx = if (isFile) idx + 1 else idx
            var path = ""
            var dirIdx = 0L
            var pairs = c.uleb().toInt()
            repeat(pairs) {
                val contentType = c.uleb()
                val form = c.uleb()
                val v = readHeaderForm(c, form)
                when (contentType) {
                    Dw.LNCT_PATH -> path = formString(v, form, c, lineStrings = true)
                    Dw.LNCT_DIRECTORY_INDEX -> dirIdx = (v as? Long) ?: 0L
                }
            }
            val full = when {
                !isFile -> path
                dirIdx == 0L || path.startsWith('/') -> path
                else -> {
                    val d = directories.getOrNull(dirIdx.toInt())?.fullPath ?: ""
                    if (d.isEmpty()) path else "$d/$path"
                }
            }
            out.add(LineFile(entryIdx, path, full))
            idx++
            if (out.size > Limits.MAX_LINE_FILES) throw LineParseException("too many file entries")
        }
        return out
    }

    private fun readHeaderForm(c: ByteCursor, form: Long): Any? {
        var hops = 0
        var f = form
        while (f == Dw.FORM_INDIRECT) {
            if (++hops > Limits.MAX_INDIRECT_HOPS) throw LineParseException("DW_FORM_indirect chain too long")
            f = c.uleb()
        }
        return when (f) {
            Dw.FORM_STRING -> c.cString()
            Dw.FORM_STRP -> { val off = c.fixed(ctx.offsetSize) ; ctx.readString(".debug_str", off) }
            Dw.FORM_LINE_STRP -> { val off = c.fixed(ctx.offsetSize); ctx.readString(".debug_line_str", off) }
            Dw.FORM_DATA1, Dw.FORM_DATA2 -> c.fixed(if (f == Dw.FORM_DATA1) 1 else 2)
            Dw.FORM_DATA4 -> c.u32()
            Dw.FORM_DATA8 -> c.u64()
            Dw.FORM_UDATA -> c.uleb()
            Dw.FORM_SDATA -> c.sleb()
            Dw.FORM_STRX, Dw.FORM_STRX1, Dw.FORM_STRX2, Dw.FORM_STRX3, Dw.FORM_STRX4,
            Dw.FORM_GNU_STR_INDEX -> {
                val ix = readIndex(c, f)
                ctx.readIndexedString(ix)
            }
            else -> throw LineParseException("unsupported line header form ${Dw.formName(f)} (cannot safely continue)")
        }
    }

    private fun readIndex(c: ByteCursor, form: Long): Long = when (form) {
        Dw.FORM_STRX, Dw.FORM_ADDRX, Dw.FORM_UDATA, Dw.FORM_GNU_STR_INDEX, Dw.FORM_GNU_ADDR_INDEX -> c.uleb()
        Dw.FORM_STRX1, Dw.FORM_ADDRX1 -> c.u8().toLong()
        Dw.FORM_STRX2, Dw.FORM_ADDRX2 -> c.u16().toLong()
        Dw.FORM_STRX3, Dw.FORM_ADDRX3 -> c.u32()
        Dw.FORM_STRX4, Dw.FORM_ADDRX4 -> c.u64()
        else -> throw LineParseException("not an index form: ${Dw.formName(form)}")
    }

    private fun formString(v: Any?, form: Long, c: ByteCursor, lineStrings: Boolean): String = when (v) {
        is String -> v
        else -> "?"
    }

    private fun runProgram(
        c: ByteCursor, unitEnd: Int, version: Int, addressSize: Int, segSel: Int,
        minInsLen: Int, maxOpsPerIns: Int, defaultIsStmt: Int, lineBase: Int, lineRange: Int, opcodeBase: Long,
        stdOps: Array<IntArray>, files: List<LineFile>,
    ): List<LineSequence> {
        data class State(
            var address: TargetAddress = TargetAddress(0), var file: Long = 1, var line: Long = 1, var column: Long = 0,
            var isStmt: Boolean = defaultIsStmt != 0, var basicBlock: Boolean = false, var endSequence: Boolean = false,
            var prologueEnd: Boolean = false, var epilogueBegin: Boolean = false, var isa: Long = 0,
            var discriminator: Long = 0, var opIndex: Long = 0,
        )
        val sequences = mutableListOf<LineSequence>()
        var rows = mutableListOf<LineRow>()
        var seqIndex = 0
        var seqStart = TargetAddress(0)
        var haveRow = false
        val s = State()

        fun emit() {
            rows.add(LineRow(s.address, s.endSequence, s.file, s.line, s.column, s.isStmt, s.isa, s.discriminator, s.basicBlock, s.prologueEnd, s.epilogueBegin, s.opIndex))
            haveRow = true
        }
        fun reset() {
            s.address = TargetAddress(0); s.file = 1; s.line = 1; s.column = 0
            s.isStmt = defaultIsStmt != 0; s.basicBlock = false; s.endSequence = false
            s.prologueEnd = false; s.epilogueBegin = false; s.isa = 0; s.discriminator = 0; s.opIndex = 0
        }
        var specialMax = 255 - opcodeBase + 1
        while (c.pos < unitEnd) {
            if (rows.size > Limits.MAX_LINE_ROWS) throw LineParseException("line row count exceeds limit")
            val op = c.u8()
            if (op == 0) {
                val extLen = c.uleb().toInt()
                val extEnd = c.pos + extLen
                val sub = c.u8()
                when (sub) {
                    Dw.LNE_END_SEQUENCE -> {
                        s.endSequence = true
                        emit()
                        val endAddr = s.address
                        sequences.add(LineSequence(seqIndex++, seqStart, endAddr, rows, c.pos.toLong()))
                        rows = mutableListOf()
                        reset()
                        haveRow = false
                    }
                    Dw.LNE_SET_ADDRESS -> {
                        val sel = if (segSel > 0) c.address(segSel) else 0L
                        val off = c.address(addressSize)
                        s.address = TargetAddress(off, sel.toInt())
                        s.opIndex = 0
                        if (!haveRow) seqStart = s.address
                    }
                    Dw.LNE_DEFINE_FILE -> {
                        // v4 only
                        c.cString(); c.uleb(); c.uleb(); c.uleb()
                    }
                    Dw.LNE_SET_DISCRIMINATOR -> s.discriminator = c.uleb()
                    else -> { /* unknown extended op: skip remaining bytes */ }
                }
                c.seek(extEnd)
            } else if (op < opcodeBase) {
                when (op) {
                    Dw.LNS_COPY -> emit()
                    Dw.LNS_ADVANCE_PC -> {
                        val adv = c.uleb()
                        s.address = TargetAddress(s.address.offset + minInsLen * ((s.opIndex + adv) / maxOpsPerIns), s.address.segment)
                        s.opIndex = (s.opIndex + adv) % maxOpsPerIns
                    }
                    Dw.LNS_ADVANCE_LINE -> s.line += c.sleb()
                    Dw.LNS_SET_FILE -> s.file = c.uleb()
                    Dw.LNS_SET_COLUMN -> s.column = c.uleb()
                    Dw.LNS_NEGATE_STMT -> s.isStmt = !s.isStmt
                    Dw.LNS_SET_BASIC_BLOCK -> s.basicBlock = true
                    Dw.LNS_CONST_ADD_PC -> {
                        val adj = specialMax / lineRange
                        s.address = TargetAddress(s.address.offset + minInsLen * ((s.opIndex + adj) / maxOpsPerIns), s.address.segment)
                        s.opIndex = (s.opIndex + adj) % maxOpsPerIns
                    }
                    Dw.LNS_FIXED_ADVANCE_PC -> {
                        val adv = c.u16()
                        s.address = TargetAddress(s.address.offset + adv, s.address.segment)
                        s.opIndex = 0
                    }
                    Dw.LNS_SET_PROLOGUE_END -> s.prologueEnd = true
                    Dw.LNS_SET_EPILOGUE_BEGIN -> s.epilogueBegin = true
                    Dw.LNS_SET_ISA -> s.isa = c.uleb()
                    else -> {
                        // Unknown standard opcode: consume each operand per its descriptor.
                        // DW_LNE_* operand kinds: 1..5 LEB, 6 u2byte, 7 u4byte, 8 u8byte, 9 uleb
                        stdOps.getOrNull(op)?.forEach { k ->
                            when (k) {
                                6 -> c.u16(); 7 -> c.u32(); 8 -> c.u64(); else -> c.uleb()
                            }
                        }
                    }
                }
            } else {
                val adj = op - opcodeBase
                val opAdv = adj / lineRange
                val lineAdv = lineBase + (adj % lineRange)
                s.line += lineAdv
                s.address = TargetAddress(s.address.offset + minInsLen * ((s.opIndex + opAdv) / maxOpsPerIns), s.address.segment)
                s.opIndex = (s.opIndex + opAdv) % maxOpsPerIns
                emit()
                s.basicBlock = false; s.prologueEnd = false; s.epilogueBegin = false; s.discriminator = 0
            }
        }
        if (rows.isNotEmpty()) {
            warnings.add(ParseWarning("line", "warning", "trailing ${rows.size} rows without end_sequence"))
        }
        return sequences
    }
}
