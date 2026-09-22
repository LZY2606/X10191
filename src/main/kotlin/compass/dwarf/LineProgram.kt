package compass.dwarf

data class LineHeader(
    val version: Int,
    val addrSize: Int,
    val minInstLength: Int,
    val maxOpsPerInst: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val standardOpcodeLengths: IntArray,
    val directories: List<String>,
    /** file entries: (dirIndex 1-based into directories, 0 = comp_dir; name) */
    val files: List<Pair<Int, String>>,
)

data class ParsedLineProgram(
    val header: LineHeader,
    val rows: List<LineRow>,
    val issues: List<String>,
)

object LineProgramParser {
    fun parse(
        line: Reader, offset: Long, compDir: String?, limits: DwarfLimits,
        resolveStr: (table: String, off: Long) -> String?,
    ): ParsedLineProgram {
        val issues = mutableListOf<String>()
        if (offset < 0 || offset >= line.size) throw DwarfException("stmt_list offset 0x${offset.toString(16)} out of bounds")
        val r = line.cloneAt(offset.toInt())
        val unitStart = r.pos
        val len0 = r.u32()
        val dwarf64 = len0 == 0xffffffffL
        val unitLen = if (dwarf64) r.u64() else len0
        val unitEnd = unitStart + (if (dwarf64) 12 else 4) + unitLen.toInt()
        if (unitEnd > line.size) throw DwarfException("line program unit overruns section")
        r.dwarf64 = dwarf64
        val version = r.u16()
        if (version !in 2..5) throw DwarfException("unsupported line program version $version")
        var addrSize = 8
        var segSize = 0
        if (version >= 5) {
            addrSize = r.u8()
            segSize = r.u8()
        }
        val headerLen = r.offset()
        val headerEnd = r.pos + headerLen.toInt()
        if (headerEnd > unitEnd) throw DwarfException("line header overruns unit")
        val minInst = r.u8()
        val maxOps = if (version >= 4) r.u8() else 1
        val defaultIsStmt = r.u8() != 0
        val lineBase = r.u8().toByte().toInt()
        val lineRange = r.u8()
        val opcodeBase = r.u8()
        if (opcodeBase == 0 || lineRange == 0) throw DwarfException("bad opcode_base/line_range")
        val stdLens = IntArray(opcodeBase - 1) { r.u8() }

        val directories = mutableListOf<String>()
        val files = mutableListOf<Pair<Int, String>>()

        fun readLnctValue(contentType: Int, form: Int): Any? = when (form) {
            Form.STRING -> r.cstring()
            Form.STRP -> resolveStr("str", r.offset())
            Form.LINE_STRP -> resolveStr("line_str", r.offset())
            Form.STRP_SUP -> { r.offset(); null }
            Form.STRX -> AttrValue.Indexed("strx", r.uleb())
            Form.STRX1 -> AttrValue.Indexed("strx", r.u8().toLong())
            Form.STRX2 -> AttrValue.Indexed("strx", r.u16().toLong())
            Form.STRX3 -> AttrValue.Indexed("strx", r.u8().toLong() or (r.u8().toLong() shl 8) or (r.u8().toLong() shl 16))
            Form.STRX4 -> AttrValue.Indexed("strx", r.u32())
            Form.DATA1 -> r.u8().toLong()
            Form.DATA2 -> r.u16().toLong()
            Form.DATA4 -> r.u32()
            Form.DATA8 -> r.u64()
            Form.UDATA -> r.uleb()
            Form.DATA16 -> r.bytes(16)
            Form.BLOCK -> r.bytes(r.uleb().toInt())
            else -> throw UnknownFormException(form, "unknown LNCT form 0x${form.toString(16)}")
        }

        if (version >= 5) {
            fun readEntryFormats(): List<Pair<Int, Int>> {
                val count = r.u8()
                return (0 until count).map { r.uleb().toInt() to r.uleb().toInt() }
            }
            val dirFormats = readEntryFormats()
            val dirCount = r.uleb()
            repeat(dirCount.toInt()) {
                var path: String? = null
                for ((ct, form) in dirFormats) {
                    val v = readLnctValue(ct, form)
                    if (ct == Lnct.PATH) path = v as? String
                }
                directories += path ?: ""
            }
            val fileFormats = readEntryFormats()
            val fileCount = r.uleb()
            repeat(fileCount.toInt()) {
                var path: String? = null
                var dirIdx = 0
                for ((ct, form) in fileFormats) {
                    val v = readLnctValue(ct, form)
                    when (ct) {
                        Lnct.PATH -> path = v as? String
                        Lnct.DIRECTORY_INDEX -> dirIdx = (v as? Long)?.toInt() ?: 0
                    }
                }
                files += dirIdx to (path ?: "")
            }
        } else {
            while (true) {
                if (r.pos >= headerEnd) throw DwarfException("directory list overruns header")
                val s = r.cstring()
                if (s.isEmpty()) break
                directories += s
            }
            while (true) {
                if (r.pos >= headerEnd) throw DwarfException("file list overruns header")
                val name = r.cstring()
                if (name.isEmpty()) break
                val dirIdx = r.uleb().toInt()
                r.uleb(); r.uleb() // mtime, size
                files += dirIdx to name
            }
        }
        r.pos = headerEnd

        fun dirOf(idx: Int): String = when {
            version >= 5 -> directories.getOrNull(idx) ?: ""
            idx == 0 -> compDir ?: ""
            else -> directories.getOrNull(idx - 1) ?: ""
        }

        fun fileName(fileIdx: Int): String {
            // v4: 1-based into files; v5: 0-based
            val i = if (version >= 5) fileIdx else fileIdx - 1
            val f = files.getOrNull(i) ?: return "<file#$fileIdx>"
            val dir = dirOf(f.first)
            return if (dir.isEmpty() || f.second.startsWith("/")) f.second else "$dir/${f.second}"
        }

        // state machine
        val rows = mutableListOf<LineRow>()
        var address = 0L
        var opIndex = 0L
        var file = 1
        var lineNo = 1
        var column = 0
        var isStmt = defaultIsStmt
        var basicBlock = false
        var endSequence = false
        var prologueEnd = false
        var epilogueBegin = false
        var isa = 0L
        var discriminator = 0L
        var seq = 0

        fun reset() {
            address = 0; opIndex = 0; file = 1; lineNo = 1; column = 0
            isStmt = defaultIsStmt; basicBlock = false; endSequence = false
            prologueEnd = false; epilogueBegin = false; isa = 0; discriminator = 0
        }

        fun emitRow() {
            if (rows.size >= limits.maxLineRows) throw DwarfException("line row count exceeds limit")
            rows += LineRow(seq, address, address, file, fileName(file), lineNo, column, isStmt,
                basicBlock, endSequence, prologueEnd, epilogueBegin, isa, discriminator)
        }

        fun advanceAddr(operand: Long) {
            val opAdvance = if (maxOps > 1) (opIndex + operand) / maxOps - opIndex / maxOps else operand
            address += minInst.toLong() * opAdvance
            opIndex = if (maxOps > 1) (opIndex + operand) % maxOps else 0
        }

        while (r.pos < unitEnd) {
            val opcode = r.u8()
            when {
                opcode == 0 -> {
                    val extLen = r.uleb()
                    val extEnd = r.pos + extLen.toInt()
                    if (extEnd > unitEnd) throw DwarfException("extended opcode overruns unit")
                    if (extLen == 0L) continue
                    val sub = r.u8()
                    when (sub) {
                        Lne.END_SEQUENCE -> {
                            endSequence = true
                            emitRow()
                            seq++
                            reset()
                        }
                        Lne.SET_ADDRESS -> {
                            address = r.addr(addrSize)
                            if (segSize > 0) r.bytes(segSize) // ignore segment selector
                            opIndex = 0
                        }
                        Lne.DEFINE_FILE -> {
                            val name = r.cstring(); val dirIdx = r.uleb().toInt(); r.uleb(); r.uleb()
                            files += dirIdx to name
                        }
                        Lne.SET_DISCRIMINATOR -> discriminator = r.uleb()
                        else -> issues += "unknown extended line opcode $sub skipped"
                    }
                    r.pos = extEnd // stay aligned regardless of sub-opcode support
                }
                opcode < opcodeBase -> when (opcode) {
                    Lns.COPY -> { emitRow(); basicBlock = false; prologueEnd = false; epilogueBegin = false; discriminator = 0 }
                    Lns.ADVANCE_PC -> advanceAddr(r.uleb())
                    Lns.ADVANCE_LINE -> lineNo += r.sleb().toInt()
                    Lns.SET_FILE -> file = r.uleb().toInt()
                    Lns.SET_COLUMN -> column = r.uleb().toInt()
                    Lns.NEGATE_STMT -> isStmt = !isStmt
                    Lns.SET_BASIC_BLOCK -> basicBlock = true
                    Lns.CONST_ADD_PC -> advanceAddr((255 - opcodeBase) / lineRange)
                    Lns.FIXED_ADVANCE_PC -> { address += r.u16(); opIndex = 0 }
                    Lns.SET_PROLOGUE_END -> prologueEnd = true
                    Lns.SET_EPILOGUE_BEGIN -> epilogueBegin = true
                    Lns.SET_ISA -> isa = r.uleb()
                    else -> {
                        // unknown standard opcode: consume its declared operands to stay aligned
                        val nargs = stdLens.getOrNull(opcode - 1)
                            ?: throw DwarfException("unknown standard opcode $opcode without length entry")
                        repeat(nargs) { r.uleb() }
                        issues += "unknown standard line opcode $opcode skipped"
                    }
                }
                else -> {
                    val adjusted = opcode - opcodeBase
                    val opAdv = adjusted / lineRange
                    val lineInc = lineBase + (adjusted % lineRange)
                    advanceAddr(opAdv.toLong())
                    lineNo += lineInc
                    emitRow()
                    basicBlock = false; prologueEnd = false; epilogueBegin = false; discriminator = 0
                }
            }
        }

        // compute end addresses within each sequence
        val finalized = mutableListOf<LineRow>()
        var i = 0
        while (i < rows.size) {
            val row = rows[i]
            val end = if (i + 1 < rows.size && rows[i + 1].sequence == row.sequence) rows[i + 1].address else row.address
            finalized += row.copy(endAddress = end)
            i++
        }
        return ParsedLineProgram(
            LineHeader(version, addrSize, minInst, maxOps, defaultIsStmt, lineBase, lineRange, opcodeBase, stdLens, directories, files),
            finalized, issues,
        )
    }
}
