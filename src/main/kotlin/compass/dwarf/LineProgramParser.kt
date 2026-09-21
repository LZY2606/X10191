package compass.dwarf

import compass.util.ByteReader
import compass.util.Limits
import compass.util.ParseException
import compass.util.U64

/**
 * Parses .debug_line / .debug_line.dwo line number programs for the given CUs.
 * Each CU's stmt_list offset selects one program inside the shared section.
 *
 * Output preserves every emitted matrix row (including end_sequence rows) so the UI can show
 * full state-machine evolution and so zero-length / equal-address ranges stay distinguishable.
 */
class LineProgramParser(
    private val sections: Sections,
    private val debugData: DebugData,
    private val dwo: Boolean
) {
    private val lineName = if (dwo) ".debug_line.dwo" else ".debug_line"

    fun parseAll(cus: List<CompilationUnit>): List<LineProgram> {
        val bytes = sections[lineName] ?: return emptyList()
        val out = ArrayList<LineProgram>()
        for (cu in cus) {
            val stmt = cu.stmtList ?: continue
            try {
                out += parseOne(bytes, stmt, cu)
            } catch (e: ParseException) {
                out += broken(cu, listOf(
                    ParseIssue("error", "BAD_LINE_PROGRAM", e.message ?: "line program parse failed", lineName, stmt, cu.offset)
                ))
            }
        }
        return out
    }

    private fun broken(cu: CompilationUnit, issues: List<ParseIssue>) = LineProgram(
        cuOffset = cu.offset, cuIndex = cu.index, dwarfVersion = cu.dwarfVersion,
        minInstructionLength = 1, maxOpsPerInstruction = 1, defaultIsStmt = true,
        lineBase = 0, lineRange = 1, opcodeBase = 13, directories = emptyList(),
        files = emptyList(), rows = emptyList(), sequences = emptyList(),
        issues = issues, parsedCompletely = false
    )

    private class Header(
        val version: Int, val dwarf64: Boolean, val offsetSize: Int,
        val minInstrLen: Int, val maxOps: Int, val defaultStmt: Boolean,
        val lineBase: Int, val lineRange: Int, val opcodeBase: Int,
        val stdOpcodeLengths: IntArray,
        val directories: List<String>, val files: List<LineFile>,
        val segmentSelectorSize: Int, val programStart: Int, val addressSize: Int
    )

    private fun parseOne(bytes: ByteArray, stmt: U64, cu: CompilationUnit): LineProgram {
        val r = ByteReader(bytes, stmt.v.toInt())
        val startPos = r.pos
        val initialLen = r.u32()
        val dwarf64: Boolean
        val unitLength: Long
        val offsetSize: Int
        if (initialLen == 0xffffffffL) {
            dwarf64 = true; offsetSize = 8; unitLength = r.u64().v
        } else {
            dwarf64 = false; offsetSize = 4; unitLength = initialLen
        }
        val programEnd = r.pos + unitLength.toInt()
        val version = r.u16()
        if (version !in 2..5) throw ParseException("line program version $version unsupported")

        var addressSize = cu.addressSize
        var segmentSelectorSize = 0
        var minInstrLen: Int
        var maxOps = 1
        var defaultStmt = 1
        var lineBase: Int
        var lineRange: Int
        var opcodeBase: Int
        var stdLengths = IntArray(0)
        var directories = emptyList<String>()
        var files = emptyList<LineFile>()

        if (version >= 5) {
            addressSize = r.u8()
            segmentSelectorSize = r.u8()
            val prologueLen = readOff(r, offsetSize)
            val prologueEnd = r.pos + prologueLen.v.toInt()
            minInstrLen = r.u8()
            maxOps = r.u8().coerceAtLeast(1)
            defaultStmt = r.u8()
            lineBase = r.s8()
            lineRange = r.u8()
            opcodeBase = r.u8()
            stdLengths = IntArray(opcodeBase - 1) { r.u8() }
            directories = readV5Directories(r, bytes, cu, version)
            files = readV5Files(r, bytes, cu, version, directories)
            r.seek(prologueEnd)
        } else {
            val prologueLen = r.u32()
            val prologueEnd = r.pos + prologueLen.toInt()
            minInstrLen = r.u8()
            if (version >= 4) defaultStmt = r.u8()
            lineBase = r.s8()
            lineRange = r.u8()
            opcodeBase = r.u8()
            stdLengths = IntArray(opcodeBase - 1) { r.u8() }
            directories = readV4IncludeDirs(r)
            files = readV4FileTable(r, directories)
            r.seek(prologueEnd)
        }

        val hdr = Header(
            version, dwarf64, offsetSize, minInstrLen, maxOps, defaultStmt != 0,
            lineBase, lineRange, opcodeBase, stdLengths, directories, files,
            segmentSelectorSize, r.pos, addressSize
        )
        val pr = runProgram(r, programEnd, hdr, cu)
        return LineProgram(
            cuOffset = cu.offset, cuIndex = cu.index, dwarfVersion = version,
            minInstructionLength = minInstrLen, maxOpsPerInstruction = maxOps,
            defaultIsStmt = defaultStmt != 0, lineBase = lineBase, lineRange = lineRange,
            opcodeBase = opcodeBase, directories = directories, files = files,
            rows = pr.rows, sequences = pr.sequences, issues = pr.issues, parsedCompletely = pr.complete
        )
    }

    private fun readV4IncludeDirs(r: ByteReader): List<String> {
        val dirs = ArrayList<String>()
        while (true) {
            val s = r.cstring()
            if (s.isEmpty()) break
            dirs += s
        }
        return dirs
    }

    private fun readV4FileTable(r: ByteReader, dirs: List<String>): List<LineFile> {
        val files = ArrayList<LineFile>()
        files += LineFile("<unknown>", null, null, null) // file index 0
        while (true) {
            val name = r.cstring()
            if (name.isEmpty()) break
            val dirIdx = r.uleb128()
            val mtime = r.uleb128()
            val size = r.uleb128()
            val dir = dirs.getOrNull((dirIdx - 1).toInt())
            files += LineFile(joinPath(dir, name), dir, U64(size), U64(mtime))
        }
        return files
    }

    private fun readV5EntryFormats(r: ByteReader): List<Pair<Int, Int>> {
        val count = r.u8()
        val out = ArrayList<Pair<Int, Int>>(count)
        repeat(count) {
            val content = r.uleb128().toInt()
            val form = r.uleb128().toInt()
            out += content to form
        }
        return out
    }

    private fun entryString(content: Int, form: Int, r: ByteReader, bytes: ByteArray, cu: CompilationUnit, version: Int): String {
        return when (form) {
            DwForm.STRING -> r.cstring()
            DwForm.LINE_STRP -> {
                val off = if (cu.dwarf64) r.u64().v else r.u32()
                debugData.readLineString(off, cu.kind == "split")
            }
            DwForm.STRP -> {
                val off = if (cu.dwarf64) r.u64().v else r.u32()
                debugData.readDebugString(off, cu.kind == "split")
            }
            DwForm.STRX1 -> debugData.resolveStrx(cu.strOffsetsBase, r.u8().toLong(), if (cu.dwarf64) 8 else 4, version, cu.kind == "split")
            DwForm.STRX2 -> debugData.resolveStrx(cu.strOffsetsBase, r.u16().toLong(), if (cu.dwarf64) 8 else 4, version, cu.kind == "split")
            DwForm.STRX, DwForm.GNU_STR_INDEX -> debugData.resolveStrx(cu.strOffsetsBase, r.uleb128(), if (cu.dwarf64) 8 else 4, version, cu.kind == "split")
            else -> throw ParseException("unsupported path form 0x${form.toString(16)} in line header")
        }
    }

    private fun skipEntryForm(form: Int, r: ByteReader) {
        when (form) {
            DwForm.STRING -> r.cstring()
            DwForm.LINE_STRP, DwForm.STRP, DwForm.SEC_OFFSET -> { if (r.remaining() >= 4) r.u32() }
            DwForm.UDATA, DwForm.SDATA, DwForm.STRX, DwForm.ADDRX, DwForm.GNU_STR_INDEX, DwForm.GNU_ADDR_INDEX -> r.uleb128()
            DwForm.DATA1, DwForm.STRX1, DwForm.ADDRX1 -> r.u8()
            DwForm.DATA2, DwForm.STRX2, DwForm.ADDRX2 -> r.u16()
            DwForm.DATA4, DwForm.STRX3, DwForm.STRX4, DwForm.ADDRX3, DwForm.ADDRX4 -> r.u32()
            DwForm.DATA8 -> r.u64()
            DwForm.ADDR -> { if (r.remaining() >= 8) r.u64() }
            DwForm.FLAG_PRESENT -> {}
            else -> throw ParseException("unsupported entry form 0x${form.toString(16)} in line header")
        }
    }

    private fun readV5Directories(r: ByteReader, bytes: ByteArray, cu: CompilationUnit, version: Int): List<String> {
        val formats = readV5EntryFormats(r)
        val count = r.uleb128().toInt()
        if (count > Limits.MAX_TABLE_ENTRIES) throw ParseException("line directory count too large")
        val dirs = ArrayList<String>(count)
        repeat(count) {
            var path = ""
            for ((content, form) in formats) {
                val v = entryString(content, form, r, bytes, cu, version)
                if (content == 1 /* DW_LNCT_path */) path = v
            }
            dirs += path
        }
        return dirs
    }

    private fun readV5Files(r: ByteReader, bytes: ByteArray, cu: CompilationUnit, version: Int, dirs: List<String>): List<LineFile> {
        val formats = readV5EntryFormats(r)
        val count = r.uleb128().toInt()
        if (count > Limits.MAX_TABLE_ENTRIES) throw ParseException("line file count too large")
        val files = ArrayList<LineFile>(count + 1)
        files += LineFile("<unknown>", null, null, null) // index 0
        repeat(count) {
            var path: String? = null
            var dirIdx = 0L
            var size: U64? = null
            var mtime: U64? = null
            for ((content, form) in formats) {
                when (content) {
                    1 -> path = entryString(content, form, r, bytes, cu, version)
                    2 -> dirIdx = when (form) {
                        DwForm.UDATA -> r.uleb128()
                        DwForm.DATA1 -> r.u8().toLong()
                        DwForm.DATA2 -> r.u16().toLong()
                        else -> { skipEntryForm(form, r); 0L }
                    }
                    3 -> size = when (form) {
                        DwForm.UDATA -> r.ulebU()
                        DwForm.DATA1 -> U64(r.u8().toLong())
                        DwForm.DATA2 -> U64(r.u16().toLong())
                        DwForm.DATA4 -> U64(r.u32())
                        DwForm.DATA8 -> r.u64()
                        else -> { skipEntryForm(form, r); null }
                    }
                    else -> skipEntryForm(form, r)
                }
            }
            val dir = dirs.getOrNull((dirIdx - 1).toInt())
            files += LineFile(joinPath(dir, path ?: "?"), dir, size, mtime)
        }
        return files
    }

    private fun joinPath(dir: String?, name: String): String =
        if (dir.isNullOrEmpty() || dir == ".") name else "$dir/$name"

    private fun readOff(r: ByteReader, size: Int): U64 = if (size == 4) U64(r.u32()) else r.u64()

    private class Regs(
        var address: U64 = U64.ZERO, var segment: Int = 0, var opIndex: Int = 0,
        var file: Int = 1, var line: Int = 1, var column: Int = 0,
        var isStmt: Boolean, var basicBlock: Boolean = false,
        var prologueEnd: Boolean = false, var epilogueBegin: Boolean = false,
        var isa: Int = 0, var discriminator: Int = 0
    )

    private class ProgramResult(
        val rows: List<LineRow>, val sequences: List<LineSequence>,
        val issues: List<ParseIssue>, val complete: Boolean
    )

    private fun runProgram(r: ByteReader, end: Int, hdr: Header, cu: CompilationUnit): ProgramResult {
        val rows = ArrayList<LineRow>()
        val seqs = ArrayList<LineSequence>()
        val issues = ArrayList<ParseIssue>()
        var complete = true
        var seqStartRow = -1
        var seqSeg = 0
        var seqStartAddr = U64.ZERO

        var reg = Regs(isStmt = hdr.defaultStmt)

        fun resetRegs() { reg = Regs(isStmt = hdr.defaultStmt) }

        fun advancePc(opAdvance: Int) {
            val opsPerInstr = hdr.maxOps.coerceAtLeast(1)
            val total = reg.opIndex + opAdvance
            reg.address = U64(reg.address.v + (total / opsPerInstr).toLong() * hdr.minInstrLen.toLong())
            reg.opIndex = total % opsPerInstr
        }

        fun emitRow(endSeq: Boolean, trigger: String) {
            if (!endSeq && seqStartRow < 0) {
                seqStartRow = rows.size; seqSeg = reg.segment; seqStartAddr = reg.address
            }
            rows += LineRow(
                address = reg.address, segment = reg.segment, opIndex = reg.opIndex,
                fileIndex = reg.file, line = reg.line, column = reg.column,
                isStmt = reg.isStmt, basicBlock = reg.basicBlock, prologueEnd = reg.prologueEnd,
                epilogueBegin = reg.epilogueBegin, isa = reg.isa, discriminator = reg.discriminator,
                endSequence = endSeq, trigger = trigger
            )
        }

        try {
            while (r.pos < end) {
                if (rows.size >= Limits.MAX_LINE_ROWS) throw ParseException("line row count exceeds cap")
                val op = r.u8()
                when {
                    op == 0 -> {
                        val extLen = r.uleb128().toInt()
                        val extEnd = r.pos + extLen
                        val sub = r.u8()
                        when (sub) {
                            DwLne.END_SEQUENCE -> {
                                emitRow(true, "DW_LNE_end_sequence")
                                if (seqStartRow >= 0) {
                                    seqs += LineSequence(seqStartRow, rows.size - 1, seqSeg, seqStartAddr, reg.address)
                                }
                                seqStartRow = -1
                                resetRegs()
                            }
                            DwLne.SET_ADDRESS -> {
                                if (hdr.version >= 5 && hdr.segmentSelectorSize > 0) {
                                    reg.segment = when (hdr.segmentSelectorSize) {
                                        1 -> r.u8()
                                        2 -> r.u16()
                                        4 -> r.u32().toInt()
                                        8 -> r.u64().v.toInt()
                                        else -> throw ParseException("bad segment selector size")
                                    }
                                }
                                reg.address = if (hdr.addressSize == 4) U64(r.u32()) else r.u64()
                                reg.opIndex = 0
                            }
                            DwLne.DEFINE_FILE -> {
                                if (hdr.version <= 4) {
                                    val name = r.cstring()
                                    r.uleb128(); r.uleb128(); r.uleb128()
                                    issues += ParseIssue("info", "LEGACY_DEFINE_FILE",
                                        "v4 DW_LNE_define_file '$name' encountered", lineName, null, cu.offset)
                                }
                            }
                            DwLne.SET_DISCRIMINATOR -> reg.discriminator = r.uleb128().toInt()
                            else -> { /* unknown extended opcode: skip operands via length */ }
                        }
                        if (r.pos < extEnd) r.seek(extEnd)
                    }
                    op < hdr.opcodeBase -> when (op) {
                        DwLns.COPY -> {
                            emitRow(false, "DW_LNS_copy")
                            reg.basicBlock = false; reg.prologueEnd = false
                            reg.epilogueBegin = false; reg.discriminator = 0
                        }
                        DwLns.ADVANCE_PC -> advancePc(r.uleb128().toInt())
                        DwLns.ADVANCE_LINE -> reg.line += r.sleb128().toInt()
                        DwLns.SET_FILE -> reg.file = r.uleb128().toInt()
                        DwLns.SET_COLUMN -> reg.column = r.uleb128().toInt()
                        DwLns.NEGATE_STMT -> reg.isStmt = !reg.isStmt
                        DwLns.SET_BASIC_BLOCK -> reg.basicBlock = true
                        DwLns.CONST_ADD_PC -> {
                            val adjusted = (255 - hdr.opcodeBase) / hdr.lineRange
                            advancePc(adjusted)
                        }
                        DwLns.FIXED_ADVANCE_PC -> {
                            val fixed = r.u16()
                            reg.address = U64(reg.address.v + fixed.toLong())
                            reg.opIndex = 0
                        }
                        DwLns.SET_PROLOGUE_END -> reg.prologueEnd = true
                        DwLns.SET_ISA -> reg.isa = r.uleb128().toInt()
                        0x0c -> if (hdr.version >= 5) reg.epilogueBegin = true else skipStd(r, op, hdr)
                        0x0d -> if (hdr.version >= 5) reg.isa = r.uleb128().toInt() else skipStd(r, op, hdr)
                        else -> skipStd(r, op, hdr)
                    }
                    else -> {
                        val adjusted = op - hdr.opcodeBase
                        val opAdvance = adjusted / hdr.lineRange
                        val lineAdvance = hdr.lineBase + adjusted % hdr.lineRange
                        advancePc(opAdvance)
                        reg.line += lineAdvance
                        emitRow(false, "special opcode $op")
                        reg.basicBlock = false; reg.prologueEnd = false
                        reg.epilogueBegin = false; reg.discriminator = 0
                    }
                }
            }
        } catch (e: ParseException) {
            complete = false
            issues += ParseIssue("error", "BAD_LINE_PROGRAM",
                e.message ?: "line program parse failed", lineName, null, cu.offset)
        }
        if (seqStartRow >= 0) {
            issues += ParseIssue("warning", "UNTERMINATED_SEQUENCE",
                "line program ended without DW_LNE_end_sequence; sequence retained but may be truncated",
                lineName, null, cu.offset)
            seqs += LineSequence(seqStartRow, rows.lastIndex.coerceAtLeast(seqStartRow), seqSeg, seqStartAddr, reg.address)
        }
        return ProgramResult(rows, seqs, issues, complete)
    }

    private fun skipStd(r: ByteReader, op: Int, hdr: Header) {
        val n = hdr.stdOpcodeLengths.getOrNull(op - 1)
            ?: throw ParseException("standard opcode $op >= opcodeBase ${hdr.opcodeBase}")
        repeat(n) { r.uleb128() }
    }
}
