package compass.dwarf

import compass.elf.Reader
import compass.elf.Truncated
import compass.model.LineRow
import compass.model.ParseIssue

class LineHeader(
    val version: Int,
    val addrSize: Int,
    val segmentSize: Int,
    val isDwarf64: Boolean,
    val minInstLength: Int,
    val maxOpsPerInst: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val stdOpcodeLengths: IntArray,
    val directories: List<String>,
    val files: List<LineFile>,
    val programStart: Int,
    val unitEnd: Int,
)

class LineFile(val name: String, val dirIndex: Long)

object LineProgram {
    class Result(val rows: List<LineRow>, val issues: List<ParseIssue>, val headerVersion: Int, val files: List<String> = emptyList())

    fun parseHeader(data: ByteArray, offset: Int, bigEndian: Boolean, sections: DwarfSections): LineHeader {
        if (offset < 0 || offset >= data.size) throw BadReference("line table offset $offset out of bounds (size ${data.size})")
        val r = Reader(data, offset, data.size, bigEndian)
        var len = r.u32()
        val dwarf64 = len == 0xFFFFFFFFL
        if (dwarf64) len = r.u64()
        val unitEnd = (r.pos + len).toInt()
        if (unitEnd > data.size) throw Truncated("line unit end $unitEnd beyond section size ${data.size}")
        val version = r.u16()
        var addrSize = 8
        var segSize = 0
        if (version >= 5) {
            addrSize = r.u8()
            segSize = r.u8()
        }
        val headerLen = if (dwarf64) r.u64() else r.u32()
        val programStart = (r.pos + headerLen).toInt()
        if (programStart > unitEnd) throw Truncated("line header overruns unit")
        val minInst = r.u8()
        val maxOps = if (version >= 4) r.u8() else 1
        val defaultStmt = r.u8() != 0
        val lineBase = r.i8()
        val lineRange = r.u8()
        val opcodeBase = r.u8()
        if (opcodeBase == 0 || opcodeBase > 64) throw BadReference("implausible opcode_base $opcodeBase")
        val stdLens = IntArray(opcodeBase - 1) { r.u8() }

        val directories: List<String>
        val files: List<LineFile>
        if (version >= 5) {
            val dirFmtCount = r.u8()
            val dirFmts = (0 until dirFmtCount).map { r.uleb128() to r.uleb128() }
            val dirCount = r.uleb128()
            if (dirCount > Limits.MAX_ABBREV_ATTRS) throw BadReference("too many directories $dirCount")
            val ctx = FormCtx(version, addrSize, dwarf64, sections = sections)
            directories = (0 until dirCount.toInt()).map { idx ->
                var path = ""
                for ((ct, form) in dirFmts) {
                    val v = FormReader.read(r, form, ctx)
                    if (ct == Lnct.PATH) path = v.str ?: v.num.toString()
                }
                path.ifEmpty { "<dir$idx>" }
            }
            val fileFmtCount = r.u8()
            val fileFmts = (0 until fileFmtCount).map { r.uleb128() to r.uleb128() }
            val fileCount = r.uleb128()
            if (fileCount > Limits.MAX_ABBREV_ATTRS) throw BadReference("too many files $fileCount")
            files = (0 until fileCount.toInt()).map {
                var name = ""; var dirIdx = 0L
                for ((ct, form) in fileFmts) {
                    val v = FormReader.read(r, form, ctx)
                    when (ct) {
                        Lnct.PATH -> name = v.str ?: v.num.toString()
                        Lnct.DIRECTORY_INDEX -> dirIdx = v.num
                    }
                }
                LineFile(name, dirIdx)
            }
        } else {
            val dirs = ArrayList<String>()
            while (true) {
                val s = r.cstring()
                if (s.isEmpty()) break
                if (dirs.size > Limits.MAX_ABBREV_ATTRS) throw BadReference("too many directories")
                dirs.add(s)
            }
            val fs = ArrayList<LineFile>()
            while (true) {
                val name = r.cstring()
                if (name.isEmpty()) break
                if (fs.size > Limits.MAX_ABBREV_ATTRS) throw BadReference("too many files")
                val dir = r.uleb128()
                r.uleb128() // mtime
                r.uleb128() // size
                fs.add(LineFile(name, dir))
            }
            directories = dirs
            files = fs
        }
        return LineHeader(version, addrSize, segSize, dwarf64, minInst, maxOps, defaultStmt,
            lineBase, lineRange, opcodeBase, stdLens, directories, files, programStart, unitEnd)
    }

    private class State(h: LineHeader) {
        var address = 0L
        var segment = 0L
        var opIndex = 0
        var file = 1
        var line = 1L
        var column = 0L
        var isStmt = h.defaultIsStmt
        var basicBlock = false
        var endSequence = false
        var prologueEnd = false
        var epilogueBegin = false
        var isa = 0L
        var discriminator = 0L
        fun reset(h: LineHeader) {
            address = 0; segment = 0; opIndex = 0; file = 1; line = 1; column = 0
            isStmt = h.defaultIsStmt; basicBlock = false; endSequence = false
            prologueEnd = false; epilogueBegin = false; isa = 0; discriminator = 0
        }
    }

    fun execute(data: ByteArray, offset: Int, bigEndian: Boolean, sections: DwarfSections, cuIndex: Int): Result {
        val issues = ArrayList<ParseIssue>()
        val rows = ArrayList<LineRow>()
        val h = try { parseHeader(data, offset, bigEndian, sections) }
        catch (e: Exception) {
            issues.add(ParseIssue(".debug_line", offset.toLong(), "error", "line header parse failed: ${e.message}"))
            return Result(rows, issues, -1, emptyList())
        }

        fun fileName(idx: Int): String {
            val v5 = h.version >= 5
            val i = if (v5) idx else idx - 1
            if (i < 0 || i >= h.files.size) return "<bad-file-$idx>"
            val f = h.files[i]
            val dirIdx = if (v5) f.dirIndex.toInt() else f.dirIndex.toInt() - 1
            val dir = if (dirIdx in h.directories.indices) h.directories[dirIdx] else null
            return if (dir.isNullOrEmpty()) f.name else "$dir/${f.name}"
        }

        val st = State(h)
        var seq = 0
        var r = Reader(data, h.programStart, h.unitEnd, bigEndian)
        fun emit() {
            if (rows.size >= Limits.MAX_LINE_ROWS) throw BadReference("line row count exceeds limit")
            rows.add(LineRow(cuIndex, seq, st.address, st.address, st.segment,
                fileName(st.file), st.line, st.column, st.isStmt, st.basicBlock,
                st.prologueEnd, st.epilogueBegin, st.isa, st.discriminator, st.endSequence))
        }

        try {
            while (!r.exhausted()) {
                val opPos = r.pos
                val opcode = r.u8()
                when {
                    opcode == 0 -> {
                        val len = r.uleb128()
                        val end = r.pos + len.toInt()
                        if (end > h.unitEnd) throw Truncated("extended opcode overruns unit at $opPos")
                        if (len == 0L) continue
                        val sub = r.u8()
                        when (sub) {
                            Lne.END_SEQUENCE -> {
                                st.endSequence = true
                                emit()
                                seq++
                                st.reset(h)
                            }
                            Lne.SET_ADDRESS -> {
                                if (h.segmentSize > 0) {
                                    st.segment = 0
                                    for (i in 0 until h.segmentSize) st.segment = st.segment or (r.u8().toLong() shl (8 * i))
                                }
                                var a = 0L
                                for (i in 0 until h.addrSize) a = a or (r.u8().toLong() shl (8 * i))
                                st.address = a
                                st.opIndex = 0
                            }
                            Lne.DEFINE_FILE -> { r.cstring(); r.uleb128(); r.uleb128(); r.uleb128() }
                            Lne.SET_DISCRIMINATOR -> st.discriminator = r.uleb128()
                            else -> { /* skip unknown extended opcode via its length */ }
                        }
                        r.pos = end
                    }
                    opcode < h.opcodeBase -> when (opcode) {
                        Lns.COPY -> { emit(); st.discriminator = 0; st.basicBlock = false; st.prologueEnd = false; st.epilogueBegin = false }
                        Lns.ADVANCE_PC -> {
                            val arg = r.uleb128()
                            advance(st, h, arg)
                        }
                        Lns.ADVANCE_LINE -> st.line += r.sleb128()
                        Lns.SET_FILE -> st.file = r.uleb128().toInt()
                        Lns.SET_COLUMN -> st.column = r.uleb128()
                        Lns.NEGATE_STMT -> st.isStmt = !st.isStmt
                        Lns.SET_BASIC_BLOCK -> st.basicBlock = true
                        Lns.CONST_ADD_PC -> {
                            val adjusted = 255 - h.opcodeBase
                            advance(st, h, (adjusted / h.lineRange).toLong())
                        }
                        Lns.FIXED_ADVANCE_PC -> { st.address += r.u16(); st.opIndex = 0 }
                        Lns.SET_PROLOGUE_END -> st.prologueEnd = true
                        Lns.SET_EPILOGUE_BEGIN -> st.epilogueBegin = true
                        Lns.SET_ISA -> st.isa = r.uleb128()
                        else -> {
                            // Unrecognised standard opcode: skip its declared operands.
                            val n = if (opcode - 1 < h.stdOpcodeLengths.size) h.stdOpcodeLengths[opcode - 1] else 0
                            repeat(n) { r.uleb128() }
                        }
                    }
                    else -> {
                        val adjusted = opcode - h.opcodeBase
                        val opAdv = adjusted / h.lineRange
                        advance(st, h, opAdv.toLong())
                        st.line += h.lineBase + (adjusted % h.lineRange)
                        emit()
                        st.basicBlock = false; st.prologueEnd = false; st.epilogueBegin = false; st.discriminator = 0
                    }
                }
            }
        } catch (e: Exception) {
            issues.add(ParseIssue(".debug_line", r.pos.toLong(), "error", "line program aborted: ${e.message}"))
        }

        // Fill endAddress: each row ends where the next row of the same sequence begins.
        for (i in rows.indices) {
            val row = rows[i]
            val next = rows.getOrNull(i + 1)
            row.endAddress = if (next != null && next.sequence == row.sequence && !row.endSequence) next.address else row.address
        }
        val fileTable = (0 until h.files.size).map { fileName(if (h.version >= 5) it else it + 1) }
        return Result(rows, issues, h.version, fileTable)
    }

    private fun advance(st: State, h: LineHeader, opAdvance: Long) {
        if (h.maxOpsPerInst > 1) {
            val newOp = st.opIndex + opAdvance.toInt()
            st.address += h.minInstLength * (newOp / h.maxOpsPerInst)
            st.opIndex = newOp % h.maxOpsPerInst
        } else {
            st.address += h.minInstLength * opAdvance
        }
    }
}
