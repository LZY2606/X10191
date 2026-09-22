package compass.dwarf

import compass.Limits

data class LineFile(val name: String, val dirIndex: Long, val dir: String?)

data class LineRow(
    val address: Long,
    val segment: Long,
    val file: Int,
    val fileName: String?,
    val line: Long,
    val column: Long,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Long,
    val discriminator: Long,
    val sequence: Int,
    val rowIndex: Int,
    var endAddress: Long = 0,
    var zeroLength: Boolean = false,
)

data class LineTable(
    val version: Int,
    val dwarf64: Boolean,
    val directories: List<String>,
    val files: List<LineFile>,
    val rows: List<LineRow>,
    val warnings: List<String>,
)

private class LineState(defaultIsStmt: Boolean) {
    var address = 0L
    var segment = 0L
    var opIndex = 0
    var file = 1
    var line = 1L
    var column = 0L
    var isStmt = defaultIsStmt
    var basicBlock = false
    var endSequence = false
    var prologueEnd = false
    var epilogueBegin = false
    var isa = 0L
    var discriminator = 0L

    fun reset(defaultStmt: Boolean) {
        address = 0; segment = 0; opIndex = 0; file = 1; line = 1; column = 0
        isStmt = defaultStmt; basicBlock = false; endSequence = false
        prologueEnd = false; epilogueBegin = false; isa = 0; discriminator = 0
    }
}

/**
 * Parses a .debug_line unit at [offset]. Supports DWARF v2-v5 headers, VLIW op_index,
 * segmented addresses and multiple sequences. Never throws on malformed programs:
 * errors become warnings and parsing stops at the unit boundary.
 */
fun parseLineProgram(
    section: ByteArray,
    offset: Int,
    resolveStrp: (Long, Boolean) -> String? = { _, _ -> null },
): LineTable {
    val warnings = ArrayList<String>()
    val r = Reader(section, offset)
    val len0 = r.u32()
    val dwarf64: Boolean
    val unitLen: Long
    if (len0 == 0xFFFF_FFFFL) { dwarf64 = true; unitLen = r.u64() } else { dwarf64 = false; unitLen = len0 }
    if (unitLen > section.size.toLong()) {
        warnings.add("line unit length 0x${unitLen.toString(16)} exceeds section; clamped")
    }
    val unitEnd = minOf(section.size, (r.pos + unitLen).coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
    r.require(minOf(2, unitEnd - r.pos))
    val version = r.u16()
    if (version < 2 || version > 5) warnings.add("unsupported line version $version; attempting parse")

    var addrSize = 8
    var segSize = 0
    if (version >= 5) {
        addrSize = r.u8()
        segSize = r.u8()
    }
    val headerLen = r.offset(dwarf64)
    val headerEnd = minOf(unitEnd, (r.pos + headerLen).coerceAtMost(Int.MAX_VALUE.toLong()).toInt())

    val minInst = r.u8()
    val maxOps = if (version >= 4) r.u8() else 1
    val defaultIsStmt = r.u8() != 0
    val lineBase = r.i8()
    val lineRange = r.u8()
    val opcodeBase = r.u8()
    if (lineRange == 0) throw ParseException("line_range is 0")
    val stdLengths = IntArray(maxOf(0, opcodeBase - 1)) { r.u8() }

    val directories = ArrayList<String>()
    val files = ArrayList<LineFile>()

    fun readLnctValue(form: Int): AttrValue =
        readFormValue(r, form, addrSize, dwarf64)

    if (version >= 5) {
        val dirFmtCount = r.u8()
        val dirFmts = (0 until dirFmtCount).map { r.uleb() to r.uleb() }
        val dirCount = r.uleb()
        if (dirCount > Limits.MAX_FILE_ENTRIES) throw ParseException("too many directories: $dirCount")
        for (i in 0 until dirCount) {
            var path: String? = null
            for ((ct, fm) in dirFmts) {
                val v = readLnctValue(fm.toInt())
                if (ct == 1L) path = stringOf(v, resolveStrp)
            }
            directories.add(path ?: "<dir#$i>")
        }
        val fileFmtCount = r.u8()
        val fileFmts = (0 until fileFmtCount).map { r.uleb() to r.uleb() }
        val fileCount = r.uleb()
        if (fileCount > Limits.MAX_FILE_ENTRIES) throw ParseException("too many files: $fileCount")
        for (i in 0 until fileCount) {
            var name: String? = null
            var dirIdx = 0L
            for ((ct, fm) in fileFmts) {
                val v = readLnctValue(fm.toInt())
                when (ct) {
                    1L -> name = stringOf(v, resolveStrp)
                    2L -> dirIdx = (v as? AttrValue.Num)?.v ?: 0
                }
            }
            val dir = directories.getOrNull(dirIdx.toInt())
            files.add(LineFile(name ?: "<file#$i>", dirIdx, dir))
        }
    } else {
        while (true) {
            if (r.pos >= headerEnd) break
            val s = r.cstr()
            if (s.isEmpty()) break
            if (directories.size >= Limits.MAX_FILE_ENTRIES) throw ParseException("too many directories")
            directories.add(s)
        }
        while (true) {
            if (r.pos >= headerEnd) break
            val name = r.cstr()
            if (name.isEmpty()) break
            if (files.size >= Limits.MAX_FILE_ENTRIES) throw ParseException("too many files")
            val dirIdx = r.uleb()
            r.uleb(); r.uleb() // mtime, size
            val dir = if (dirIdx == 0L) null else directories.getOrNull((dirIdx - 1).toInt())
            files.add(LineFile(name, dirIdx, dir))
        }
    }
    r.pos = headerEnd

    val rows = ArrayList<LineRow>()
    val st = LineState(defaultIsStmt)
    var sequence = 0

    fun fileName(idx: Int): String? {
        val i = if (version >= 5) idx else idx - 1
        return files.getOrNull(i)?.let { f -> if (f.dir != null) "${f.dir}/${f.name}" else f.name }
    }

    fun appendRow() {
        if (rows.size >= Limits.MAX_LINE_ROWS) throw ParseException("too many line rows")
        rows.add(
            LineRow(
                address = st.address, segment = st.segment, file = st.file,
                fileName = fileName(st.file), line = st.line, column = st.column,
                isStmt = st.isStmt, basicBlock = st.basicBlock, endSequence = st.endSequence,
                prologueEnd = st.prologueEnd, epilogueBegin = st.epilogueBegin,
                isa = st.isa, discriminator = st.discriminator,
                sequence = sequence, rowIndex = rows.size,
            )
        )
        st.basicBlock = false; st.prologueEnd = false; st.epilogueBegin = false
        st.discriminator = 0
    }

    fun advance(opAdvance: Long) {
        if (maxOps <= 1) {
            st.address += minInst * opAdvance
        } else {
            val sum = st.opIndex.toLong() + opAdvance
            st.address += minInst * (sum / maxOps)
            st.opIndex = (sum % maxOps).toInt()
        }
    }

    while (r.pos < unitEnd) {
        val opcode = r.u8()
        if (opcode == 0) {
            val len = r.uleb()
            if (len > Int.MAX_VALUE || r.pos + len.toInt() > unitEnd) {
                warnings.add("extended opcode overruns unit at 0x${(r.pos).toString(16)}; stopping")
                break
            }
            val subEnd = r.pos + len.toInt()
            if (len == 0L) continue
            val sub = r.u8()
            when (sub) {
                1 -> { // end_sequence
                    st.endSequence = true
                    appendRow()
                    st.reset(defaultIsStmt)
                    sequence++
                }
                2 -> { // set_address
                    if (version >= 5 && segSize > 0) st.segment = r.addr(segSize)
                    st.address = r.addr(addrSize)
                    st.opIndex = 0
                }
                3 -> { // define_file (pre-v5)
                    val name = r.cstr()
                    val dirIdx = r.uleb(); r.uleb(); r.uleb()
                    val dir = if (dirIdx == 0L) null else directories.getOrNull((dirIdx - 1).toInt())
                    files.add(LineFile(name, dirIdx, dir))
                }
                4 -> st.discriminator = r.uleb()
                else -> warnings.add("unknown extended line opcode $sub at 0x${(r.pos - 1).toString(16)}; skipped")
            }
            r.pos = subEnd
        } else if (opcode < opcodeBase) {
            when (opcode) {
                1 -> appendRow() // copy
                2 -> advance(r.uleb()) // advance_pc
                3 -> st.line += r.sleb() // advance_line
                4 -> st.file = r.uleb().toInt() // set_file
                5 -> st.column = r.uleb() // set_column
                6 -> st.isStmt = !st.isStmt
                7 -> st.basicBlock = true
                8 -> { // const_add_pc
                    val opAdv = (255 - opcodeBase) / lineRange
                    advance(opAdv.toLong())
                }
                9 -> { st.address += r.u16(); st.opIndex = 0 } // fixed_advance_pc
                10 -> st.prologueEnd = true
                11 -> st.epilogueBegin = true
                12 -> st.isa = r.uleb()
                else -> {
                    // Unknown standard opcode: consume declared args to stay in sync.
                    val nargs = stdLengths.getOrNull(opcode - 1) ?: 0
                    repeat(nargs) { r.uleb() }
                    warnings.add("unknown standard line opcode $opcode; consumed $nargs args")
                }
            }
        } else {
            val opAdv = (opcode - opcodeBase) / lineRange
            val lineAdv = lineBase + (opcode - opcodeBase) % lineRange
            advance(opAdv.toLong())
            st.line += lineAdv
            appendRow()
        }
    }

    // Compute row ranges within each sequence.
    var seqStart = 0
    for (i in rows.indices) {
        val row = rows[i]
        if (row.endSequence) {
            row.endAddress = row.address
            row.zeroLength = true
            for (j in seqStart until i) {
                rows[j].endAddress = rows[j + 1].address
                rows[j].zeroLength = rows[j].endAddress == rows[j].address
                if (rows[j].endAddress < rows[j].address)
                    warnings.add("row ${rows[j].rowIndex} has descending address; range kept as-is")
            }
            seqStart = i + 1
        }
    }
    for (j in seqStart until rows.size) { // unterminated final sequence
        rows[j].endAddress = if (j + 1 < rows.size) rows[j + 1].address else rows[j].address
        rows[j].zeroLength = rows[j].endAddress == rows[j].address
    }
    if (rows.isNotEmpty() && rows.last().endSequence.not() && rows.last().endAddress == rows.last().address)
        warnings.add("line program missing final end_sequence")

    return LineTable(version, dwarf64, directories, files, rows, warnings)
}

private fun stringOf(v: AttrValue, resolveStrp: (Long, Boolean) -> String?): String? = when (v) {
    is AttrValue.Str -> v.s
    is AttrValue.Strp -> resolveStrp(v.offset, v.lineStr) ?: "<str@0x${v.offset.toString(16)}>"
    else -> null
}
