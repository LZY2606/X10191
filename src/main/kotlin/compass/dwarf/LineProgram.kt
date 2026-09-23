package compass.dwarf

data class LineFile(val name: String, val dirIndex: Long, val dir: String?)

data class LineRow(
    val sequence: Int,
    val address: Long,
    val file: Int,
    val fileName: String,
    val line: Long,
    val column: Long,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val discriminator: Long,
)

data class LineProgramResult(
    val version: Int,
    val rows: List<LineRow>,
    val files: List<LineFile>,
    val directories: List<String>,
    val warnings: List<String>,
)

object LineProgramParser {
    private const val MAX_ROWS = 1_000_000

    /** Parses one line-number program at [offset] in .debug_line. */
    fun parse(
        lineData: ByteArray,
        offset: Long,
        addrSize: Int,
        strData: ByteArray?,
        lineStrData: ByteArray?,
        bigEndian: Boolean = false,
    ): LineProgramResult {
        val warnings = mutableListOf<String>()
        if (offset < 0 || offset >= lineData.size) throw DwarfException(".debug_line: offset 0x${offset.toString(16)} out of bounds")
        val r = Reader(lineData, ".debug_line", offset.toInt(), bigEndian)
        val (unitLength, dwarf64) = r.initialLength()
        val unitEnd = (r.pos + unitLength).coerceAtMost(lineData.size.toLong())
        if (r.pos + unitLength > lineData.size) warnings.add("line program length exceeds section; clamped")
        val version = r.u16()
        if (version < 2 || version > 5) throw DwarfException(".debug_line: unsupported version $version")

        var segmentSize = 0
        var actualAddrSize = addrSize
        if (version >= 5) {
            actualAddrSize = r.u8()
            segmentSize = r.u8()
        }
        val headerLength = if (dwarf64) r.u64() else r.u32()
        val programStart = (r.pos + headerLength).coerceAtMost(unitEnd)
        if (r.pos + headerLength > unitEnd) warnings.add("line header length exceeds unit; clamped")

        val minInstLen = r.u8()
        val maxOpsPerInst = if (version >= 4) r.u8() else 1
        val defaultIsStmt = r.u8() != 0
        val lineBase = r.i8()
        val lineRange = r.u8()
        val opcodeBase = r.u8()
        if (lineRange == 0) throw DwarfException(".debug_line: line_range is zero")
        if (opcodeBase < 1 || opcodeBase > 64) throw DwarfException(".debug_line: implausible opcode_base $opcodeBase")
        val stdOpcodeLens = IntArray(opcodeBase)
        for (i in 1 until opcodeBase) stdOpcodeLens[i] = r.u8()

        fun resolveStr(v: AttrValue): String = when (v) {
            is AttrValue.Str -> v.value
            is AttrValue.StrOffset -> {
                val tab = if (v.lineStr) lineStrData else strData
                if (tab == null) { warnings.add("string table missing for strp"); "<missing-str>" }
                else runCatching { Reader(tab, "str").cstringAt(v.offset) }.getOrElse { "<bad-str>" }
            }
            is AttrValue.Data -> "<0x${v.value.toString(16)}>"
            else -> "<?>"
        }

        val directories = mutableListOf<String>()
        val files = mutableListOf<LineFile>()

        if (version >= 5) {
            val fd = FormDecoder(version, actualAddrSize, dwarf64, bigEndian)
            val dirFmtCount = r.u8()
            val dirFmts = (0 until dirFmtCount).map { readContentEntryFormat() }
            val dirCount = r.uleb128()
            repeat(dirCount.toInt().coerceAtMost(100_000)) {
                var dir = ""
                for ((_, form) in dirFmts) {
                    val v = fd.read(r, form)
                    dir = resolveStr(v)
                }
                directories.add(dir)
            }
            val fileFmtCount = r.u8()
            val fileFmts = (0 until fileFmtCount).map { readContentEntryFormat() }
            val fileCount = r.uleb128()
            repeat(fileCount.toInt().coerceAtMost(1_000_000)) {
                var name = ""; var dirIdx = 0L
                for ((contentType, form) in fileFmts) {
                    val v = fd.read(r, form)
                    when (contentType) {
                        1 -> name = resolveStr(v) // DW_LNCT_path
                        2 -> dirIdx = (v as? AttrValue.Data)?.value ?: 0 // DW_LNCT_directory_index
                    }
                }
                val dir = directories.getOrNull(dirIdx.toInt())
                files.add(LineFile(name, dirIdx, dir))
            }
        } else {
            // DWARF2-4: null-terminated directory list then file list
            while (true) {
                val s = r.cstring()
                if (s.isEmpty()) break
                directories.add(s)
            }
            while (true) {
                val name = r.cstring()
                if (name.isEmpty()) break
                val dirIdx = r.uleb128()
                r.uleb128() // mtime
                r.uleb128() // size
                val dir = if (dirIdx == 0L) null else directories.getOrNull(dirIdx.toInt() - 1)
                files.add(LineFile(name, dirIdx, dir))
            }
        }

        // ---- VM ----
        var address = 0L
        var segment = 0L
        var file = 1
        var line = 1L
        var column = 0L
        var isStmt = defaultIsStmt
        var basicBlock = false
        var endSequence = false
        var discriminator = 0L
        var sequence = 0
        val rows = mutableListOf<LineRow>()

        fun fileName(idx: Int): String {
            if (version >= 5) return files.getOrNull(idx)?.let { f -> listOfNotNull(f.dir, f.name).joinToString("/") } ?: "<file#$idx>"
            if (idx == 0) return "<none>"
            return files.getOrNull(idx - 1)?.let { f -> listOfNotNull(f.dir, f.name).joinToString("/") } ?: "<file#$idx>"
        }

        fun emit() {
            if (rows.size >= MAX_ROWS) throw DwarfException(".debug_line: row limit exceeded")
            rows.add(LineRow(sequence, address, file, fileName(file), line, column, isStmt, basicBlock, endSequence, discriminator))
            basicBlock = false
            discriminator = 0
        }

        fun reset() {
            address = 0; segment = 0; file = 1; line = 1; column = 0
            isStmt = defaultIsStmt; basicBlock = false; endSequence = false; discriminator = 0
        }

        r.seek(programStart.toInt())
        while (r.pos < unitEnd && !r.eof()) {
            val opcode = r.u8()
            if (opcode == 0) {
                // extended
                val len = r.uleb128()
                val end = r.pos + len
                if (end > unitEnd) { warnings.add("extended opcode overruns unit"); break }
                if (len == 0L) continue
                val sub = r.u8()
                when (sub) {
                    Dw.LNE_end_sequence -> { endSequence = true; emit(); sequence++; reset() }
                    Dw.LNE_set_address -> {
                        address = when (actualAddrSize) { 4 -> r.u32(); 8 -> r.u64(); else -> r.bytes(actualAddrSize).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xFF) } }
                        if (segmentSize > 0) segment = r.bytes(segmentSize).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xFF) }
                    }
                    Dw.LNE_define_file -> {
                        val name = r.cstring(); val dirIdx = r.uleb128(); r.uleb128(); r.uleb128()
                        val dir = if (dirIdx == 0L) null else directories.getOrNull(dirIdx.toInt() - 1)
                        files.add(LineFile(name, dirIdx, dir))
                    }
                    Dw.LNE_set_discriminator -> { discriminator = r.uleb128() }
                    else -> r.seek(end.toInt()) // skip unknown extended opcode by length
                }
                if (r.pos < end) r.seek(end.toInt())
            } else if (opcode < opcodeBase) {
                when (opcode) {
                    Dw.LNS_copy -> emit()
                    Dw.LNS_advance_pc -> address += r.uleb128() * minInstLen
                    Dw.LNS_advance_line -> line += r.sleb128()
                    Dw.LNS_set_file -> file = r.uleb128().toInt()
                    Dw.LNS_set_column -> column = r.uleb128()
                    Dw.LNS_negate_stmt -> isStmt = !isStmt
                    Dw.LNS_set_basic_block -> basicBlock = true
                    Dw.LNS_const_add_pc -> address += ((255 - opcodeBase) / lineRange) * minInstLen
                    Dw.LNS_fixed_advance_pc -> address += r.u16()
                    Dw.LNS_set_prologue_end, Dw.LNS_set_epilogue_begin -> Unit
                    Dw.LNS_set_isa -> r.uleb128()
                    else -> {
                        // unknown standard opcode: skip its declared operands to stay aligned
                        repeat(stdOpcodeLens.getOrElse(opcode) { 0 }) { r.uleb128() }
                    }
                }
            } else {
                // special opcode
                val adjusted = opcode - opcodeBase
                val opAdvance = adjusted / lineRange
                address += (opAdvance * minInstLen)
                line += lineBase + (adjusted % lineRange)
                emit()
            }
        }
        if (segment != 0L) warnings.add("non-zero segment selector 0x${segment.toString(16)} in line program")
        return LineProgramResult(version, rows, files, directories, warnings)
    }

    private fun Reader.readContentEntryFormat(): Pair<Int, Int> = uleb128().toInt() to uleb128().toInt()
}
