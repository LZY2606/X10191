package compass.dwarf

const val MAX_LINE_ROWS = 500_000

data class LineRow(
    val address: Long,
    val file: Int,
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
)

data class ParsedLineProgram(
    val version: Int,
    val dirs: List<String>,
    val files: List<String>,
    val rows: List<LineRow>,
    val warnings: List<String>,
) {
    /** DWARF4 file indexes are 1-based; DWARF5 are 0-based. */
    fun fileName(index: Int): String? =
        if (version >= 5) files.getOrNull(index) else if (index >= 1) files.getOrNull(index - 1) else null
}

fun parseLineProgram(
    section: ByteArray,
    offset: Long,
    littleEndian: Boolean,
    defaultAddrSize: Int,
): ParsedLineProgram {
    val warnings = mutableListOf<String>()
    if (offset < 0 || offset >= section.size) throw DwarfParseException("line program offset $offset out of bounds")
    val c = Cursor(section, offset.toInt(), section.size, littleEndian)
    var dwarf64 = false
    var unitLength = c.u32()
    if (unitLength == 0xFFFFFFFFL) { dwarf64 = true; unitLength = c.u64() }
    val unitEnd = minOf(c.pos.toLong() + unitLength, section.size.toLong()).toInt()
    val version = c.u16()
    if (version !in 2..5) throw DwarfParseException("unsupported line program version $version")

    var addrSize = defaultAddrSize
    var segmentSelectorSize = 0
    if (version >= 5) {
        addrSize = c.u8()
        segmentSelectorSize = c.u8()
    }
    val headerLength = c.offset(dwarf64)
    val programStart = (c.pos + headerLength).toInt()
    val minInstLen = c.u8()
    val maxOps = if (version >= 4) c.u8().coerceAtLeast(1) else 1
    val defaultIsStmt = c.u8() != 0
    val lineBase = c.i8()
    val lineRange = c.u8().coerceAtLeast(1)
    val opcodeBase = c.u8().coerceAtLeast(1)
    val stdLengths = IntArray(opcodeBase - 1) { c.u8() }

    val dirs = mutableListOf<String>()
    val files = mutableListOf<String>()
    if (version >= 5) {
        val dirFormats = readLnctFormats(c)
        val dirCount = c.uleb()
        repeat(dirCount.toInt().coerceAtMost(100_000)) { dirs += readLnctEntry(c, dirFormats) }
        val fileFormats = readLnctFormats(c)
        val fileCount = c.uleb()
        repeat(fileCount.toInt().coerceAtMost(1_000_000)) { files += readLnctEntry(c, fileFormats) }
    } else {
        while (true) {
            val s = c.cstring()
            if (s.isEmpty()) break
            dirs += s
        }
        while (true) {
            val name = c.cstring()
            if (name.isEmpty()) break
            c.uleb(); c.uleb(); c.uleb() // dir index, mtime, size
            files += name
        }
    }

    val rows = mutableListOf<LineRow>()
    var address = 0L
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
    var sequence = 0

    fun reset() {
        address = 0; opIndex = 0; file = 1; line = 1; column = 0
        isStmt = defaultIsStmt; basicBlock = false; endSequence = false
        prologueEnd = false; epilogueBegin = false; isa = 0; discriminator = 0
    }
    fun advanceAddress(opAdvance: Long) {
        val newOpIndex = opIndex + opAdvance
        address += minInstLen * (newOpIndex / maxOps)
        opIndex = (newOpIndex % maxOps).toInt()
    }
    fun emit() {
        if (rows.size >= MAX_LINE_ROWS) throw DwarfParseException("line row limit exceeded")
        rows += LineRow(address, file, line, column, isStmt, basicBlock, endSequence,
            prologueEnd, epilogueBegin, isa, discriminator, sequence)
        basicBlock = false; prologueEnd = false; epilogueBegin = false; discriminator = 0
    }

    val p = Cursor(section, minOf(programStart, unitEnd), unitEnd, littleEndian)
    while (p.remaining > 0) {
        val op = p.u8()
        if (op == 0) {
            val len = p.uleb().toInt()
            val ext = p.slice(len)
            if (ext.remaining < 1) break
            when (ext.u8()) {
                1 -> { // DW_LNE_end_sequence
                    endSequence = true
                    emit()
                    sequence++
                    reset()
                }
                2 -> { // DW_LNE_set_address
                    if (segmentSelectorSize > 0) ext.bytes(segmentSelectorSize)
                    address = ext.addr(addrSize)
                    opIndex = 0
                }
                3 -> { // DW_LNE_define_file
                    ext.cstring(); ext.uleb(); ext.uleb(); ext.uleb()
                }
                4 -> discriminator = ext.uleb() // DW_LNE_set_discriminator
                else -> { /* unknown extended opcode: skipped via declared length */ }
            }
        } else if (op < opcodeBase) {
            when (op) {
                1 -> emit() // copy
                2 -> advanceAddress(p.uleb()) // advance_pc
                3 -> line += p.sleb() // advance_line
                4 -> file = p.uleb().toInt() // set_file
                5 -> column = p.uleb() // set_column
                6 -> isStmt = !isStmt
                7 -> basicBlock = true
                8 -> { // const_add_pc
                    val opAdvance = (255 - opcodeBase) / lineRange
                    advanceAddress(opAdvance.toLong())
                }
                9 -> { advanceAddress(p.u16().toLong() / minInstLen.coerceAtLeast(1)); } // fixed_advance_pc
                10 -> prologueEnd = true
                11 -> epilogueBegin = true
                12 -> isa = p.uleb()
                else -> { // unknown standard opcode: skip its declared operands
                    val n = stdLengths.getOrElse(op - 1) { 0 }
                    repeat(n) { p.uleb() }
                    warnings += "unknown standard opcode $op skipped ($n operands)"
                }
            }
        } else {
            // special opcode
            val adjusted = op - opcodeBase
            val opAdvance = adjusted / lineRange
            advanceAddress(opAdvance.toLong())
            line += lineBase + (adjusted % lineRange)
            emit()
        }
    }
    return ParsedLineProgram(version, dirs, files, rows, warnings)
}

private fun readLnctFormats(c: Cursor): List<Pair<Long, Long>> {
    val count = c.u8()
    return (0 until count).map { c.uleb() to c.uleb() }
}

private fun readLnctEntry(c: Cursor, formats: List<Pair<Long, Long>>): String {
    var path = ""
    val reader = FormReader(8, false, 5, 0)
    for ((contentType, form) in formats) {
        val v = reader.read(c, form, null)
        if (contentType == DW.LNCT_PATH) {
            path = when (v) {
                is AttrValue.StrV -> v.s
                is AttrValue.StrpV -> "<strp@${v.offset}>"
                else -> path
            }
        }
    }
    return path
}
