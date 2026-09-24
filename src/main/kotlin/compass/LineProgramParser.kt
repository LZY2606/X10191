package compass

import java.math.BigInteger

object LineProgramParser {
    private data class Header(
        val version: Int, val addressSize: Int, val segmentSize: Int, val minInstructionLength: Int,
        val maxOpsPerInstruction: Int, val defaultIsStmt: Boolean, val lineBase: Int, val lineRange: Int,
        val opcodeBase: Int, val standardLengths: List<Int>, val files: MutableList<SourceFile>,
        val directories: MutableList<String>, val programOffset: Long
    )

    fun parse(lineBytes: ByteArray, offset: Long, unit: DwarfUnit, endian: Int, lineStrings: ByteArray, strings: ByteArray): UnitLines {
        if (offset < 0 || offset >= lineBytes.size) throw CursorException("line program offset out of bounds", offset)
        val reader = ByteReader(lineBytes)
        reader.pos = offset.toInt()
        val first = reader.u32(endian)
        val is64 = first == 0xffffffffL
        val length = if (is64) reader.u64(endian) else first
        if (length < 1) throw CursorException("invalid line program length")
        val end = reader.pos + (if (is64) 8 else 0) + length
        if (end > lineBytes.size) throw CursorException("line program exceeds section")
        val version = reader.u16(endian)
        if (version !in 2..5) throw CursorException("unsupported line program version $version")
        val header = if (version >= 5) readV5Header(reader, unit, endian, lineStrings, strings) else readV4Header(reader, unit, endian)
        reader.pos = (offset + header.programOffset).toInt()

        val rows = mutableListOf<LineRow>()
        val sequences = mutableListOf<LineSequence>()
        var state = State(header.defaultIsStmt)
        var sequenceStart = 0L
        var sequenceSegment = 0
        var rowOrdinal = 0
        fun file(index: Int?): SourceFile? = index?.let { header.files.getOrNull(it) }
        fun emit(endSequence: Boolean) {
            val row = LineRow(
                ordinal = rowOrdinal++, address = state.address, segment = state.segment, fileOrdinal = state.file,
                fileName = file(state.file)?.path, line = state.line, column = state.column, isa = state.isa,
                discriminator = state.discriminator, isStmt = state.isStmt, basicBlock = state.basicBlock,
                prologueEnd = state.prologueEnd, epilogueBegin = state.epilogueBegin, endSequence = endSequence
            )
            rows += row
            state.basicBlock = false; state.prologueEnd = false; state.epilogueBegin = false; state.discriminator = 0
        }
        while (reader.pos < end) {
            val opcode = reader.u8()
            when {
                opcode == 0 -> {
                    val extLen = reader.uleb().toInt()
                    val extEnd = reader.pos + extLen
                    if (extEnd > end) throw CursorException("extended opcode crosses line program")
                    when (val ext = reader.u8()) {
                        DwarfConstants.DW_LNE_end_sequence -> {
                            emit(true)
                            val seqRows = rows.dropWhile { it.address < sequenceStart }.filter { it.segment == sequenceSegment }
                            sequences += LineSequence(sequences.size, sequenceStart, state.address, sequenceSegment, rows.filter { rowsForSequence(it, sequenceStart, sequenceSegment, rows) })
                            state = State(header.defaultIsStmt)
                        }
                        DwarfConstants.DW_LNE_set_address -> {
                            if (header.segmentSize > 0) state.segment = reader.uint(header.segmentSize, endian).toInt()
                            state.address = reader.uint(header.addressSize, endian)
                            sequenceStart = state.address; sequenceSegment = state.segment
                        }
                        DwarfConstants.DW_LNE_define_file -> {
                            if (version < 5) {
                                val name = reader.string(); val dirIndex = reader.uleb().toInt(); reader.uleb(); reader.uleb()
                                header.files += SourceFile(header.files.size, name, header.directories.getOrNull(dirIndex) ?: unit.compDir.orEmpty())
                            } else throw CursorException("DW_LNE_define_file is invalid in DWARF 5")
                        }
                        DwarfConstants.DW_LNE_set_discriminator -> state.discriminator = reader.uleb().toInt()
                        else -> {
                            if (reader.pos != extEnd) reader.pos = extEnd
                        }
                    }
                    reader.pos = extEnd
                }
                opcode < header.opcodeBase -> {
                    val operands = if (opcode - 1 in header.standardLengths.indices) header.standardLengths[opcode - 1] else throw CursorException("unknown standard opcode $opcode")
                    val args = (0 until operands).map { reader.uleb() }
                    when (opcode) {
                        DwarfConstants.DW_LNS_copy -> emit(false)
                        DwarfConstants.DW_LNS_advance_pc -> state.address += (args[0].toInt() * header.minInstructionLength)
                        DwarfConstants.DW_LNS_advance_line -> state.line += args[0].toInt()
                        DwarfConstants.DW_LNS_set_file -> state.file = args[0].toInt()
                        DwarfConstants.DW_LNS_set_column -> state.column = args[0].toInt()
                        DwarfConstants.DW_LNS_negate_stmt -> state.isStmt = !state.isStmt
                        DwarfConstants.DW_LNS_set_basic_block -> state.basicBlock = true
                        DwarfConstants.DW_LNS_const_add_pc -> state.address += ((255 - header.opcodeBase) / header.lineRange) * header.minInstructionLength
                        DwarfConstants.DW_LNS_fixed_advance_pc -> state.address += reader.u16(endian).toLong()
                        DwarfConstants.DW_LNS_set_prologue_end -> state.prologueEnd = true
                        DwarfConstants.DW_LNS_set_epilogue_begin -> state.epilogueBegin = true
                        DwarfConstants.DW_LNS_set_isa -> state.isa = args[0].toInt()
                    }
                }
                else -> {
                    val adjusted = opcode - header.opcodeBase
                    val addressAdvance = adjusted / header.lineRange
                    val lineAdvance = header.lineBase + adjusted % header.lineRange
                    state.address += addressAdvance * header.minInstructionLength
                    state.line += lineAdvance
                    emit(false)
                }
            }
        }
        val fixedSequences = sequences.mapIndexed { index, seq -> seq.copy(rows = rows.filter { row -> belongs(row, seq) }) }
        return UnitLines(unit.ordinal, version, header.addressSize, header.segmentSize, offset, header.files, fixedSequences, emptyList())
    }

    private data class State(
        val defaultIsStmt: Boolean, var address: Long = 0, var segment: Int = 0, var file: Int? = null,
        var line: Int = 1, var column: Int = 0, var isStmt: Boolean = defaultIsStmt, var basicBlock: Boolean = false,
        var prologueEnd: Boolean = false, var epilogueBegin: Boolean = false, var isa: Int = 0, var discriminator: Int = 0
    )

    private fun rowsForSequence(row: LineRow, start: Long, segment: Int, allRows: List<LineRow>): Boolean = row.address >= start && row.segment == segment
    private fun belongs(row: LineRow, sequence: LineSequence): Boolean = row.segment == sequence.segment &&
        if (sequence.startAddress == sequence.endAddress) row.address == sequence.startAddress
        else row.address >= sequence.startAddress && row.address <= sequence.endAddress

    private fun readV4Header(reader: ByteReader, unit: DwarfUnit, endian: Int): Header {
        val headerLength = reader.u32(endian)
        val headerStart = reader.pos
        val min = reader.u8(); reader.u8(); reader.u8()
        val defaultStmt = reader.u8() == 1
        val lineBase = reader.s8(); val lineRange = reader.u8(); val opcodeBase = reader.u8()
        val standardLengths = (1 until opcodeBase).map { reader.u8().toInt() }
        val directories = mutableListOf(unit.compDir.orEmpty())
        while (true) { val value = reader.string(); if (value.isEmpty()) break; directories += value }
        val files = mutableListOf(SourceFile(0, "", ""))
        while (true) {
            val name = reader.string(); if (name.isEmpty()) break
            val dirIndex = reader.uleb().toInt(); reader.uleb(); reader.uleb()
            files += SourceFile(files.size, name, directories.getOrElse(dirIndex) { unit.compDir.orEmpty() })
        }
        val programOffset = (headerStart + headerLength).toLong() - ByteReader(ByteArray(0)).base
        return Header(4, unit.addressSize, 0, min, 1, defaultStmt, lineBase, lineRange, opcodeBase, standardLengths, files, directories, programOffset)
    }

    private fun readV5Header(reader: ByteReader, unit: DwarfUnit, endian: Int, lineStrings: ByteArray, strings: ByteArray): Header {
        val addressSize = reader.u8(); val segmentSize = reader.u8(); val headerLength = reader.u32(endian)
        val headerStart = reader.pos
        val min = reader.u8(); val maxOps = reader.u8(); val defaultStmt = reader.u8() == 1
        val lineBase = reader.s8(); val lineRange = reader.u8(); val opcodeBase = reader.u8()
        val standardLengths = (1 until opcodeBase).map { reader.u8().toInt() }
        val directoryEntryFormatCount = reader.u8(); val directoryCount = reader.u32(endian)
        val directoryFormats = (0 until directoryEntryFormatCount).map { reader.uleb().toInt() to reader.uleb().toInt() }
        val directories = mutableListOf(unit.compDir.orEmpty())
        repeat(directoryCount.toInt()) { directories += readPathEntry(reader, directoryFormats, endian, strings, lineStrings, directories) }
        val fileEntryFormatCount = reader.u8(); val fileCount = reader.u32(endian)
        val fileFormats = (0 until fileEntryFormatCount).map { reader.uleb().toInt() to reader.uleb().toInt() }
        val files = mutableListOf<SourceFile>()
        repeat(fileCount.toInt()) { index ->
            val (path, dirIndex) = readPathEntryWithIndex(reader, fileFormats, endian, strings, lineStrings, directories)
            files += SourceFile(index, path, directories.getOrElse(dirIndex) { unit.compDir.orEmpty() })
        }
        val programOffset = (headerStart.toLong() + headerLength)
        return Header(5, addressSize, segmentSize, min, maxOps, defaultStmt, lineBase, lineRange, opcodeBase, standardLengths, files, directories, programOffset)
    }

    private fun readPathEntry(reader: ByteReader, formats: List<Pair<Int, Int>>, endian: Int, strings: ByteArray, lineStrings: ByteArray, directories: MutableList<String>): String =
        readPathEntryWithIndex(reader, formats, endian, strings, lineStrings, directories).first

    private fun readPathEntryWithIndex(reader: ByteReader, formats: List<Pair<Int, Int>>, endian: Int, strings: ByteArray, lineStrings: ByteArray, directories: List<String>): Pair<String, Int> {
        var path = ""; var dirIndex = 0
        for ((contentType, form) in formats) {
            val value = readHeaderForm(reader, form, endian, strings, lineStrings)
            when (contentType) {
                DwarfConstants.DW_LNCT_path -> path = value
                DwarfConstants.DW_LNCT_directory_index -> dirIndex = reader.lastInteger.toInt()
            }
        }
        return path to dirIndex
    }

    private var ByteReader.lastInteger: Long get() = 0; set(_) {}

    private fun readHeaderForm(reader: ByteReader, form: Int, endian: Int, strings: ByteArray, lineStrings: ByteArray): String {
        return when (form) {
            DwarfConstants.DW_FORM_string -> reader.string()
            DwarfConstants.DW_FORM_line_strp -> ByteReader(lineStrings).stringAt(reader.u32(endian))
            DwarfConstants.DW_FORM_strp -> ByteReader(strings).stringAt(reader.u32(endian))
            DwarfConstants.DW_FORM_data1, DwarfConstants.DW_FORM_strx1, DwarfConstants.DW_FORM_addrx1 -> reader.u8().toString()
            DwarfConstants.DW_FORM_data2, DwarfConstants.DW_FORM_strx2, DwarfConstants.DW_FORM_addrx2 -> reader.u16(endian).toString()
            DwarfConstants.DW_FORM_udata, DwarfConstants.DW_FORM_strx, DwarfConstants.DW_FORM_addrx -> reader.uleb().toString()
            DwarfConstants.DW_FORM_data4, DwarfConstants.DW_FORM_strx4, DwarfConstants.DW_FORM_addrx4 -> reader.u32(endian).toString()
            else -> throw UnknownFormException(form)
        }
    }
}
