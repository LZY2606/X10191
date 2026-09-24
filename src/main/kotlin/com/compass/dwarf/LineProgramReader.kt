package com.compass.dwarf

class LineProgramReader(
    private val sections: Map<String, ByteArray>,
    private val unit: UnitContext,
    private val statementOffset: Long,
    littleEndian: Boolean
) {
    private val data = sections[".debug_line"] ?: throw DwarfParseException("Missing .debug_line")
    private val c = BinaryCursor(data, littleEndian = littleEndian)
    private var minimumInstructionLength = 1
    private var maximumOperationsPerInstruction = 1
    private var defaultIsStatement = true
    private var lineBase = 0
    private var lineRange = 1
    private var opcodeBase = 13
    private var standardLengths = IntArray(0)
    private val files = mutableListOf<LineFile>()
    private val directories = mutableListOf<String>()
    private var addressSize = unit.addressSize
    private var segmentSize = 0
    private val rows = mutableListOf<LineRow>()
    private var rowIndex = 0

    private inner class State {
        var segment = 0L
        var address = 0L
        var file = if (unit.version >= 5) 0 else 1
        var line = 1
        var column = 0
        var isStatement = defaultIsStatement
        var basicBlock = false
        var endSequence = false
        var prologueEnd = false
        var epilogueBegin = false
        var isa = 0
        var discriminator = 0
        var operationIndex = 0
        fun copyState() = State().also {
            it.segment = segment; it.address = address; it.file = file; it.line = line; it.column = column
            it.isStatement = isStatement; it.basicBlock = basicBlock; it.endSequence = endSequence
            it.prologueEnd = prologueEnd; it.epilogueBegin = epilogueBegin; it.isa = isa
            it.discriminator = discriminator; it.operationIndex = operationIndex
        }
    }

    fun parse(): LineProgram? {
        if (statementOffset == 0L || statementOffset >= data.size) return null
        c.localSeek(statementOffset.toInt())
        val sectionStart = c.absolutePosition()
        val first = c.u32()
        val dwarf64 = first == 0xffffffffL
        val length = if (dwarf64) c.u64() else first
        val end = sectionStart + 4 + (if (dwarf64) 12 else 4) + length
        val version = c.u16()
        if (version !in 2..5) throw DwarfParseException("Unsupported line program version $version")
        if (version >= 5) {
            addressSize = c.u8()
            segmentSize = c.u8()
        }
        val headerLength = readInitialLength(dwarf64)
        val headerStart = c.absolutePosition()
        val programStart = headerStart + headerLength
        minimumInstructionLength = c.u8()
        if (version >= 4) maximumOperationsPerInstruction = c.u8().coerceAtLeast(1)
        defaultIsStatement = c.u8() != 0
        lineBase = c.i8()
        lineRange = c.u8()
        opcodeBase = c.u8()
        if (opcodeBase <= 0) throw DwarfParseException("Bad line opcode base")
        standardLengths = IntArray(opcodeBase - 1) { c.u8() }
        if (version >= 5) parseV5Paths() else parseV4Paths()
        c.seek(programStart)
        runStateMachine(end)
        return LineProgram(
            unit.start, statementOffset, version, minimumInstructionLength,
            maximumOperationsPerInstruction, defaultIsStatement, lineBase, lineRange,
            opcodeBase, files.toList(), directories.toList(), buildSequences(), rows.toList()
        )
    }

    private fun readInitialLength(dwarf64: Boolean): Long = if (dwarf64) c.u64() else c.u32()

    private fun parseV4Paths() {
        while (true) {
            val directory = c.cString()
            if (directory.isEmpty()) break
            directories += directory
        }
        var index = 1
        while (true) {
            val name = c.cString()
            if (name.isEmpty()) break
            val directoryIndex = c.uleb().toInt()
            c.uleb(); c.uleb()
            files += LineFile(index++, name, directoryIndex)
        }
    }

    private data class EntryFormat(val type: Long, val form: Int)

    private fun parseV5Paths() {
        val dirFormats = parseFormats()
        val directoryCount = c.uleb()
        repeat(directoryCount.toInt()) { index ->
            val values = parsePathEntry(dirFormats)
            directories += values.text ?: ""
        }
        val fileFormats = parseFormats()
        val fileCount = c.uleb()
        repeat(fileCount.toInt()) { index ->
            val values = parsePathEntry(fileFormats)
            files += LineFile(index, values.text ?: "?", values.directoryIndex)
        }
    }

    private fun parseFormats(): List<EntryFormat> {
        val count = c.u8()
        return List(count) { EntryFormat(c.uleb(), c.uleb().toInt()) }
    }

    private data class PathValues(var text: String? = null, var directoryIndex: Int? = null)

    private fun parsePathEntry(formats: List<EntryFormat>): PathValues {
        val values = PathValues()
        formats.forEach { format ->
            val raw = readLineForm(format.form)
            when (format.type) {
                1L, 4L, 2L -> when (raw) {
                    is AttrValue.TextValue -> values.text = raw.value
                    is AttrValue.NumberValue -> if (format.type == 2L) values.directoryIndex = raw.value.toInt()
                    else -> {}
                }
            }
        }
        return values
    }

    private fun readLineForm(form: Int): AttrValue = when (form) {
        DwarfConst.DW_FORM_STRING -> AttrValue.TextValue(c.cString())
        DwarfConst.DW_FORM_LINE_STRP -> readLineString(c.u32(), ".debug_line_str")
        DwarfConst.DW_FORM_STRP -> readLineString(c.u32(), ".debug_str")
        DwarfConst.DW_FORM_DATA1, DwarfConst.DW_FORM_STRX1, DwarfConst.DW_FORM_ADDRX1 -> AttrValue.NumberValue(c.u8().toLong())
        DwarfConst.DW_FORM_DATA2, DwarfConst.DW_FORM_STRX2 -> AttrValue.NumberValue(c.u16().toLong())
        DwarfConst.DW_FORM_DATA4 -> AttrValue.NumberValue(c.u32())
        DwarfConst.DW_FORM_DATA8 -> AttrValue.NumberValue(c.u64())
        DwarfConst.DW_FORM_UDATA, DwarfConst.DW_FORM_STRX, DwarfConst.DW_FORM_ADDRX -> AttrValue.NumberValue(c.uleb())
        DwarfConst.DW_FORM_BLOCK1 -> AttrValue.BytesValue(c.bytes(c.u8()))
        DwarfConst.DW_FORM_BLOCK2 -> AttrValue.BytesValue(c.bytes(c.u16()))
        else -> throw DwarfParseException("Unsupported line path form 0x${form.toString(16)}")
    }

    private fun readLineString(offset: Long, section: String): AttrValue.TextValue {
        val bytes = sections[section] ?: throw DwarfParseException("Missing $section")
        val cursor = BinaryCursor(bytes)
        return AttrValue.TextValue(cursor.cStringAt(offset))
    }

    private fun runStateMachine(end: Long) {
        var state = State()
        while (c.absolutePosition() < end) {
            when (val opcode = c.u8()) {
                0 -> {
                    val length = c.uleb().toInt()
                    val after = c.absolutePosition() + length
                    val extended = c.u8()
                    handleExtended(extended, state)
                    c.seek(after)
                }
                in 1 until opcodeBase -> handleStandard(opcode, state)
                else -> handleSpecial(opcode, state)
            }
            if (state.endSequence) {
                emit(state)
                state = State()
            }
        }
    }

    private fun handleExtended(opcode: Int, state: State) {
        when (opcode) {
            DwarfConst.DW_LNS_SET_ADDRESS -> {
                if (unit.version >= 5 && segmentSize > 0) state.segment = readNumber(segmentSize)
                state.address = readNumber(addressSize)
                state.operationIndex = 0
            }
            DwarfConst.DW_LNS_END_SEQUENCE -> state.endSequence = true
            DwarfConst.DW_LNS_SET_DISC -> state.discriminator = c.uleb().toInt()
            DwarfConst.DW_LNS_SET_ENTRY -> state.basicBlock = true
            DwarfConst.DW_LNS_SET_EPILOGUE -> state.epilogueBegin = c.u8() != 0
            DwarfConst.DW_LNS_SET_ISA_EXT -> state.isa = c.uleb().toInt()
            DwarfConst.DW_LNS_DEFINE_FILE -> if (unit.version < 5) {
                val name = c.cString(); val dir = c.uleb().toInt(); c.uleb(); c.uleb()
                files += LineFile(files.size + 1, name, dir)
            }
        }
    }

    private fun handleStandard(opcode: Int, state: State) {
        when (opcode) {
            DwarfConst.DW_LNS_COPY -> emit(state)
            DwarfConst.DW_LNS_ADVANCE_PC -> state.address += c.uleb()
            DwarfConst.DW_LNS_ADVANCE_LINE -> state.line += c.sleb().toInt()
            DwarfConst.DW_LNS_SET_FILE -> state.file = c.uleb().toInt()
            DwarfConst.DW_LNS_SET_COLUMN -> state.column = c.uleb().toInt()
            DwarfConst.DW_LNS_NEGATE_STMT -> state.isStatement = !state.isStatement
            DwarfConst.DW_LNS_SET_BASIC_BLOCK -> state.basicBlock = true
            DwarfConst.DW_LNS_CONST_ADD_PC -> state.address += constAdvance()
            DwarfConst.DW_LNS_FIXED_ADVANCE_PC -> { state.address += c.u16().toLong(); state.operationIndex = 0 }
            DwarfConst.DW_LNS_SET_PROLOGUE_END -> state.prologueEnd = true
            DwarfConst.DW_LNS_SET_ISA -> state.isa = c.uleb().toInt()
        }
    }

    private fun handleSpecial(opcode: Int, state: State) {
        val adjusted = opcode - opcodeBase
        val addressAdvance = minimumInstructionLength * ((adjusted / lineRange) + state.operationIndex / maximumOperationsPerInstruction)
        state.address += addressAdvance
        state.line += lineBase + (adjusted % lineRange)
        emit(state)
        state.basicBlock = false; state.prologueEnd = false; state.epilogueBegin = false; state.discriminator = 0
    }

    private fun constAdvance(): Int = minimumInstructionLength * ((255 - opcodeBase) / lineRange)

    private fun readNumber(size: Int): Long = when (size) {
        1 -> c.u8().toLong(); 2 -> c.u16().toLong(); 4 -> c.u32(); 8 -> c.u64()
        else -> throw DwarfParseException("Unsupported encoded number size $size")
    }

    private fun emit(source: State) {
        val state = source.copyState()
        rows += LineRow(rowIndex++, state.segment, state.address, state.file, state.line, state.column,
            state.endSequence, state.isStatement, state.basicBlock, state.prologueEnd,
            state.epilogueBegin, state.isa, state.discriminator, state.operationIndex)
    }

    private fun buildSequences(): List<LineSequence> {
        val result = mutableListOf<LineSequence>()
        var sequenceRows = mutableListOf<LineRow>()
        rows.forEach { row ->
            sequenceRows += row
            if (row.endSequence) {
                val first = sequenceRows.first()
                result += LineSequence(result.size, first.segment, first.address, row.address, sequenceRows.toList())
                sequenceRows = mutableListOf()
            }
        }
        return result
    }
}
