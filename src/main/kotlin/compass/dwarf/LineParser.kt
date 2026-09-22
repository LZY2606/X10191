package compass.dwarf

import compass.binfmt.Cursor
import compass.binfmt.DwarfParseException

class LineProgramParser(
    private val sections: DwarfSections,
    private val littleEndian: Boolean,
) {
    private val maxRows = 2_000_000
    private val maxOps = 20_000_000

    fun parseAll(): List<LineSequence> {
        val d = sections.line ?: return emptyList()
        val out = mutableListOf<LineSequence>()
        var pos = 0
        var guard = 0
        while (pos < d.size) {
            if (guard++ > 100_000) break
            val c = Cursor(d, pos, d.size, pos, littleEndian)
            val parsed = try { parseOne(c) } catch (e: DwarfParseException) { break }
            out.add(parsed.sequence)
            if (parsed.consumedEnd <= pos) break
            pos = parsed.consumedEnd
        }
        return out
    }

    data class ParsedUnit(val sequence: LineSequence, val consumedEnd: Int)

    private data class Fmt(val contentType: Int, val form: Int)

    fun parseOne(c: Cursor): ParsedUnit {
        val headerOffset = c.pos.toLong()
        val (unitLength, is64) = initialLen(c)
        val unitEnd = c.pos + unitLength.toIntExact()
        if (unitEnd > c.end) throw DwarfParseException("line unit length exceeds section at $headerOffset")
        val version = c.u16()
        var addressSize = 8
        var segmentSize = 0
        if (version >= 5) { addressSize = c.u8(); segmentSize = c.u8() }
        val headerLength = if (is64) c.u64() else c.u32()
        val headerStart = c.pos
        val headerEnd = headerStart + headerLength.toIntExact()
        val minInstLen = c.u8()
        val maxOpsPerInst = if (version >= 4) c.u8() else 1
        val defaultIsStmt = c.u8()
        val lineBase = c.s8()
        val lineRange = c.u8()
        val opcodeBase = c.u8()
        if (lineRange == 0) throw DwarfParseException("line_range is 0 at $headerOffset")
        val stdLengths = IntArray(maxOf(0, opcodeBase - 1)) { c.u8().toInt() }

        val directories = mutableListOf<String?>(null)
        val files = mutableListOf<LineFile>()
        if (version >= 5) parseFileTableV5(c, directories, files, addressSize)
        else parseFileTableV4(c, directories, files)
        c.seek(headerEnd)

        val rows = runProgram(c, unitEnd, version, addressSize, segmentSize, minInstLen,
            maxOpsPerInst, defaultIsStmt, lineBase, lineRange, opcodeBase, stdLengths)
        return ParsedUnit(
            LineSequence(headerOffset, version, headerOffset, files.toList(), directories.toList(), null, rows),
            unitEnd,
        )
    }

    private fun parseFileTableV4(c: Cursor, directories: MutableList<String?>, files: MutableList<LineFile>) {
        while (true) {
            val s = c.zstring()
            if (s.isEmpty()) break
            directories.add(s)
        }
        while (true) {
            val name = c.zstring()
            if (name.isEmpty()) break
            val dir = c.uleb128().toInt(); val time = c.uleb128(); val size = c.uleb128()
            files.add(LineFile(name, dir, time, size))
        }
    }

    private fun parseFileTableV5(c: Cursor, directories: MutableList<String?>, files: MutableList<LineFile>, addressSize: Int) {
        fun formats(): List<Fmt> {
            val n = c.u8()
            return (0 until n).map { Fmt(c.uleb128().toInt(), c.uleb128().toInt()) }
        }
        val dirFmt = formats(); val dirCount = c.uleb128().toInt()
        for (i in 0 until dirCount) {
            var path: String? = null
            for (f in dirFmt) { val s = readStringOrSkip(c, f.form, addressSize); if (f.contentType == Dw.CT_path) path = s }
            directories.add(path)
        }
        val fileFmt = formats(); val fileCount = c.uleb128().toInt()
        for (i in 0 until fileCount) {
            var name: String? = null; var dirIdx = 0; var time = 0L; var size = 0L
            for (f in fileFmt) {
                when (f.contentType) {
                    Dw.CT_path -> name = readStringOrSkip(c, f.form, addressSize)
                    Dw.CT_directory_index -> dirIdx = readNumber(c, f.form).toInt()
                    Dw.CT_timestamp -> time = readNumber(c, f.form)
                    Dw.CT_size -> size = readNumber(c, f.form)
                    else -> readStringOrSkip(c, f.form, addressSize)
                }
            }
            files.add(LineFile(name, dirIdx, time, size))
        }
    }

    private fun readNumber(c: Cursor, form: Int): Long = when (form) {
        Dw.FORM_data1 -> c.u8().toLong(); Dw.FORM_data2 -> c.u16().toLong()
        Dw.FORM_data4 -> c.u32(); Dw.FORM_data8 -> c.u64()
        Dw.FORM_udata -> c.uleb128(); Dw.FORM_sdata -> c.sleb128()
        Dw.FORM_strx1, Dw.FORM_addrx1 -> c.u8().toLong()
        Dw.FORM_strx2, Dw.FORM_addrx2 -> c.u16().toLong()
        Dw.FORM_strx3, Dw.FORM_addrx3 -> c.u24()
        Dw.FORM_strx4, Dw.FORM_addrx4 -> c.u32()
        Dw.FORM_strx, Dw.FORM_addrx -> c.uleb128()
        else -> throw DwarfParseException("non-numeric line form 0x${form.toString(16)}")
    }

    private fun readStringOrSkip(c: Cursor, form: Int, addressSize: Int): String? = when (form) {
        Dw.FORM_string -> c.zstring()
        Dw.FORM_strp -> sections.stringAt(readOff(c))
        Dw.FORM_line_strp -> sections.lineStringAt(readOff(c))
        Dw.FORM_strx1, Dw.FORM_strx2, Dw.FORM_strx3, Dw.FORM_strx4, Dw.FORM_strx -> null.also {
            skipScalar(c, form, addressSize)
        }
        else -> { skipScalar(c, form, addressSize); null }
    }

    private fun readOff(c: Cursor): Long = c.u32()

    private fun skipScalar(c: Cursor, form: Int, addressSize: Int) {
        when (form) {
            Dw.FORM_data1, Dw.FORM_flag -> c.u8()
            Dw.FORM_data2 -> c.u16()
            Dw.FORM_data4, Dw.FORM_sec_offset -> c.u32()
            Dw.FORM_data8 -> c.u64()
            Dw.FORM_udata, Dw.FORM_sdata -> c.uleb128()
            Dw.FORM_addr -> c.addr(addressSize)
            Dw.FORM_block1 -> c.bytes(c.u8())
            Dw.FORM_block2 -> c.bytes(c.u16())
            Dw.FORM_block4 -> c.bytes(c.u32().toIntExact())
            Dw.FORM_block, Dw.FORM_exprloc -> c.bytes(c.uleb128().toIntExact())
            Dw.FORM_strx1, Dw.FORM_addrx1 -> c.u8()
            Dw.FORM_strx2, Dw.FORM_addrx2 -> c.u16()
            Dw.FORM_strx3, Dw.FORM_addrx3 -> c.u24()
            Dw.FORM_strx4, Dw.FORM_addrx4 -> c.u32()
            Dw.FORM_strx, Dw.FORM_addrx, Dw.FORM_rnglistx, Dw.FORM_loclistx -> c.uleb128()
            Dw.FORM_flag_present -> {}
            Dw.FORM_data16 -> c.bytes(16)
            else -> throw DwarfParseException("unsupported line header form 0x${form.toString(16)}")
        }
    }

    private class State(val defaultIsStmt: Int) {
        var address = 0L; var segment = 0L; var opIndex = 0
        var file = 1; var line = 1; var column = 0
        var isStmt = defaultIsStmt != 0; var basicBlock = false; var endSequence = false
        var prologueEnd = false; var epilogueBegin = false; var isa = 0; var discriminator = 0
        fun reset() {
            address = 0; segment = 0; opIndex = 0; file = 1; line = 1; column = 0
            isStmt = defaultIsStmt != 0; basicBlock = false; endSequence = false
            prologueEnd = false; epilogueBegin = false; isa = 0; discriminator = 0
        }
    }

    @Suppress("LongParameterList")
    private fun runProgram(
        c: Cursor, unitEnd: Int, version: Int, addressSize: Int, segmentSize: Int,
        minInstLen: Int, maxOpsPerInst: Int, defaultIsStmt: Int, lineBase: Int, lineRange: Int,
        opcodeBase: Int, stdLengths: IntArray,
    ): List<LineRow> {
        val rows = mutableListOf<LineRow>()
        val st = State(defaultIsStmt)
        fun append() {
            if (rows.size >= maxRows) throw DwarfParseException("line row limit exceeded")
            rows.add(LineRow(st.address, st.segment, st.file, st.line, st.column, st.isStmt,
                st.basicBlock, st.endSequence, st.prologueEnd, st.epilogueBegin, st.isa,
                st.discriminator, st.opIndex))
        }
        fun advance(operandAdvance: Int) {
            val mopi = maxOf(1, maxOpsPerInst)
            val newOp = st.opIndex + operandAdvance
            st.address += minInstLen.toLong() * (newOp / mopi)
            st.opIndex = newOp % mopi
        }
        var ops = 0
        while (c.pos < unitEnd) {
            if (ops++ > maxOps) throw DwarfParseException("opcode limit exceeded")
            val op = c.u8()
            when {
                op == 0 -> {
                    val extLen = c.uleb128().toInt()
                    if (extLen < 1 || c.pos + extLen > unitEnd) throw DwarfParseException("bad extended opcode length")
                    val bodyEnd = c.pos + extLen
                    val sub = c.u8()
                    when (sub) {
                        Dw.LNE_end_sequence -> { st.endSequence = true; append(); st.reset() }
                        Dw.LNE_set_address -> {
                            if (segmentSize > 0) st.segment = c.addr(segmentSize)
                            st.address = c.addr(addressSize); st.opIndex = 0
                        }
                        Dw.LNE_define_file -> {
                            if (version < 5) { c.zstring(); c.uleb128(); c.uleb128(); c.uleb128() }
                        }
                        0x04 -> st.discriminator = c.uleb128().toInt()
                        0x00 -> { // DW_LNE_set_discriminator? no — v5 define_file reuses 0x03; 0x00 unknown
                        }
                        else -> { /* unknown extended opcode: skip remaining body */ }
                    }
                    c.seek(bodyEnd)
                }
                op < opcodeBase -> {
                    val arity = stdLengths.getOrElse(op - 1) { 0 }
                    when (op) {
                        Dw.LNS_copy -> { append(); st.basicBlock = false; st.prologueEnd = false; st.epilogueBegin = false }
                        Dw.LNS_advance_pc -> advance(c.uleb128().toInt())
                        Dw.LNS_advance_line -> st.line += c.sleb128().toInt()
                        Dw.LNS_set_file -> st.file = c.uleb128().toInt()
                        Dw.LNS_set_column -> st.column = c.uleb128().toInt()
                        Dw.LNS_negate_stmt -> st.isStmt = !st.isStmt
                        Dw.LNS_set_basic_block -> st.basicBlock = true
                        Dw.LNS_const_add_pc -> advance((255 - opcodeBase) / lineRange)
                        Dw.LNS_fixed_advance_pc -> { st.address += c.u16().toLong(); st.opIndex = 0 }
                        Dw.LNS_set_prologue_end -> st.prologueEnd = true
                        Dw.LNS_set_epilogue_begin -> st.epilogueBegin = true
                        Dw.LNS_set_isa -> st.isa = c.uleb128().toInt()
                        else -> repeat(arity) { c.uleb128() }
                    }
                }
                else -> {
                    val adjusted = op - opcodeBase
                    val opAdvance = adjusted / lineRange
                    st.line += lineBase + adjusted % lineRange
                    advance(opAdvance)
                    append()
                    st.basicBlock = false; st.prologueEnd = false; st.epilogueBegin = false
                }
            }
        }
        return rows
    }

    private fun initialLen(c: Cursor): Pair<Long, Boolean> {
        val first = c.u32()
        if (first == 0xffffffffL) return c.u64() to true
        return first to false
    }
}

private fun Long.toIntExact(): Int {
    if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseException("length out of range: $this")
    return toInt()
}
