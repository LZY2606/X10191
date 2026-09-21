package compass.dwarf

import java.nio.ByteOrder

data class LineRow(
    val address: Long,
    val file: String,
    val line: Long,
    val column: Long,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Long,
    val discriminator: Long,
    val sequence: Int,      // which sequence (0-based) within this line program
    val rowIndex: Int,      // global row index within this program
)

class LineProgram(
    val version: Int,
    val offset: Long,
) {
    val rows = mutableListOf<LineRow>()
    val notes = mutableListOf<String>()
    var error: String? = null
    var directories = listOf<String>()
    var files = listOf<String>()
}

/** DWARF .debug_line state machine, v2-v5 headers, bounded execution. */
object LineProgramParser {

    private class Header(
        val version: Int, val minInsn: Int, val maxOps: Int, val defaultIsStmt: Boolean,
        val lineBase: Int, val lineRange: Int, val opcodeBase: Int,
        val stdLengths: IntArray, val programStart: Int, val unitEnd: Int,
        val directories: List<String>, val files: List<String>,
    )

    fun parse(buf: ByteArray, offset: Int, order: ByteOrder, addrSize: Int): LineProgram {
        val lp = LineProgram(0, offset.toLong())
        if (offset < 0 || offset + 4 > buf.size) {
            lp.error = "line program offset 0x${offset.toString(16)} out of bounds"
            return lp
        }
        try {
            val c = Cursor(buf, offset, buf.size, order)
            var unitLength = c.u32()
            val is64 = unitLength == 0xFFFFFFFFL
            if (is64) unitLength = c.u64()
            if (unitLength <= 0 || unitLength > Int.MAX_VALUE) throw DwarfParseException("bad line unit length")
            val unitEnd = (c.pos + unitLength).coerceAtMost(buf.size.toLong()).toInt()
            if (c.pos + unitLength > buf.size) lp.notes += "line program truncated by section size"

            val version = c.u16()
            lp.rows.clear()
            val header = if (version >= 5) readHeaderV5(c, version, is64, unitEnd, lp)
            else readHeaderV4(c, version, is64, unitEnd, lp)
            val lp2 = LineProgram(version, offset.toLong())
            lp2.directories = header.directories
            lp2.files = header.files
            lp2.notes += lp.notes
            runProgram(buf, header, unitEnd, order, addrSize, lp2)
            return lp2
        } catch (e: DwarfParseException) {
            lp.error = e.message
            return lp
        }
    }

    private fun readDirsFilesV4(c: Cursor, lp: LineProgram): Pair<List<String>, List<String>> {
        val dirs = mutableListOf<String>()
        while (true) {
            if (c.remaining <= 0) throw DwarfParseException("directory table unterminated")
            val s = c.cstring()
            if (s.isEmpty()) break
            if (dirs.size >= 100_000) throw DwarfParseException("directory table too large")
            dirs += s
        }
        val files = mutableListOf<String>()
        while (true) {
            if (c.remaining <= 0) throw DwarfParseException("file table unterminated")
            val name = c.cstring()
            if (name.isEmpty()) break
            if (files.size >= 1_000_000) throw DwarfParseException("file table too large")
            val dirIdx = c.uleb(); c.uleb(); c.uleb() // dir, mtime, size
            val dir = if (dirIdx == 0L) "" else dirs.getOrElse(dirIdx.toInt() - 1) { "" }
            files += if (dir.isEmpty()) name else "$dir/$name"
        }
        return dirs to files
    }

    private fun readHeaderV4(c: Cursor, version: Int, is64: Boolean, unitEnd: Int, lp: LineProgram): Header {
        val headerLength = c.uintN(if (is64) 8 else 4)
        val programStart = (c.pos + headerLength).coerceAtMost(unitEnd.toLong()).toInt()
        val minInsn = c.u8()
        val maxOps = if (version >= 4) c.u8() else 1
        val defaultIsStmt = c.u8() != 0
        val lineBase = c.i8()
        val lineRange = c.u8()
        val opcodeBase = c.u8()
        if (opcodeBase < 1 || opcodeBase > 64) throw DwarfParseException("bad opcode_base $opcodeBase")
        val std = IntArray(opcodeBase - 1) { c.u8() }
        val (dirs, files) = readDirsFilesV4(c, lp)
        c.pos = programStart
        return Header(version, minInsn, maxOps, defaultIsStmt, lineBase, lineRange, opcodeBase,
            std, programStart, unitEnd, dirs, files)
    }

    private fun readFormatTable(c: Cursor, ctx: FormContext): List<Pair<Int, Int>> {
        val count = c.u8()
        if (count > 64) throw DwarfParseException("entry format count $count too large")
        return (0 until count).map { c.uleb().toInt() to c.uleb().toInt() }
    }

    private fun readHeaderV5(c: Cursor, version: Int, is64: Boolean, unitEnd: Int, lp: LineProgram): Header {
        val addrSize = c.u8()
        c.u8() // segment_selector_size
        val headerLength = c.uintN(if (is64) 8 else 4)
        val programStart = (c.pos + headerLength).coerceAtMost(unitEnd.toLong()).toInt()
        val minInsn = c.u8()
        val maxOps = c.u8()
        val defaultIsStmt = c.u8() != 0
        val lineBase = c.i8()
        val lineRange = c.u8()
        val opcodeBase = c.u8()
        if (opcodeBase < 1 || opcodeBase > 64) throw DwarfParseException("bad opcode_base $opcodeBase")
        val std = IntArray(opcodeBase - 1) { c.u8() }
        val ctx = FormContext(version, addrSize, c.order, null, null, null, 0, null, 0, is64)

        fun readEntries(): List<List<Pair<Int, AttrValue>>> {
            val formats = readFormatTable(c, ctx)
            val count = c.uleb()
            if (count > 1_000_000) throw DwarfParseException("file/dir entry count too large")
            return (0 until count.toInt()).map {
                formats.map { (ct, form) ->
                    ct to try { ctx.decode(form, c) } catch (e: UnknownFormException) {
                        throw DwarfParseException("line header: ${e.message}")
                    }
                }
            }
        }

        val dirEntries = readEntries()
        val fileEntries = readEntries()
        fun pathOf(values: List<Pair<Int, AttrValue>>, dirs: List<String>): String {
            var name = ""; var dirIdx = 0L
            for ((ct, v) in values) when (ct) {
                Dw.LNCT_path -> name = v.asString() ?: ""
                Dw.LNCT_directory_index -> dirIdx = v.asLong() ?: 0L
            }
            // DWARF5 directory_index is 0-based into the directories table.
            val dir = dirs.getOrElse(dirIdx.toInt()) { "" }
            return if (dir.isEmpty() || name.startsWith("/")) name else "$dir/$name"
        }
        val dirs = dirEntries.map { pathOf(it, emptyList()) }
        val files = fileEntries.map { pathOf(it, dirs) }
        c.pos = programStart
        return Header(version, minInsn, maxOps, defaultIsStmt, lineBase, lineRange, opcodeBase,
            std, programStart, unitEnd, dirs, files)
    }

    private class State(val h: Header) {
        var address = 0L
        var opIndex = 0L
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
        fun reset() {
            address = 0; opIndex = 0; file = 1; line = 1; column = 0
            isStmt = h.defaultIsStmt; basicBlock = false; endSequence = false
            prologueEnd = false; epilogueBegin = false; isa = 0; discriminator = 0
        }
    }

    private fun runProgram(
        buf: ByteArray, h: Header, unitEnd: Int, order: ByteOrder, addrSize: Int, lp: LineProgram,
    ) {
        val c = Cursor(buf, h.programStart, unitEnd, order)
        val st = State(h)
        var sequence = 0
        var rowIndex = 0
        var guard = 0

        fun fileName(idx: Int): String {
            // DWARF <=4: files are 1-based. DWARF5: 0-based.
            val i = if (h.version >= 5) idx else idx - 1
            return h.files.getOrElse(i) { "<file#$idx>" }
        }

        fun emitRow() {
            if (rowIndex >= Dw.MAX_LINE_ROWS) throw DwarfParseException("line row limit exceeded")
            lp.rows += LineRow(
                st.address, fileName(st.file), st.line, st.column, st.isStmt,
                st.basicBlock, st.endSequence, st.prologueEnd, st.epilogueBegin,
                st.isa, st.discriminator, sequence, rowIndex,
            )
            rowIndex++
            st.basicBlock = false; st.prologueEnd = false; st.epilogueBegin = false
            st.discriminator = 0
        }

        fun advancePC(operand: Long) {
            val maxOps = if (h.maxOps == 0) 1 else h.maxOps
            val opAdvance = (st.opIndex + operand) % maxOps
            val addrAdvance = ((st.opIndex + operand) / maxOps) * h.minInsn
            st.address += addrAdvance
            st.opIndex = opAdvance
        }

        fun special(opcode: Int) {
            val adjusted = opcode - h.opcodeBase
            if (h.lineRange == 0) { lp.notes += "line_range=0, special opcode skipped"; return }
            val opAdv = adjusted / h.lineRange
            val lineInc = h.lineBase + (adjusted % h.lineRange)
            advancePC(opAdv.toLong())
            st.line += lineInc
            emitRow()
        }

        while (c.pos < unitEnd) {
            if (++guard > Dw.MAX_LINE_ROWS * 4 + 1000) throw DwarfParseException("line program step limit")
            val opcode = c.u8()
            when {
                opcode == 0 -> {
                    // Extended opcode: length-prefixed, so unknown ones are skippable safely.
                    val len = c.uleb()
                    if (len > Int.MAX_VALUE || c.remaining < len.toInt()) {
                        throw DwarfParseException("extended opcode overruns line program")
                    }
                    val subEnd = c.pos + len.toInt()
                    if (len == 0L) continue
                    val sub = c.u8()
                    when (sub) {
                        Dw.LNE_end_sequence -> {
                            st.endSequence = true
                            emitRow()
                            st.reset()
                            sequence++
                        }
                        Dw.LNE_set_address -> {
                            if (c.remaining < addrSize) throw DwarfParseException("set_address truncated")
                            st.address = c.uintN(addrSize)
                            st.opIndex = 0
                        }
                        Dw.LNE_define_file -> {
                            // DWARF4 only; parse and append.
                            val name = c.cstring(); val dirIdx = c.uleb(); c.uleb(); c.uleb()
                            val dir = if (dirIdx == 0L) "" else h.directories.getOrElse(dirIdx.toInt() - 1) { "" }
                            (h.files as? MutableList)?.add(if (dir.isEmpty()) name else "$dir/$name")
                        }
                        Dw.LNE_set_discriminator -> st.discriminator = c.uleb()
                        else -> lp.notes += "unknown extended opcode $sub skipped"
                    }
                    c.pos = subEnd // realign regardless of how much we consumed
                }
                opcode < h.opcodeBase -> when (opcode) {
                    Dw.LNS_copy -> emitRow()
                    Dw.LNS_advance_pc -> advancePC(c.uleb())
                    Dw.LNS_advance_line -> st.line += c.sleb()
                    Dw.LNS_set_file -> st.file = c.uleb().toInt()
                    Dw.LNS_set_column -> st.column = c.uleb()
                    Dw.LNS_negate_stmt -> st.isStmt = !st.isStmt
                    Dw.LNS_set_basic_block -> st.basicBlock = true
                    Dw.LNS_const_add_pc -> {
                        val adjusted = 255 - h.opcodeBase
                        if (h.lineRange != 0) advancePC((adjusted / h.lineRange).toLong())
                    }
                    Dw.LNS_fixed_advance_pc -> { st.address += c.u16(); st.opIndex = 0 }
                    Dw.LNS_set_prologue_end -> st.prologueEnd = true
                    Dw.LNS_set_epilogue_begin -> st.epilogueBegin = true
                    Dw.LNS_set_isa -> st.isa = c.uleb()
                    else -> {
                        // Unknown standard opcode: skip its declared operands.
                        val argc = h.stdLengths.getOrElse(opcode - 1) { 0 }
                        repeat(argc) { c.uleb() }
                        lp.notes += "unknown standard opcode $opcode skipped ($argc args)"
                    }
                }
                else -> special(opcode)
            }
        }
    }
}
