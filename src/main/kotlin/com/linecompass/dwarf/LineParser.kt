package com.linecompass.dwarf

import com.linecompass.io.ByteReader
import com.linecompass.io.ParseException

class LineProgramParser(
    private val lineSection: ByteArray,
    private val strings: StringTables,
    private val issues: MutableList<ParseIssue>
) {
    fun parse(stmtListOffset: Long?, cu: CompilationUnit): LineProgram? {
        if (stmtListOffset == null) return null
        if (stmtListOffset < 0 || stmtListOffset >= lineSection.size) {
            issues += ParseIssue(".debug_line", "WARNING", "STMT_LIST_OOB",
                "CU 0x${cu.offset.toString(16)} stmt_list 0x${stmtListOffset.toString(16)} out of bounds",
                cuOffset = cu.offset)
            return null
        }
        return try {
            buildProgram(stmtListOffset.toInt(), cu)
        } catch (e: Exception) {
            issues += ParseIssue(".debug_line", "WARNING", "LINE_PROGRAM_FAILED",
                "CU 0x${cu.offset.toString(16)} line program at 0x${stmtListOffset.toString(16)} failed: ${e.message}",
                offset = stmtListOffset, cuOffset = cu.offset)
            null
        }
    }

    private fun readInitialLength(start: Int): Pair<Boolean, Long> {
        val r = ByteReader(lineSection, true, ".debug_line", start)
        val first = r.u4()
        return when {
            first != 0xffffffffL && first < 0xfffffff0L -> false to first
            first == 0xffffffffL -> true to r.u8()
            else -> throw ParseException("reserved line program length at 0x$start")
        }
    }

    private fun buildProgram(start: Int, cu: CompilationUnit): LineProgram {
        val (is64, length) = readInitialLength(start)
        val offsetSize = if (is64) 8 else 4
        val contentStart = start + (if (is64) 12 else 4)
        val programEnd = contentStart + length.toInt()
        val r = ByteReader(lineSection, true, ".debug_line", contentStart)
        if (programEnd > lineSection.size) {
            throw ParseException("line program extends beyond section (end 0x${programEnd.toString(16)} > ${lineSection.size})")
        }

        val version = r.u2()
        if (version < 2 || version > 5) throw ParseException("unsupported line version $version")
        var addressSize = cu.addressSize
        if (version >= 5) addressSize = r.u1()
        if (version >= 5) r.u1() // segment_selector_size (segments unsupported in fixtures)
        var headerLength: Long? = null
        if (version < 5) headerLength = r.u(offsetSize)
        val minInstLen = r.u1()
        val maxOps = if (version >= 5) r.u1() else 1
        val defaultIsStmt = r.u1() != 0
        val lineBase = r.s1()
        val lineRange = r.u1()
        val opcodeBase = r.u1()
        val standardLengths = (1 until opcodeBase).map { r.u1() }

        val dirs = mutableListOf<String>()
        val files = mutableListOf<FileEntry>()

        if (version <= 4) {
            while (true) {
                val d = r.cString()
                if (d.isEmpty()) break
                dirs += d
            }
            while (true) {
                val name = r.cString()
                if (name.isEmpty()) break
                val dirIndex = r.uleb128().toInt()
                r.uleb128(); r.uleb128()
                files += FileEntry(name, dirIndex, resolvePath(name, dirIndex, dirs))
            }
        } else {
            val dirFormCount = r.u1()
            val dirFormPairs = (0 until dirFormCount).map { r.uleb128().toInt() to r.uleb128().toInt() }
            val dirContentCount = r.uleb128().toInt()
            val rawDirs = (0 until dirContentCount).map { readEntryContent(r, dirFormPairs, offsetSize, start) }
            dirs += "" // index 0 = comp_dir
            rawDirs.forEach { dirs += it }

            val fileFormCount = r.u1()
            val fileFormPairs = (0 until fileFormCount).map { r.uleb128().toInt() to r.uleb128().toInt() }
            val fileContentCount = r.uleb128().toInt()
            files += FileEntry("", 0, cu.compDir ?: "")
            repeat(fileContentCount) {
                var name = ""
                var dirIndex = 0
                fileFormPairs.forEach { (contentType, form) ->
                    val v = readOneContent(r, form, offsetSize, start)
                    when (contentType) {
                        1 -> name = v
                        2 -> dirIndex = v.toLongOrNull()?.toInt() ?: 0
                    }
                }
                files += FileEntry(name, dirIndex, resolvePath(name, dirIndex, dirs))
            }
        }

        val sequences = runStateMachine(r, programEnd, version, addressSize, minInstLen,
            lineBase, lineRange, opcodeBase, standardLengths, defaultIsStmt, files, dirs, cu)
        return LineProgram(cu, version, minInstLen, maxOps, defaultIsStmt, lineBase, lineRange,
            opcodeBase, files, dirs, sequences)
    }

    private fun readEntryContent(
        r: ByteReader, pairs: List<Pair<Int, Int>>, offsetSize: Int, programStart: Int
    ): String {
        var text = ""
        pairs.forEach { (contentType, form) ->
            val v = readOneContent(r, form, offsetSize, programStart)
            if (contentType == 1) text = v
        }
        return text
    }

    private fun readOneContent(r: ByteReader, form: Int, offsetSize: Int, programStart: Int): String {
        val ctx = CuDecodeCtx(CuDecodeCtx.CompilationUnitRef(), offsetSize, true,
            strings, AddrTableReader(null, issues), issues)
        val value = FormReader.read(r, form, 0, ctx, programStart, programStart.toLong())
        return when (value) {
            is AttrValue.Text -> value.value
            is AttrValue.Number -> value.value.toString()
            else -> ""
        }
    }

    private fun resolvePath(name: String, dirIndex: Int, dirs: List<String>): String {
        if (name.startsWith("/")) return name
        val dir = dirs.getOrNull(dirIndex) ?: return name
        return if (dir.isEmpty()) name else "$dir/$name"
    }

    private class MachineState(val defaultIsStmt: Boolean) {
        var address = 0L
        var segment = 0
        var file = 1
        var line = 1
        var column = 0
        var isStmt = defaultIsStmt
        var isa = 0
        var discriminator = 0
    }

    private fun runStateMachine(
        r: ByteReader, programEnd: Int, version: Int, addressSize: Int,
        minInstLen: Int, lineBase: Int, lineRange: Int, opcodeBase: Int,
        standardLengths: List<Int>, defaultIsStmt: Boolean,
        files: MutableList<FileEntry>, dirs: List<String>, cu: CompilationUnit
    ): List<LineSequence> {
        val sequences = mutableListOf<LineSequence>()
        var rows = mutableListOf<LineRow>()
        var seqStart: Long = 0L
        var seqStartSet = false
        var order = 0
        var rowCount = 0
        val st = MachineState(defaultIsStmt)

        fun appendRow(endSequence: Boolean) {
            if (rowCount++ >= Limits.MAX_LINE_ROWS_PER_PROGRAM) {
                issues += ParseIssue(".debug_line", "ERROR", "TOO_MANY_ROWS",
                    "CU 0x${cu.offset.toString(16)} exceeds ${Limits.MAX_LINE_ROWS_PER_PROGRAM} rows; truncating",
                    cuOffset = cu.offset)
                return
            }
            val fileEntry = files.getOrNull(st.file) ?: FileEntry("?", st.file, "?")
            rows += LineRow(st.address, st.segment, st.file, fileEntry,
                st.line, st.column, st.isStmt, endSequence, st.isa, st.discriminator, order++)
            if (!seqStartSet) { seqStart = st.address; seqStartSet = true }
            st.discriminator = 0
        }

        fun resetState() {
            st.address = 0; st.segment = 0; st.file = 1; st.line = 1; st.column = 0
            st.isStmt = defaultIsStmt; st.isa = 0; st.discriminator = 0
            seqStartSet = false
        }

        while (r.offset < programEnd) {
            val opcode = r.u1()
            when {
                opcode == 0 -> {
                    val extLen = r.uleb128().toInt()
                    val extEnd = r.offset + extLen
                    val sub = r.u1()
                    when (sub) {
                        DW.LNE_end_sequence -> {
                            appendRow(true)
                            sequences += LineSequence(seqStart, st.address, st.segment, rows, cu)
                            rows = mutableListOf()
                            resetState()
                        }
                        DW.LNE_set_address -> {
                            if (version >= 5) {
                                // selector_size handled at header; fixtures use flat addresses
                                st.address = r.u(addressSize)
                            } else {
                                st.address = r.u(addressSize)
                            }
                            if (!seqStartSet) { seqStart = st.address; seqStartSet = true }
                        }
                        DW.LNE_define_file -> {
                            val name = r.cString()
                            val dirIndex = r.uleb128().toInt()
                            r.uleb128(); r.uleb128()
                            files += FileEntry(name, dirIndex, resolvePath(name, dirIndex, dirs))
                        }
                        DW.LNE_set_discriminator -> st.discriminator = r.uleb128().toInt()
                        else -> { /* unknown extended opcode: skip body */ }
                    }
                    r.seek(extEnd)
                }
                opcode < opcodeBase -> {
                    var emits = false
                    when (opcode) {
                        DW.LNS_copy -> emits = true
                        DW.LNS_advance_pc -> st.address += r.uleb128() * minInstLen
                        DW.LNS_advance_line -> st.line += r.sleb128().toInt()
                        DW.LNS_set_file -> st.file = r.uleb128().toInt()
                        DW.LNS_set_column -> st.column = r.uleb128().toInt()
                        DW.LNS_negate_stmt -> st.isStmt = !st.isStmt
                        7 -> {
                            // v4: set_basic_block (no operands); v5: set_line (signed LEB)
                            if (version >= 5) st.line += r.sleb128().toInt()
                        }
                        DW.LNS_const_add_pc -> {
                            val adjusted = (255 - opcodeBase) / lineRange
                            st.address += adjusted * minInstLen
                        }
                        DW.LNS_fixed_advance_pc -> st.address += r.u2().toLong()
                        DW.LNS_set_prologue_end -> { }
                        DW.LNS_set_epilogue_begin -> { }
                        DW.LNS_set_isa -> st.isa = r.uleb128().toInt()
                        else -> {
                            val count = standardLengths.getOrNull(opcode - 1) ?: 0
                            repeat(count) { r.uleb128() }
                        }
                    }
                    if (emits) appendRow(false)
                }
                else -> {
                    val adjusted = opcode - opcodeBase
                    val advanceOp = adjusted / lineRange
                    st.line += lineBase + (adjusted % lineRange)
                    st.address += advanceOp * minInstLen
                    appendRow(false)
                }
            }
        }
        if (rows.isNotEmpty()) {
            issues += ParseIssue(".debug_line", "WARNING", "SEQUENCE_NOT_TERMINATED",
                "CU 0x${cu.offset.toString(16)} has a line sequence missing DW_LNE_end_sequence",
                cuOffset = cu.offset)
            sequences += LineSequence(seqStart, rows.last().address, st.segment, rows, cu)
        }
        return sequences
    }
}
