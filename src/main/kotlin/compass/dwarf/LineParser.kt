package compass.dwarf

import compass.elf.ByteReader

/**
 * .debug_line parser for DWARF 4 and 5.
 *
 * Returns full matrix rows plus a compact opcode transition log. Multiple
 * sequences are preserved; zero-length sequences keep their start address.
 * Unknown standard opcodes with malformed operands and op overruns stop that
 * program with an issue instead of poisoning later programs.
 */
class LineParser(
    private val section: ByteReader,
    private val resolveStrx: (Long) -> String?,
    private val resolveLineStrp: (Long) -> String?
) {
    fun parseAt(sectionOffset: Long): LineProgram {
        if (sectionOffset < 0 || sectionOffset >= section.size)
            throw DwarfParseException("line program offset $sectionOffset out of bounds")
        val issues = mutableListOf<ParseIssue>()
        val r = section.subReader(sectionOffset.toInt(), section.size - sectionOffset.toInt())
        val startPos = r.save()
        val (length, afterLen, dwarf64) = readInitialLength(r)
        val progEnd = afterLen + length.toInt()
        val body = section.subReader(sectionOffset.toInt() + afterLen, length.toInt())
        val version = body.u2()
        var addressSize = 8
        var segmentSelectorSize = 0
        if (version >= 5) {
            addressSize = body.u1()
            segmentSelectorSize = body.u1()
        }
        val compDir = if (version <= 4) null else null // v5 dropped comp_dir from line header
        val maximumOperationsPerInstruction: Int = if (version >= 4) body.u1() else 1
        val minimumInstructionLength = body.u1()
        val defaultIsStmt = body.u1() != 0
        val lineBase = body.s1()
        val lineRange = body.u1()
        val opcodeBase = body.u1()
        val standardOpcodeLengths = IntArray(maxOf(0, opcodeBase - 1)) { body.u1() }
        val dirs = ArrayList<LineFile>() // directories modeled as files for naming helper
        val includeDirs = ArrayList<String>()
        val files = ArrayList<LineFile>()

        if (version <= 4) {
            // include_directories
            var dirIdx = 0
            while (true) {
                val s = body.cString()
                if (s.isEmpty()) break
                includeDirs.add(s); dirIdx++
            }
            // file_names
            var idx = 1L
            while (true) {
                val s = body.cString()
                if (s.isEmpty()) break
                val dirIndex = body.uleb()
                body.uleb() // mtime
                body.uleb() // size
                val dir = includeDirs.getOrNull((dirIndex - 1).toInt()) ?: ""
                files.add(LineFile(idx, s, dir))
                idx++
            }
        } else {
            // directories
            val directoryEntryFormatCount = body.u1()
            data class Fmt(val ct: Int, val form: Int)
            val dirFmt = ArrayList<Fmt>()
            repeat(directoryEntryFormatCount) { dirFmt.add(Fmt(body.uleb().toInt(), body.u1())) }
            val directoriesCount = body.uleb()
            var dIdx = 0L
            repeat(directoriesCount.toInt()) {
                var path = ""
                for ((ct, form) in dirFmt) path = consumePath(body, ct, form, path)
                includeDirs.add(path)
                dIdx++
            }
            // file names
            val fileEntryFormatCount = body.u1()
            val fileFmt = ArrayList<Fmt>()
            repeat(fileEntryFormatCount) { fileFmt.add(Fmt(body.uleb().toInt(), body.u1())) }
            val fileNamesCount = body.uleb()
            var fIdx = 0L
            repeat(fileNamesCount.toInt()) {
                var name = ""
                var dir = ""
                var dirIndex = -1L
                for ((ct, form) in fileFmt) {
                    when (ct) {
                        DW.CT_path -> name = consumePath(body, ct, form, name)
                        DW.CT_directory_index -> dirIndex = readPathScalar(body, form)
                        else -> skipPathForm(body, form)
                    }
                }
                if (dirIndex >= 0) dir = includeDirs.getOrNull(dirIndex.toInt()) ?: ""
                files.add(LineFile(fIdx, name, dir))
                fIdx++
            }
        }
        // body begins at current position
        val bodyStart = body.save()
        val programBytes = section.subReader(
            sectionOffset.toInt() + afterLen + bodyStart,
            progEnd - afterLen - bodyStart
        )
        val machine = StateMachine(
            version, addressSize, segmentSelectorSize, minimumInstructionLength,
            maximumOperationsPerInstruction, defaultIsStmt, lineBase, lineRange, opcodeBase,
            standardOpcodeLengths, files, resolveStrx, resolveLineStrp
        )
        machine.run(programBytes)
        issues.addAll(machine.issues)
        val seqs = groupSequences(machine.rows)
        return LineProgram(
            sectionOffset, version, files, machine.rows, seqs, machine.transitions,
            minimumInstructionLength, maximumOperationsPerInstruction, defaultIsStmt,
            lineBase, lineRange, opcodeBase, issues
        )
    }

    private fun consumePath(body: ByteReader, ct: Int, form: Int, current: String): String {
        if (ct != DW.CT_path) { skipPathForm(body, form); return current }
        return readPathForm(body, form)
    }

    private fun readPathScalar(body: ByteReader, form: Int): Long = when (form) {
        DW.FORM_data1, DW.FORM_strx1, DW.FORM_addrx1 -> body.u1().toLong()
        DW.FORM_data2, DW.FORM_strx2 -> body.u2().toLong() and 0xffffL
        DW.FORM_udata, DW.FORM_strx, DW.FORM_addrx -> body.uleb()
        DW.FORM_data4 -> body.u4().toLong() and 0xffffffffL
        else -> { skipPathForm(body, form); -1L }
    }

    private fun readPathForm(body: ByteReader, form: Int): String = when (form) {
        DW.FORM_string -> body.cString()
        DW.FORM_line_strp -> resolveLineStrp(body.u8()) ?: ""
        DW.FORM_strp -> body.u8().let { off -> resolveLineStrp(off) ?: "" }
        DW.FORM_strx, DW.FORM_strx1, DW.FORM_strx2, DW.FORM_strx3, DW.FORM_strx4 -> {
            val idx = readPathScalar(body, form)
            resolveStrx(idx) ?: ""
        }
        else -> { skipPathForm(body, form); "" }
    }

    private fun skipPathForm(body: ByteReader, form: Int) {
        when (form) {
            DW.FORM_data1, DW.FORM_strx1, DW.FORM_addrx1 -> body.u1()
            DW.FORM_data2, DW.FORM_strx2, DW.FORM_addrx2 -> body.u2()
            DW.FORM_udata, DW.FORM_strx, DW.FORM_addrx -> body.uleb()
            DW.FORM_sdata -> body.sleb()
            DW.FORM_data4, DW.FORM_strx4, DW.FORM_addrx4 -> body.u4()
            DW.FORM_data8, DW.FORM_strp, DW.FORM_line_strp -> body.u8()
            DW.FORM_string -> body.cString()
            DW.FORM_data16 -> body.skip(16)
            else -> throw DwarfParseException(String.format("unsupported line-header form 0x%02x", form))
        }
    }

    private fun groupSequences(rows: List<LineRow>): List<LineSequence> {
        val out = ArrayList<LineSequence>()
        var seqIdx = 0
        var i = 0
        while (i < rows.size) {
            val start = i
            var end = i
            while (end < rows.size && !rows[end].endSequence) end++
            // include the end_sequence row
            val groupRows = rows.subList(start, minOf(rows.size, end + 1))
            if (groupRows.isNotEmpty()) {
                val first = groupRows.first()
                val last = groupRows.last()
                out.add(LineSequence(seqIdx, first.address, last.address, first.segment, groupRows.toList()))
                seqIdx++
            }
            i = end + 1
        }
        return out
    }

    private fun ByteReader.s1(): Int = u1().let { if (it and 0x80 != 0) it - 256 else it }
}
