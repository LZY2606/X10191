package compass.dwarf

import compass.dwarf.DW.LCT_directory_index
import compass.dwarf.DW.LCT_MD5
import compass.dwarf.DW.LCT_path
import compass.dwarf.DW.LCT_size
import compass.dwarf.DW.LCT_timestamp
import compass.dwarf.DW.LNE_define_file
import compass.dwarf.DW.LNE_end_sequence
import compass.dwarf.DW.LNE_set_address
import compass.dwarf.DW.LNE_set_discriminator
import compass.dwarf.DW.LNS_advance_line
import compass.dwarf.DW.LNS_advance_pc
import compass.dwarf.DW.LNS_const_add_pc
import compass.dwarf.DW.LNS_copy
import compass.dwarf.DW.LNS_fixed_advance_pc
import compass.dwarf.DW.LNS_negate_stmt
import compass.dwarf.DW.LNS_set_basic_block
import compass.dwarf.DW.LNS_set_column
import compass.dwarf.DW.LNS_set_epilogue_begin
import compass.dwarf.DW.LNS_set_file
import compass.dwarf.DW.LNS_set_isa
import compass.dwarf.DW.LNS_set_prologue_end
import compass.model.AttrForm
import compass.model.BoundsException
import compass.model.BoundedReader
import compass.model.FileEntry
import compass.model.LineEvent
import compass.model.LineProgram
import compass.model.LineRow
import compass.model.LineSequence
import compass.model.ParseIssue
import java.nio.ByteOrder

/**
 * Parses .debug_line. Supports the DWARF <= 4 and DWARF 5 header layouts and
 * records each emitted matrix row together with the opcode that produced it so
 * the UI can show the state machine walk.
 */
class LineParser(private val sections: DebugSections) {
    private val order = if (sections.elf.littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
    val issues = ArrayList<ParseIssue>()

    fun parseAll(): List<LineProgram> {
        val data = sections.line ?: return emptyList()
        val out = ArrayList<LineProgram>()
        var off = 0
        while (off < data.size) {
            try {
                val (prog, next) = parseOne(data, off)
                out += prog
                if (next <= off) break
                off = next
            } catch (e: BoundsException) {
                issues += ParseIssue("ERROR", "LINE_TRUNCATED",
                    "line program @$off abandoned: ${e.message}", ".debug_line", off.toLong())
                break
            } catch (e: Exception) {
                issues += ParseIssue("ERROR", "LINE_BAD",
                    "line program @$off abandoned: ${e.message}", ".debug_line", off.toLong())
                break
            }
        }
        return out
    }

    private fun parseOne(data: ByteArray, offset: Int): Pair<LineProgram, Int> {
        val r = BoundedReader(data, offset, data.size, order)
        val lengthField = r.u32()
        val is64: Boolean
        val length: Long
        if (lengthField == 0xffffffffL) { is64 = true; length = r.u64() } else { is64 = false; length = lengthField }
        val programEnd = Math.addExact(r.pos, length.toInt())
        if (programEnd > data.size) throw BoundsException("line program length overruns section")
        r.limit = programEnd

        val version = r.u16()
        if (version !in 2..5) throw BoundsException("unsupported line program version $version")
        var addressSize = sections.elf.elfClass.bytes
        var segmentSize = 0
        if (version >= 5) {
            addressSize = r.u8()
            segmentSize = r.u8()
        }
        val headerLength = r.readOffset(is64)
        val headerEnd = Math.addExact(r.pos, headerLength.toInt())
        if (headerEnd > programEnd) throw BoundsException("line header length overruns program")

        val minInstrLen = r.u8()
        var maxOpsPerInstr = 1
        if (version >= 4) maxOpsPerInstr = r.u8().coerceAtLeast(1)
        val defaultIsStmt = r.u8() != 0
        val lineBase = r.u8().toByte().toInt()
        val lineRange = r.u8().coerceAtLeast(1)
        val opcodeBase = r.u8()
        val stdOpcodeLengths = IntArray((opcodeBase - 1).coerceAtLeast(0)) { r.u8() }

        val dirs = ArrayList<String>()
        val files = ArrayList<FileEntry>()

        if (version <= 4) {
            while (true) {
                val d = r.nulString()
                if (d.isEmpty()) break
                dirs += d
            }
            // file entries
            var id = 1
            while (true) {
                val name = r.nulString()
                if (name.isEmpty()) break
                val dirIdx = r.uleb().toInt()
                val mtime = r.uleb()
                val size = r.uleb()
                files += FileEntry(id++, name, dirIdx, mtime, size)
            }
        } else {
            parseV5FileNames(r, headerEnd, dirs, files)
        }
        if (r.pos != headerEnd) {
            // tolerate producers with padding
            r.seek(headerEnd)
        }

        val programReader = BoundedReader(data, headerEnd, programEnd, order)
        val (sequences, events) = runProgram(
            programReader, version, offset.toLong(), minInstrLen, maxOpsPerInstr,
            defaultIsStmt, lineBase, lineRange, opcodeBase, stdOpcodeLengths,
            addressSize, segmentSize,
        )

        return LineProgram(
            version = version, cuHeaderOffset = offset.toLong(),
            files = files, dirs = dirs, sequences = sequences, events = events,
            defaultIsStmt = defaultIsStmt, minimumInstructionLength = minInstrLen,
            maximumOperationsPerInstruction = maxOpsPerInstr,
        ) to programEnd
    }

    private data class V5EntryFormat(val contentCode: Int, val formCode: Int)

    private fun parseV5FileNames(r: BoundedReader, headerEnd: Int, dirs: ArrayList<String>, files: ArrayList<FileEntry>) {
        val dirFormatCount = r.u8()
        val dirFormats = ArrayList<V5EntryFormat>(dirFormatCount)
        repeat(dirFormatCount) { dirFormats += V5EntryFormat(r.uleb().toInt(), r.uleb().toInt()) }
        val dirCount = r.uleb().toInt()
        dirs += "" // index 0 = comp_dir
        repeat(dirCount) {
            var path = ""
            for (f in dirFormats) path = readV5Content(r, f, path)
            dirs += path
        }
        val fileFormatCount = r.u8()
        val fileFormats = ArrayList<V5EntryFormat>(fileFormatCount)
        repeat(fileFormatCount) { fileFormats += V5EntryFormat(r.uleb().toInt(), r.uleb().toInt()) }
        val fileCount = r.uleb().toInt()
        var id = 1
        repeat(fileCount) {
            var name = ""; var dirIdx = 0; var mtime = 0L; var size = 0L
            for (f in fileFormats) {
                when (f.contentCode) {
                    LCT_path -> name = readV5Content(r, f, name)
                    LCT_directory_index -> dirIdx = readV5Content(r, f, "").toIntOrNull() ?: 0
                    LCT_timestamp -> mtime = readV5Content(r, f, "0").toLong()
                    LCT_size -> size = readV5Content(r, f, "0").toLong()
                    LCT_MD5 -> { r.bytes(16) }
                    else -> skipV5Form(r, f.formCode)
                }
            }
            files += FileEntry(id++, name, dirIdx, mtime, size)
        }
    }

    private fun readV5Content(r: BoundedReader, f: V5EntryFormat, current: String): String {
        return when (f.formCode) {
            AttrForm.STRING.code -> r.nulString()
            AttrForm.LINE_STRP.code -> {
                val off = r.u32()
                val t = sections.lineStr
                if (t == null || off >= t.size) "<missing .debug_line_str@$off>"
                else BoundedReader(t).nulStringAt(off.toInt())
            }
            AttrForm.STRP.code -> {
                val off = r.u32()
                val t = sections.str
                if (t == null || off >= t.size) "<missing .debug_str@$off>"
                else BoundedReader(t).nulStringAt(off.toInt())
            }
            AttrForm.DATA1.code -> r.u8().toString()
            AttrForm.DATA2.code -> r.u16().toString()
            AttrForm.DATA4.code -> r.u32().toString()
            AttrForm.DATA8.code -> r.u64().toString()
            AttrForm.UDATA.code -> r.uleb().toString()
            else -> { skipV5Form(r, f.formCode); current }
        }
    }

    private fun skipV5Form(r: BoundedReader, formCode: Int) {
        when (formCode) {
            AttrForm.STRING.code -> r.nulString()
            AttrForm.LINE_STRP.code, AttrForm.STRP.code, AttrForm.DATA4.code -> r.u32()
            AttrForm.DATA1.code -> r.u8()
            AttrForm.DATA2.code -> r.u16()
            AttrForm.DATA8.code -> r.u64()
            AttrForm.UDATA.code -> r.uleb()
            else -> throw BoundsException("unsupported path entry form ${DwarfNames.form(formCode)}")
        }
    }

    private class Machine(
        val minInstrLen: Int, val maxOps: Int, val lineBase: Int, val lineRange: Int,
        val opcodeBase: Int, val stdLengths: IntArray, val defaultIsStmt: Boolean,
    ) {
        var address = 0L
        var selector = 0L
        var file = 1
        var line = 1
        var column = 0
        var isStmt = defaultIsStmt
        var basicBlock = false
        var prologueEnd = false
        var epilogueBegin = false
        var isa = 0
        var discriminator = 0
        var opIndex = 0

        fun reset() {
            address = 0; selector = 0; file = 1; line = 1; column = 0
            isStmt = defaultIsStmt; basicBlock = false; prologueEnd = false
            epilogueBegin = false; isa = 0; discriminator = 0; opIndex = 0
        }

        fun specialOpcodeAdjust(opcode: Int): Pair<Int, Int> {
            val adjusted = opcode - opcodeBase
            val advOp = adjusted / lineRange
            val advLine = lineBase + (adjusted % lineRange)
            return advLine to advOp
        }

        fun advancePc(advOp: Int) {
            address += minInstrLen.toLong() * ((opIndex + advOp) / maxOps.coerceAtLeast(1))
            opIndex = 0
        }
    }

    private fun runProgram(
        r: BoundedReader, version: Int, cuHeaderOffset: Long,
        minInstrLen: Int, maxOps: Int, defaultIsStmt: Boolean,
        lineBase: Int, lineRange: Int, opcodeBase: Int, stdLengths: IntArray,
        addressSize: Int, segmentSize: Int,
    ): Pair<List<LineSequence>, List<LineEvent>> {
        val m = Machine(minInstrLen, maxOps, lineBase, lineRange, opcodeBase, stdLengths, defaultIsStmt)
        val rows = ArrayList<LineRow>()
        val sequences = ArrayList<LineSequence>()
        val events = ArrayList<LineEvent>()
        var seqIndex = 0
        var seqStartRowCount = 0

        fun emit(trigger: String, endSeq: Boolean) {
            val row = LineRow(
                m.address, m.selector, m.file, m.line, m.column, endSeq,
                m.isStmt, m.basicBlock, m.prologueEnd, m.epilogueBegin,
                m.isa, m.discriminator, m.opIndex,
            )
            rows += row
            events += LineEvent(seqIndex, row, trigger)
            if (endSeq) {
                val seqRows = rows.subList(seqStartRowCount, rows.size).toList()
                sequences += LineSequence(seqIndex, seqRows, cuHeaderOffset)
                seqIndex++
                seqStartRowCount = rows.size
                m.reset()
            } else {
                m.basicBlock = false; m.prologueEnd = false; m.epilogueBegin = false; m.discriminator = 0
            }
        }

        while (r.remaining > 0) {
            val opcode = r.u8()
            when {
                opcode == 0 -> {
                    val extLen = r.uleb().toInt()
                    if (extLen == 0 || r.remaining < extLen) throw BoundsException("bad extended opcode length $extLen")
                    val extEnd = r.pos + extLen
                    val sub = r.u8()
                    when (sub) {
                        LNE_end_sequence -> emit("DW_LNE_end_sequence", true)
                        LNE_set_address -> {
                            if (segmentSize > 0) m.selector = r.uint(segmentSize)
                            m.address = r.uint(addressSize)
                            m.opIndex = 0
                        }
                        LNE_define_file -> {
                            r.nulString(); r.uleb(); r.uleb(); r.uleb()
                        }
                        LNE_set_discriminator -> m.discriminator = r.uleb().toInt()
                        else -> { /* skip below */ }
                    }
                    if (r.pos < extEnd) r.seek(extEnd)
                }
                opcode < opcodeBase -> {
                    val arity = if (opcode - 1 in stdLengths.indices) stdLengths[opcode - 1] else 0
                    when (opcode) {
                        LNS_copy -> emit("DW_LNS_copy", false)
                        LNS_advance_pc -> m.advancePc(r.uleb().toInt())
                        LNS_advance_line -> m.line += r.sleb().toInt()
                        LNS_set_file -> m.file = r.uleb().toInt()
                        LNS_set_column -> m.column = r.uleb().toInt()
                        LNS_negate_stmt -> m.isStmt = !m.isStmt
                        LNS_set_basic_block -> m.basicBlock = true
                        LNS_const_add_pc -> {
                            val adj = 255 - opcodeBase
                            m.advancePc(adj / lineRange)
                        }
                        LNS_fixed_advance_pc -> {
                            val adv = r.u16()
                            m.address += adv.toLong()
                            m.opIndex = 0
                        }
                        LNS_set_prologue_end -> m.prologueEnd = true
                        LNS_set_epilogue_begin -> m.epilogueBegin = true
                        LNS_set_isa -> m.isa = r.uleb().toInt()
                        else -> repeat(arity) { r.uleb() }
                    }
                }
                else -> {
                    val (advLine, advOp) = m.specialOpcodeAdjust(opcode)
                    m.line += advLine
                    m.advancePc(advOp)
                    emit("special opcode $opcode", false)
                }
            }
        }
        if (seqStartRowCount < rows.size) {
            // Unterminated sequence: keep the rows with a synthetic end row at last address
            // (zero-length) and flag via events so the UI can mark it.
            val last = rows.last()
            events += LineEvent(seqIndex, last, "WARNING: sequence without end_sequence")
            sequences += LineSequence(seqIndex, rows.subList(seqStartRowCount, rows.size).toList(), cuHeaderOffset)
        }
        return sequences to events
    }
}
