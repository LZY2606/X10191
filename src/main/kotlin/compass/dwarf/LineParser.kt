package compass.dwarf

import compass.binary.ByteReader
import compass.binary.ParseException
import compass.binary.uleb

/**
 * .debug_line parser for DWARF 3/4 and 5. Several independent programs may
 * live in one section; callers index by section offset (DW_AT_stmt_list).
 * Unknown standard/extended opcodes are skipped using their declared operand
 * counts/lengths so the program cursor never loses alignment.
 */
object LineParser {
    fun parseAll(sections: DwarfSections, sectionName: String = ".debug_line"): Map<Long, LineProgram> {
        val data = sections.bytes(sectionName) ?: return emptyMap()
        val programs = LinkedHashMap<Long, LineProgram>()
        val r = ByteReader(data)
        while (r.remaining() > 0) {
            val off = r.pos
            val p = parseOne(r, sections)
            programs[off.toLong()] = p
            if (r.pos <= off) throw ParseException("line program at 0x${off.toString(16)} made no progress")
        }
        return programs
    }

    private class Header(
        val version: Int,
        val minInstructionLength: Int,
        val maxOpsPerInstruction: Int,
        val defaultIsStmt: Boolean,
        val lineBase: Int,
        val lineRange: Int,
        val opcodeBase: Int,
        val stdOpcodeLengths: List<Int>,
        val files: MutableList<LineFile>,
        val directories: List<String>,
        val addressSize: Int,
        val segmentSelectorSize: Int,
    )

    private fun parseOne(r: ByteReader, sections: DwarfSections): LineProgram {
        val start = r.pos
        val lengthField = r.u4().toLong() and 0xffffffffL
        val is64 = lengthField == 0xffffffffL
        val unitLength = if (is64) r.u8() else lengthField
        val afterLength = r.pos
        val end = (afterLength + unitLength).toInt()
        if (end <= r.pos || end > r.data.size) throw ParseException("line program bad length at 0x${start.toString(16)}")
        val body = ByteReader(r.data, afterLength, end, afterLength)

        val version = body.u2()
        var addressSize = 4
        var segmentSelectorSize = 0
        if (version >= 5) {
            addressSize = body.u1()
            segmentSelectorSize = body.u1()
        }
        val minInsnLen = body.u1()
        var maxOps = 1
        if (version >= 4) {
            body.u1() // maximum_operations_per_indirect (v4); v5: maximum_ops_per_instruction
            maxOps = 1
        }
        val defaultStmt = body.u1() == 1
        val lineBase = body.u1().toByte().toInt()
        val lineRange = body.u1()
        if (lineRange == 0) throw ParseException("line_range == 0 at 0x${start.toString(16)}")
        val opcodeBase = body.u1()
        val stdLengths = mutableListOf<Int>()
        for (i in 1 until opcodeBase) stdLengths.add(body.u1())

        val directories = mutableListOf<String>()
        val files = mutableListOf<LineFile>()

        if (version >= 5) {
            val dirEntryFormatCount = body.u1()
            val dirFormats = (0 until dirEntryFormatCount).map { body.uleb().toInt() to body.uleb().toInt() }
            val dirsCount = body.uleb().toInt()
            repeat(dirsCount) {
                directories.add(readPath(dirFormats, body, sections, directories) ?: "")
            }
            val fileEntryFormatCount = body.u1()
            val fileFormats = (0 until fileEntryFormatCount).map { body.uleb().toInt() to body.uleb().toInt() }
            val filesCount = body.uleb().toInt()
            var id = 1
            repeat(filesCount) {
                val attrs = readEntryAttrs(fileFormats, body, sections, directories)
                val name = attrs[DW.LN.LCT_path]?.let { it as? AttrValue.Str }?.value ?: ""
                val dirIdx = (attrs[DW.LN.LCT_directory_index] as? AttrValue.Const)?.value?.toInt()
                files.add(LineFile(id++, name, dirIdx, null, null))
            }
        } else {
            directories.add("") // index 0 = compile directory
            while (true) {
                val s = body.zeroString()
                if (s.isEmpty()) break
                directories.add(s)
            }
            while (true) {
                val name = body.zeroString()
                if (name.isEmpty()) break
                val dirIdx = body.uleb().toInt()
                val ts = body.uleb()
                val size = body.uleb()
                files.add(LineFile(files.size + 1, name, dirIdx, ts, size))
            }
        }

        val header = Header(version, minInsnLen, maxOps, defaultStmt, lineBase, lineRange,
            opcodeBase, stdLengths, files, directories, addressSize, segmentSelectorSize)

        val sequences = runProgram(body, header)
        return LineProgram(
            sectionOffset = start.toLong(),
            version = version,
            files = files,
            directories = directories,
            sequences = sequences,
            addressSize = addressSize,
            segmentSelectorSize = segmentSelectorSize,
            defaultIsStatement = defaultStmt,
        )
    }

    private fun readPath(
        formats: List<Pair<Int, Int>>,
        r: ByteReader,
        sections: DwarfSections,
        directories: List<String>,
    ): String? {
        val attrs = readEntryAttrs(formats, r, sections, directories)
        return attrs[DW.LN.LCT_path]?.let { it as? AttrValue.Str }?.value
    }

    private fun readEntryAttrs(
        formats: List<Pair<Int, Int>>,
        r: ByteReader,
        sections: DwarfSections,
        directories: List<String>,
    ): Map<Int, AttrValue> {
        val out = LinkedHashMap<Int, AttrValue>()
        // A temporary unit-like context is overkill for line headers; handle forms inline.
        for ((contentType, form) in formats) {
            val v: AttrValue = when (form) {
                DW.FORM.string -> AttrValue.Str(r.zeroString())
                DW.FORM.strp -> {
                    val off = r.u4().toLong() and 0xffffffffL
                    val sec = sections.bytes(".debug_str")
                    if (sec != null && off < sec.size) AttrValue.Str(ByteReader(sec).cStringAt(off.toInt()))
                    else AttrValue.Str("")
                }
                DW.FORM.line_strp -> {
                    val off = r.u4().toLong() and 0xffffffffL
                    val sec = sections.bytes(".debug_line_str")
                    if (sec != null && off < sec.size) AttrValue.Str(ByteReader(sec).cStringAt(off.toInt()))
                    else AttrValue.Str("")
                }
                DW.FORM.data1, DW.FORM.udata -> if (form == DW.FORM.data1) AttrValue.Const(r.u1().toLong()) else AttrValue.Const(r.uleb())
                DW.FORM.data2 -> AttrValue.Const(r.u2().toLong())
                DW.FORM.data4 -> AttrValue.Const(r.u4().toLong() and 0xffffffffL)
                DW.FORM.data8 -> AttrValue.Const(r.u8())
                DW.FORM.sdata -> AttrValue.Const(r.sleb())
                DW.FORM.flag_present -> AttrValue.Const(1L)
                else -> throw ParseException("unsupported line-header form 0x${form.toString(16)}")
            }
            out[contentType] = v
        }
        return out
    }

    private class State(val defaultStmt: Boolean, var seg: Int = 0) {
        var address = 0L
        var file = 1
        var line = 1
        var column = 0
        var isStmt = defaultStmt
        var basicBlock = false
        var endSequence = false
        var prologueEnd = false
        var epilogueBegin = false
        var isa = 0
        var discriminator = 0
    }

    private fun runProgram(r: ByteReader, h: Header): List<LineSequence> {
        val sequences = mutableListOf<LineSequence>()
        val rows = mutableListOf<LineRow>()
        var s = State(h.defaultIsStmt)
        var sequenceStart = 0L

        fun append() {
            rows.add(LineRow(
                s.address, s.seg, s.file, s.line, s.column, s.isStmt, s.basicBlock,
                s.endSequence, s.prologueEnd, s.epilogueBegin, s.isa, s.discriminator,
            ))
        }

        fun reset() {
            s = State(h.defaultIsStmt, s.seg)
            rows.clear()
            sequenceStart = 0L
        }

        while (r.remaining() > 0) {
            val op = r.u1()
            when {
                op == 0 -> {
                    val extLen = r.uleb().toInt()
                    if (extLen <= 0 || r.remaining() < extLen) {
                        throw ParseException("extended opcode bad length $extLen")
                    }
                    val sub = ByteReader(r.data, r.pos, r.pos + extLen, r.pos)
                    r.skip(extLen)
                    val extOp = sub.u1()
                    when (extOp) {
                        DW.LN.EXT_end_sequence -> {
                            s.endSequence = true
                            append()
                            val seg = rows.firstOrNull()?.segment ?: 0
                            val start = sequenceStart
                            val end = s.address
                            sequences.add(LineSequence(rows.toList(), seg, start, end))
                            reset()
                        }
                        DW.LN.EXT_set_address -> {
                            if (h.segmentSelectorSize > 0) {
                                s.seg = readSized(sub, h.segmentSelectorSize).toInt()
                            }
                            s.address = readSized(sub, h.addressSize)
                            sequenceStart = s.address
                        }
                        DW.LN.EXT_define_file -> {
                            val name = sub.zeroString()
                            val dirIdx = sub.uleb().toInt()
                            val ts = sub.uleb()
                            val size = sub.uleb()
                            h.files.add(LineFile(h.files.size + 1, name, dirIdx, ts, size))
                        }
                        DW.LN.EXT_set_discriminator -> s.discriminator = sub.uleb().toInt()
                        else -> {
                            // Unknown extended op: length already skipped; cursor stays aligned.
                        }
                    }
                }
                op < h.opcodeBase -> {
                    when (op) {
                        DW.LN.copy -> {
                            append()
                            s.basicBlock = false; s.prologueEnd = false; s.epilogueBegin = false
                            s.discriminator = 0
                        }
                        DW.LN.advance_pc -> {
                            s.address += r.uleb()
                            if (sequenceStart == 0L) sequenceStart = s.address
                        }
                        DW.LN.advance_line -> s.line += r.sleb().toInt()
                        DW.LN.set_file -> s.file = r.uleb().toInt()
                        DW.LN.set_column -> s.column = r.uleb().toInt()
                        DW.LN.negate_stmt -> s.isStmt = !s.isStmt
                        DW.LN.set_basic_block -> s.basicBlock = true
                        DW.LN.const_add_pc -> {
                            s.address += adjustedOpcode(255, h).first.toLong() * h.minInsnLen.toLong()
                            if (sequenceStart == 0L) sequenceStart = s.address
                        }
                        DW.LN.fixed_advance_pc -> s.address += r.u2().toLong() and 0xffffL
                        DW.LN.set_prologue_end -> s.prologueEnd = true
                        DW.LN.set_epilogue_begin -> s.epilogueBegin = true
                        DW.LN.set_isa -> s.isa = r.uleb().toInt()
                        else -> {
                            val operands = h.stdOpcodeLengths.getOrElse(op - 1) {
                                throw ParseException("standard opcode $op outside declared lengths")
                            }
                            repeat(operands) { r.uleb() }
                        }
                    }
                }
                else -> {
                    val (adv, lineAdv) = adjustedOpcode(op, h)
                    s.address += adv.toLong() * h.minInsnLen.toLong()
                    if (sequenceStart == 0L) sequenceStart = s.address
                    s.line += lineAdv
                    append()
                    s.basicBlock = false; s.prologueEnd = false; s.epilogueBegin = false
                    s.discriminator = 0
                }
            }
        }
        return sequences
    }

    private fun adjustedOpcode(op: Int, h: Header): Pair<Int, Int> {
        val adjusted = op - h.opcodeBase
        val adv = adjusted / h.lineRange
        val lineAdv = h.lineBase + (adjusted % h.lineRange)
        return adv to lineAdv
    }

    private fun readSized(r: ByteReader, size: Int): Long = when (size) {
        1 -> r.u1().toLong()
        2 -> r.u2().toLong() and 0xffffL
        4 -> r.u4().toLong() and 0xffffffffL
        8 -> r.u8()
        else -> throw ParseException("unsupported address/segment size $size")
    }
}
