@file:JvmName("LineProgramParser")
package compass.dwarf

import compass.binary.ByteReader
import compass.binary.DwarfCorruptException


internal data class PendingRef(val offset: Long, val lineStr: Boolean)

internal class LineRegs(h: LineHeader) {
    var address = 0L
    var segment = 0L
    var opIndex = 0
    var file = h.fileIndexBase
    var line = 1
    var column = 0
    var isStmt = h.defaultIsStmt != 0
    var basicBlock = false
    var endSequence = false
    var prologueEnd = false
    var epilogueBegin = false
    var isa = 0
    var discriminator = 0

    fun reset(h: LineHeader) {
        address = 0L; segment = 0L; opIndex = 0
        file = h.fileIndexBase; line = 1; column = 0
        isStmt = h.defaultIsStmt != 0
        basicBlock = false; endSequence = false; prologueEnd = false
        epilogueBegin = false; isa = 0; discriminator = 0
    }

    fun row(h: LineHeader) = LineRow(
        address, segment, file, line, column, isStmt, endSequence,
        basicBlock, prologueEnd, epilogueBegin, isa, discriminator
    )
}

internal fun parseLineHeader(reader: ByteReader, versionHint: Int = 0): LineHeader {
    val offset = reader.pos.toLong()
    val lengthFirst = reader.u32()
    val dwarf64: Boolean
    val unitLength: Long
    when (lengthFirst) {
        0xffffffffL -> { dwarf64 = true; unitLength = reader.u64() }
        in 0..0xfffffff0L -> { dwarf64 = false; unitLength = lengthFirst }
        else -> throw DwarfCorruptException("reserved line unit length")
    }
    val afterLength = reader.pos
    val endOffset = afterLength.toLong() + unitLength
    if (endOffset > reader.data.size) throw DwarfCorruptException("line program overruns section")
    val version = reader.u16()
    if (version !in 2..5) throw DwarfCorruptException("unsupported line program version $version")

    var addressSize = -1
    var segmentSelectorSize = 0
    if (version >= 5) {
        addressSize = reader.u8()
        segmentSelectorSize = reader.u8()
    }
    if (dwarf64) reader.u64() else reader.u32() // header_length offset field (comp_dir offset)
    val headerLength = if (dwarf64) reader.u64() else reader.u32()
    val programStart = reader.pos.toLong() + headerLength

    val minInsnLength = reader.u8()
    var maxOps = 1
    if (version >= 5) maxOps = reader.u8().let { if (it == 0) 1 else it }
    val defaultIsStmt = reader.u8()
    val lineBase = reader.u8().toByte().toInt()
    val lineRange = reader.u8()
    if (lineRange == 0) throw DwarfCorruptException("line_range is zero")
    val opcodeBase = reader.u8()
    val stdLengths = IntArray(maxOf(0, opcodeBase - 1))
    for (i in stdLengths.indices) stdLengths[i] = reader.u8()

    val directories = mutableListOf<String>()
    val pendingDirRefs = mutableListOf<PendingRef>()
    val files = mutableListOf<LineFile>()
    var fileIndexBase = 1

    if (version <= 4) {
        // include_directories
        directories.add("") // index 0 = comp dir placeholder
        while (true) {
            val s = readV4String(reader, programStart)
            if (s.isEmpty()) break
            directories.add(s)
        }
        // file_names
        while (true) {
            val start = reader.pos
            val name = readV4String(reader, programStart)
            if (name.isEmpty()) break
            val dir = reader.uleb().toInt()
            reader.uleb() // mtime
            reader.uleb() // size
            files.add(LineFile(name, dir))
            @Suppress("UNUSED_VARIABLE") val unused = start
        }
    } else {
        fileIndexBase = 0
        directories.add("") // index 0 = current directory (comp_dir joins happen at display time)
        val dirEntryFormatCount = reader.u8()
        val dirFormCount = reader.u8()
        val dirForms = ArrayList<Pair<Int, Int>>(dirFormCount)
        repeat(dirEntryFormatCount) {
            val contentType = reader.uleb().toInt()
            val form = reader.uleb().toInt()
            dirForms.add(contentType to form)
        }
        val dirsCount = reader.uleb().toInt()
        if (dirsCount > 1_000_000) throw DwarfCorruptException("directory count absurd")
        repeat(dirsCount) {
            var path: String? = null
            var pending: Long? = null
            var lineStr = false
            for ((contentType, form) in dirForms) {
                val raw = readLineHeaderValue(reader, form, dwarf64)
                if (contentType == DW.CT_path) {
                    when (raw) {
                        is AttrValue.Str -> path = raw.text
                        is AttrValue.StrRef -> { pending = raw.offset; lineStr = raw.lineStr }
                        else -> {}
                    }
                }
            }
            if (path == null && pending != null) {
                directories.add("")
                pendingDirRefs.add(PendingRef(pending, lineStr))
            } else directories.add(path ?: "")
        }

        val fileEntryFormatCount = reader.u8()
        val fileFormCount = reader.u8()
        val fileForms = ArrayList<Pair<Int, Int>>(fileFormCount)
        repeat(fileEntryFormatCount) {
            fileForms.add(reader.uleb().toInt() to reader.uleb().toInt())
        }
        val fileCount = reader.uleb().toInt()
        if (fileCount > 10_000_000) throw DwarfCorruptException("file count absurd")
        repeat(fileCount) {
            var path: String? = null
            var dirIndex = 0
            var pending: Long? = null
            var lineStr = false
            for ((contentType, form) in fileForms) {
                val raw = readLineHeaderValue(reader, form, dwarf64)
                when (contentType) {
                    DW.CT_path -> when (raw) {
                        is AttrValue.Str -> path = raw.text
                        is AttrValue.StrRef -> { pending = raw.offset; lineStr = raw.lineStr }
                        else -> {}
                    }
                    DW.CT_directory_index -> if (raw is AttrValue.Constant) dirIndex = raw.value.toInt()
                }
            }
            files.add(LineFile(path, dirIndex, pending, lineStr))
        }
    }

    if (reader.pos.toLong() != programStart) {
        // tolerant: jump to program start (v5 forms are fixed-width so this is usually exact)
        reader.seek(programStart.toInt())
    }

    return LineHeader(
        offset = offset,
        version = version,
        addressSize = if (addressSize > 0) addressSize else 4,
        segmentSelectorSize = segmentSelectorSize,
        minInstructionLength = minInsnLength,
        maxOpsPerInstruction = maxOps,
        defaultIsStmt = defaultIsStmt,
        lineBase = lineBase,
        lineRange = lineRange,
        opcodeBase = opcodeBase,
        standardOpcodeLengths = stdLengths,
        directories = directories,
        files = files,
        fileIndexBase = fileIndexBase,
        programOffset = programStart,
        unitLength = unitLength
    )
}

private fun readV4String(reader: ByteReader, limit: Long): String {
    val start = reader.pos
    var end = start
    while (end < limit && reader.data[end].toInt() != 0) end++
    if (end >= limit) throw DwarfCorruptException("unterminated line header string")
    val s = String(reader.data, start, end - start, Charsets.UTF_8)
    reader.seek(end + 1)
    return s
}

private fun readLineHeaderValue(reader: ByteReader, form: Int, dwarf64: Boolean): AttrValue = when (form) {
    DW.FORM_string -> AttrValue.Str(reader.cstring())
    DW.FORM_line_strp -> AttrValue.StrRef(if (dwarf64) reader.u64() else reader.u32(), true)
    DW.FORM_strp -> AttrValue.StrRef(if (dwarf64) reader.u64() else reader.u32(), false)
    DW.FORM_data1, DW.FORM_strx1, DW.FORM_addrx1 -> AttrValue.Constant(reader.u8().toLong(), 1)
    DW.FORM_data2, DW.FORM_strx2, DW.FORM_addrx2 -> AttrValue.Constant(reader.u16().toLong(), 2)
    DW.FORM_data4, DW.FORM_strx4, DW.FORM_addrx4 -> AttrValue.Constant(reader.u32(), 4)
    DW.FORM_data8 -> AttrValue.Constant(reader.u64(), 8)
    DW.FORM_udata, DW.FORM_strx, DW.FORM_addrx -> AttrValue.Constant(reader.uleb(), 0)
    DW.FORM_sdata -> AttrValue.Constant(reader.sleb(), 0)
    DW.FORM_flag -> AttrValue.Flag(reader.u8() != 0)
    DW.FORM_flag_present -> AttrValue.FlagTrue
    DW.FORM_sec_offset -> AttrValue.SecOffset(if (dwarf64) reader.u64() else reader.u32())
    else -> throw DwarfCorruptException("unsupported line header form 0x${form.toString(16)}")
}

internal fun executeLineProgram(
    sections: DwarfSections,
    littleEndian: Boolean,
    header: LineHeader
): List<LineSequence> {
    val data = sections[".debug_line"] ?: sections[".debug_line.dwo"]
        ?: throw DwarfCorruptException("missing .debug_line")
    val reader = ByteReader(data, littleEndian, header.programOffset.toInt())
    val lengthFieldSize = if (data[header.offset.toInt()].toLong() and 0xff == 0xffL) 12 else 4
    val programEnd = header.offset + lengthFieldSize + header.unitLength
    val regs = LineRegs(header)
    val rows = mutableListOf<LineRow>()
    val sequences = mutableListOf<LineSequence>()

    fun flush() {
        if (rows.isNotEmpty()) sequences.add(LineSequence(header, rows.toList()))
        rows.clear()
    }

    while (reader.pos.toLong() < programEnd) {
        val opcode = reader.u8()
        if (opcode == 0) {
            // extended
            val length = reader.uleb().toInt()
            if (length == 0) continue
            val extStart = reader.pos
            val sub = reader.u8()
            when (sub) {
                DW.LNE_end_sequence -> {
                    regs.endSequence = true
                    rows.add(regs.row(header))
                    flush()
                    regs.reset(header)
                }
                DW.LNE_set_address -> {
                    if (header.version >= 5 && header.segmentSelectorSize > 0) {
                        regs.segment = reader.word(header.segmentSelectorSize)
                    }
                    regs.address = reader.word(header.addressSize)
                    regs.opIndex = 0
                }
                DW.LNE_define_file -> {
                    if (header.version <= 4) {
                        reader.cstring(programEnd.toInt())
                        reader.uleb(); reader.uleb(); reader.uleb()
                    } else {
                        // v5 reserves 3 as DW_LNE_define_file with v4-style operands, rarely used
                        reader.cstring(programEnd.toInt())
                        reader.uleb(); reader.uleb(); reader.uleb()
                    }
                }
                DW.LNE_set_discriminator -> regs.discriminator = reader.uleb().toInt()
                else -> reader.seek(extStart + length)
            }
            if (reader.pos < extStart + length) reader.seek(extStart + length)
        } else if (opcode < header.opcodeBase) {
            when (opcode) {
                DW.LNS_copy -> rows.add(regs.row(header))
                DW.LNS_advance_pc -> {
                    val advance = reader.uleb().toInt()
                    regs.address += (header.minInstructionLength *
                        (regs.opIndex + advance) / header.maxOpsPerInstruction).toLong()
                    regs.opIndex = (regs.opIndex + advance) % header.maxOpsPerInstruction
                }
                DW.LNS_advance_line -> regs.line += reader.sleb().toInt()
                DW.LNS_set_file -> regs.file = reader.uleb().toInt()
                DW.LNS_set_column -> regs.column = reader.uleb().toInt()
                DW.LNS_negate_stmt -> regs.isStmt = !regs.isStmt
                DW.LNS_set_basic_block -> regs.basicBlock = true
                DW.LNS_const_add_pc -> {
                    val adjusted = (255 - header.opcodeBase) / header.lineRange
                    regs.address += (header.minInstructionLength *
                        (regs.opIndex + adjusted) / header.maxOpsPerInstruction).toLong()
                }
                DW.LNS_fixed_advance_pc -> {
                    val operand = reader.u16()
                    regs.address += operand.toLong()
                    regs.opIndex = 0
                }
                DW.LNS_set_prologue_end -> regs.prologueEnd = true
                DW.LNS_set_epilogue_begin -> regs.epilogueBegin = true
                DW.LNS_set_isa -> regs.isa = reader.uleb().toInt()
                else -> {
                    val arity = header.standardOpcodeLengths.getOrNull(opcode - 1) ?: 0
                    repeat(arity) { reader.uleb() }
                }
            }
            if (opcode != DW.LNS_advance_pc && opcode != DW.LNS_const_add_pc &&
                opcode != DW.LNS_fixed_advance_pc) {
                // non-PC opcodes: no adjustment needed
            }
            if (opcode == DW.LNS_copy) {
                regs.basicBlock = false; regs.prologueEnd = false
                regs.epilogueBegin = false; regs.discriminator = 0
            }
        } else {
            val adjusted = opcode - header.opcodeBase
            val advanceAddr = header.minInstructionLength *
                ((regs.opIndex + adjusted / header.lineRange) / header.maxOpsPerInstruction)
            regs.address += advanceAddr.toLong()
            regs.opIndex = (regs.opIndex + adjusted / header.lineRange) % header.maxOpsPerInstruction
            regs.line += header.lineBase + (adjusted % header.lineRange)
            rows.add(regs.row(header))
            regs.basicBlock = false; regs.prologueEnd = false
            regs.epilogueBegin = false; regs.discriminator = 0
        }
    }
    if (rows.isNotEmpty()) flush() // malformed missing end_sequence: still expose collected rows
    return sequences
}

/** Walks .debug_line collecting every header and the sequences produced by each program. */
internal fun parseAllLineProgramsInSection(
    sectionName: String,
    sections: DwarfSections,
    littleEndian: Boolean,
    headers: MutableList<LineHeader>,
    sequences: MutableList<LineSequence>,
    warnings: MutableList<String>
) {
    val data = sections[sectionName] ?: return
    val reader = ByteReader(data, littleEndian)
    while (reader.remaining > 0) {
        val start = reader.pos
        try {
            val header = parseLineHeader(reader)
            val seqs = executeLineProgram(sections, littleEndian, header)
            headers.add(header)
            sequences.addAll(seqs)
            val lengthFieldSize = if (data[start].toLong() and 0xff == 0xffL) 12 else 4
            val unitEnd = (header.offset + lengthFieldSize + header.unitLength).toInt()
            reader.seek(unitEnd)
        } catch (e: DwarfCorruptException) {
            warnings.add("$sectionName@0x${start.toString(16)}: ${e.message}")
            break
        }
    }
}
