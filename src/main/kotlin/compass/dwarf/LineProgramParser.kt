package compass.dwarf

import compass.elf.ElfFile

/** Result of parsing one .debug_line contribution for a CU. */
object LineProgramParser {

    private data class Regs(
        var address: Long = 0,
        var segment: Long = 0,
        var opIndex: Int = 0,
        var file: Int = 1,
        var line: Int = 1,
        var column: Int = 0,
        var isStmt: Boolean,
        var basicBlock: Boolean = false,
        var endSequence: Boolean = false,
        var prologueEnd: Boolean = false,
        var epilogueBegin: Boolean = false,
        var isa: Int = 0,
        var discriminator: Int = 0,
    )

    fun parse(
        elf: ElfFile,
        sectionOffset: Long,
        cuVersion: Int,
        cuAddressSize: Int,
        cuDwarf64: Boolean,
        cuId: Int,
        warnings: MutableList<String>,
    ): LineProgram? {
        val sec = elf.reader(".debug_line") ?: return null
        val r = sec.subReader(sec.base, sec.limit)
        try {
            r.seek(sectionOffset)
        } catch (e: BoundsException) {
            warnings.add("DW_AT_stmt_list offset 0x${sectionOffset.toString(16)} is out of .debug_line bounds")
            return null
        }
        try {
            val (unitLen, d64) = r.initialLength()
            if (unitLen <= 0) {
                warnings.add("line program at 0x${sectionOffset.toString(16)} has non-positive length")
                return null
            }
            val endOff = r.sectionOffset() + unitLen
            if (endOff > r.limit - r.base) {
                warnings.add("line program at 0x${sectionOffset.toString(16)} overruns .debug_line")
                return null
            }
            val version = r.u16().toInt()
            if (version !in 2..5) {
                warnings.add("line program version $version unsupported")
                return null
            }

            var minInsnLen = 1
            var maxOps = 1
            var defaultStmt = true
            var lineBase = 0
            var lineRange = 1
            var opcodeBase = 13
            var standardOpcodeLengths = IntArray(0)
            val directories = ArrayList<String>()
            val files = ArrayList<LineFile>()
            var segmentSelectorSize = 0
            var lineAddressSize = cuAddressSize
            var directoryEntryFormat = emptyList<Pair<Int, Int>>()
            var fileEntryFormat = emptyList<Pair<Int, Int>>()

            if (version >= 5) {
                lineAddressSize = r.u8() // address_size
                segmentSelectorSize = r.u8()
                minInsnLen = r.u8()
                maxOps = r.u8().coerceAtLeast(1)
                r.u8() // default_is_stmt
                defaultStmt = r.u8() != 0
                lineBase = r.i8()
                lineRange = r.u8()
                opcodeBase = r.u8()
                standardOpcodeLengths = IntArray(opcodeBase) { if (it == 0) 0 else r.u8() }
                val dirEntryFormatCount = r.u8()
                directoryEntryFormat = readEntryFormats(r, dirEntryFormatCount)
                val dirCount = r.uleb().toInt()
                readV5FileLists(r, elf, directoryEntryFormat, dirCount, directories, files, true, d64, cuVersion, warnings)
                val fileEntryFormatCount = r.u8()
                fileEntryFormat = readEntryFormats(r, fileEntryFormatCount)
                val fileCount = r.uleb().toInt()
                readV5FileLists(r, elf, fileEntryFormat, fileCount, directories, files, false, d64, cuVersion, warnings)
            } else {
                minInsnLen = r.u8()
                defaultStmt = r.u8() != 0
                lineBase = r.i8()
                lineRange = r.u8()
                opcodeBase = r.u8()
                standardOpcodeLengths = IntArray(opcodeBase) { if (it == 0) 0 else r.u8() }
                // include_directories
                while (true) {
                    val s = r.cString()
                    if (s.isEmpty()) break
                    directories.add(s)
                }
                // file_names
                var fileId = 1
                while (true) {
                    val name = r.cString()
                    if (name.isEmpty()) break
                    val dirIdx = r.uleb().toInt()
                    val mtime = r.uleb()
                    val size = r.uleb()
                    files.add(LineFile(fileId++, name, if (dirIdx == 0) "" else directories.getOrElse(dirIdx - 1) { "" }, mtime, size))
                }
            }

            val sequences = ArrayList<LineSequence>()
            val orderedRows = ArrayList<LineRow>()
            val regs = Regs(isStmt = defaultStmt)
            var rowsSinceReset = ArrayList<LineRow>()
            var rowGuard = 0
            val dummyTables = AbbreviationTables(null)
            val formReader = FormReader(elf, dummyTables, AddrTable(elf.reader(".debug_addr")))
            val ctx = FormReader.CuContext(cuVersion, d64, cuAddressSize, sectionOffset, null, null)

            fun row(endSeq: Boolean) {
                val copy = LineRow(regs.address, regs.segment, regs.file, regs.line, regs.column,
                    regs.isStmt, endSeq, regs.basicBlock, regs.prologueEnd, regs.epilogueBegin,
                    regs.isa, regs.discriminator, regs.opIndex)
                orderedRows.add(copy)
                rowsSinceReset.add(copy)
            }

            fun reset() {
                regs.address = 0; regs.segment = 0; regs.opIndex = 0; regs.file = 1
                regs.line = 1; regs.column = 0; regs.isStmt = defaultStmt
                regs.basicBlock = false; regs.endSequence = false; regs.prologueEnd = false
                regs.epilogueBegin = false; regs.isa = 0; regs.discriminator = 0
                rowsSinceReset = ArrayList()
            }

            while (r.sectionOffset() < endOff) {
                if (++rowGuard > 20_000_000) {
                    warnings.add("line program at 0x${sectionOffset.toString(16)} hit row limit")
                    break
                }
                val opcode = r.u8()
                if (opcode >= opcodeBase) {
                    val adjusted = opcode - opcodeBase
                    val advanceAmount = adjusted / lineRange
                    if (maxOps > 1) {
                        val newOp = regs.opIndex + advanceAmount
                        regs.address += (minInsnLen * (newOp / maxOps)).toLong()
                        regs.opIndex = newOp % maxOps
                    } else {
                        regs.address += (minInsnLen * advanceAmount).toLong()
                    }
                    regs.line += lineBase + (adjusted % lineRange)
                    row(false)
                    regs.basicBlock = false
                    regs.prologueEnd = false
                    regs.epilogueBegin = false
                    regs.discriminator = 0
                    continue
                }
                when (opcode) {
                    0 -> {
                        val extLen = r.uleb().toInt()
                        val extEnd = r.sectionOffset() + extLen
                        val extOp = r.u8()
                        when (extOp) {
                            LineExt.END_SEQUENCE -> {
                                regs.endSequence = true
                                row(true)
                                if (rowsSinceReset.isNotEmpty()) {
                                    val seqRows = rowsSinceReset.toList()
                                    val start = seqRows.first()
                                    val endAddr = regs.address
                                    sequences.add(LineSequence(
                                        startAddress = start.address,
                                        endAddress = endAddr,
                                        segment = regs.segment,
                                        rows = seqRows,
                                        startFile = start.file,
                                        startLine = start.line,
                                    ))
                                }
                                reset()
                            }
                            LineExt.SET_ADDRESS -> {
                                if (segmentSelectorSize > 0) {
                                    regs.segment = when (segmentSelectorSize) {
                                        1 -> r.u8().toLong(); 2 -> r.u16().toLong()
                                        4 -> r.u32(); 8 -> r.u64(); else -> r.u64()
                                    }
                                }
                                val savedSize = r.addressSize
                                r.addressSize = lineAddressSize
                                regs.address = r.address()
                                r.addressSize = savedSize
                            }
                            LineExt.DEFINE_FILE -> {
                                if (version >= 5) {
                                    val values = readContentDescription(r, elf, fileEntryFormat, formReader, ctx, warnings)
                                    val name = (values[0x01] as? AttrValue.Str)?.v ?: ""
                                    val dirIdx = (values[0x02] as? AttrValue.Num)?.v?.toInt() ?: 0
                                    files.add(LineFile(files.size + 1, name,
                                        directories.getOrElse(dirIdx) { "" }, 0, 0))
                                } else {
                                    val name = r.cString()
                                    val dirIdx = r.uleb().toInt()
                                    val mtime = r.uleb(); val size = r.uleb()
                                    files.add(LineFile(files.size + 1, name,
                                        directories.getOrElse(dirIdx - 1) { "" }, mtime, size))
                                }
                            }
                            LineExt.SET_DISCRIMINATOR -> regs.discriminator = r.uleb().toInt()
                            LineExt.SET_IS_STATEMENT_V5 -> { regs.isStmt = r.u8() != 0 }
                            LineExt.SET_BASIC_BLOCK_V5 -> { regs.basicBlock = true }
                            LineExt.ADD_CONST_PC_V5 -> {
                                regs.address += minInsnLen.toLong()
                            }
                            LineExt.SET_FIRST_SPECIAL_V5 -> { /* no operands */ }
                            else -> {
                                // Unknown extended opcode: skip the remaining body bytes.
                            }
                        }
                        r.seek(extEnd)
                    }
                    LineOp.ADVANCE_PC -> {
                        val a = r.uleb().toInt()
                        if (maxOps > 1) {
                            val newOp = regs.opIndex + a
                            regs.address += (minInsnLen * (newOp / maxOps)).toLong()
                            regs.opIndex = newOp % maxOps
                        } else {
                            regs.address += (minInsnLen * a).toLong()
                        }
                    }
                    LineOp.LINE -> regs.line = r.sleb().toInt()
                    LineOp.FILE -> {
                        if (version >= 5) regs.file = r.uleb().toInt()
                        else regs.file = r.uleb().toInt()
                    }
                    LineOp.SET_COLUMN -> regs.column = r.uleb().toInt()
                    LineOp.NEGATE_STMT -> regs.isStmt = !regs.isStmt
                    LineOp.SET_BASIC_BLOCK -> regs.basicBlock = true
                    LineOp.CONST_ADD_PC -> {
                        val a = (255 - opcodeBase) / lineRange
                        regs.address += (minInsnLen * a).toLong()
                    }
                    LineOp.FIXED_ADVANCE_PC -> regs.address += r.u16().toLong()
                    LineOp.SET_PROLOGUE_END, LineOp.SET_PROLOGUE_END_V5 -> regs.prologueEnd = true
                    LineOp.SET_EPILOGUE_BEGIN, LineOp.SET_EPILOGUE_BEGIN_V5 -> regs.epilogueBegin = true
                    LineOp.SET_ISA -> regs.isa = r.uleb().toInt()
                    LineOp.COPY -> row(false).also {
                        regs.basicBlock = false; regs.prologueEnd = false
                        regs.epilogueBegin = false; regs.discriminator = 0
                    }
                    LineOp.UNDEFINED -> { /* DWARF5: register undefined, no operands */ }
                    LineOp.SAME_VALUE -> { /* DWARF5: no operands */ }
                    else -> {
                        val len = standardOpcodeLengths.getOrNull(opcode)
                        if (len == null) {
                            warnings.add("unknown standard opcode $opcode in line program at 0x${sectionOffset.toString(16)}; cannot resynchronize, stopping this program")
                            break
                        }
                        repeat(len) { r.uleb() }
                    }
                }
            }

            return LineProgram(cuId, sectionOffset, version, minInsnLen, maxOps, defaultStmt,
                lineBase, lineRange, opcodeBase, files, directories, sequences, orderedRows)
        } catch (e: BoundsException) {
            warnings.add("line program at 0x${sectionOffset.toString(16)} truncated: ${e.message}")
            return null
        }
    }

    private fun readEntryFormats(r: ByteReader, count: Int): List<Pair<Int, Int>> {
        val out = ArrayList<Pair<Int, Int>>(count)
        repeat(count) { out.add(r.uleb().toInt() to r.uleb().toInt()) }
        return out
    }

    private fun readContentDescription(
        r: ByteReader, elf: ElfFile, formats: List<Pair<Int, Int>>,
        formReader: FormReader, ctx: FormReader.CuContext, warnings: MutableList<String>
    ): Map<Int, AttrValue> {
        val map = HashMap<Int, AttrValue>()
        val savedAddrSize = r.addressSize
        for ((contentType, form) in formats) {
            try {
                val v = if (form == Form.IMPLICIT_CONST) AttrValue.Num(0)
                else formReader.read(form, 0, r, ctx)
                map[contentType] = v
            } catch (e: UnknownFormException) {
                warnings.add("unknown line content form 0x${e.form.toString(16)}; file entry incomplete")
                throw e
            }
        }
        r.addressSize = savedAddrSize
        return map
    }

    private fun readV5FileLists(
        r: ByteReader, elf: ElfFile, formats: List<Pair<Int, Int>>, count: Int,
        directories: MutableList<String>, files: MutableList<LineFile>,
        isDir: Boolean, d64: Boolean, cuVersion: Int, warnings: MutableList<String>
    ) {
        val formReader = FormReader(elf, AbbreviationTables(null), AddrTable(null))
        val ctx = FormReader.CuContext(cuVersion, d64, 8, 0, null, null)
        repeat(count) {
            val savedAddrSize = r.addressSize
            val values = readContentDescription(r, elf, formats, formReader, ctx, warnings)
            r.addressSize = savedAddrSize
            val name = (values[0x01] as? AttrValue.Str)?.v ?: ""
            val dirIdx = (values[0x02] as? AttrValue.Num)?.v?.toInt() ?: 0
            if (isDir) directories.add(name)
            else files.add(LineFile(files.size + 1, name,
                directories.getOrElse(dirIdx) { "" }, 0, 0))
        }
    }
}
