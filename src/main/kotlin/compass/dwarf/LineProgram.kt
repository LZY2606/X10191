package compass.dwarf

import compass.elf.ByteReader
import compass.elf.DwarfParseException

/** Parsed view of one .debug_line contribution ("line program") with all of its sequences. */
class LineProgram(
    val version: Int,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val files: List<LineFile>,
    val sequences: List<LineSequence>,
    val cuOffset: Int,
    val notes: List<String>
)

object LineProgramParser {
    private const val MAX_OPS = 5_000_000

    fun parse(bundle: DebugBundle, sectionStartOffset: Long, cuOffset: Int, cuVersion: Int): LineProgram? {
        val section = bundle.line ?: return null
        val notes = ArrayList<String>()
        return try {
            parseInner(bundle, section, sectionStartOffset.toIntOrBail(), cuOffset, notes)
        } catch (e: DwarfParseException) {
            notes.add("line program parse failed: ${e.message}")
            null
        }
    }

    private fun Long.toIntOrBail(): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseException(".debug_line offset too large")
        return toInt()
    }

    private fun parseInner(
        bundle: DebugBundle,
        section: ByteArray,
        start: Int,
        cuOffset: Int,
        notes: MutableList<String>
    ): LineProgram {
        val r = ByteReader(section, bundle.elf.bigEndian, ".debug_line")
        r.seek(start)
        val unitStart = start
        val unitLength = r.u32()
        val is64: Boolean
        val length: Int
        if (unitLength == 0xffffffffL) {
            is64 = true; length = r.u64().toIntOrBail2()
        } else {
            is64 = false
            if (unitLength > Int.MAX_VALUE) throw DwarfParseException(".debug_line: bad unit length")
            length = unitLength.toInt()
        }
        val unitEnd = if (is64) r.pos + length else start + 4 + length
        if (unitEnd > section.size) throw DwarfParseException(".debug_line: unit runs past section end")

        val version = r.u16()
        if (version !in 2..5) throw DwarfParseException(".debug_line: unsupported version $version")

        var addressSize = 8
        var segmentSelectorSize = 0
        if (version >= 5) {
            addressSize = r.u8()
            segmentSelectorSize = r.u8()
        }
        val hlen = if (is64) r.u64() else r.u32()
        val headerEnd = r.pos + hlen.toInt()
        if (headerEnd > unitEnd) throw DwarfParseException(".debug_line: header length past unit end")

        val minInsnLen = r.u8()
        val maxOpsPerInsn = if (version >= 5) r.u8() else 1
        val defaultIsStmt = r.u8()
        val lineBase = r.sleb128().toInt()
        val lineRange = r.u8()
        val opcodeBase = r.u8()
        val stdOpcodeLengths = IntArray(opcodeBase) { 0 }
        for (i in 1 until opcodeBase) stdOpcodeLengths[i] = r.u8()
        if (lineRange == 0) throw DwarfParseException(".debug_line: line_range is zero")

        val dirs = ArrayList<String>()
        val files = ArrayList<LineFile>()

        if (version < 5) {
            // include_directories
            while (true) {
                val s = readStringInSection(section, r, bundle, inLineStr = false)
                if (s.isEmpty()) break
                dirs.add(s)
            }
            // file_names: null-terminated string, uleb dir, uleb time, uleb size
            while (true) {
                val name = readStringInSection(section, r, bundle, inLineStr = false)
                if (name.isEmpty()) break
                val dirIdx = r.uleb128().toInt()
                r.uleb128(); r.uleb128()
                val dir = if (dirIdx == 0) "" else dirs.getOrElse(dirIdx - 1) { "" }
                files.add(LineFile(dir, name))
            }
        } else {
            val directoryEntryFormatCount = r.u8()
            val dirFormat = ArrayList<Pair<Int, Int>>()
            for (i in 0 until directoryEntryFormatCount) {
                val content = r.uleb128().toInt(); val form = r.uleb128().toInt()
                dirFormat.add(content to form)
            }
            val directoriesCount = r.uleb128().toInt()
            for (i in 0 until directoriesCount) {
                var path = ""
                for ((_, form) in dirFormat) {
                    val v = readContent(form, r, bundle, notes)
                    if (v is AttrValue.StringVal) path = v.v
                }
                dirs.add(path)
            }
            val fileEntryFormatCount = r.u8()
            val fileFormat = ArrayList<Triple<Int, Int, Int>>()
            for (i in 0 until fileEntryFormatCount) {
                val content = r.uleb128().toInt(); val form = r.uleb128().toInt()
                fileFormat.add(Triple(content, form, 0))
            }
            val filesCount = r.uleb128().toInt()
            for (fi in 0 until filesCount) {
                var name = ""; var dirIdx = 0
                for ((content, form, _) in fileFormat) {
                    when (content) {
                        LCT.PATH -> { val v = readContent(form, r, bundle, notes); if (v is AttrValue.StringVal) name = v.v }
                        LCT.DIRECTORY_INDEX -> dirIdx = (readContent(form, r, bundle, notes) as? AttrValue.Constant)?.v?.toInt() ?: 0
                        else -> readContent(form, r, bundle, notes)
                    }
                }
                // v5 directory index is 0-based into the directories table; 0 = comp dir.
                val dir = if (dirIdx == 0) "" else dirs.getOrElse(dirIdx - 1) { "" }
                files.add(LineFile(dir, name))
            }
        }
        if (r.pos != headerEnd) {
            notes.add(".debug_line header padding: declared ${headerEnd - (r.pos)} trailing bytes skipped")
            r.seek(headerEnd)
        }

        val sequences = ArrayList<LineSequence>()
        var rows = ArrayList<LineRow>()
        var address = 0L
        var fileIndex = 1
        var line = 1
        var column = 0
        var isStmt = defaultIsStmt != 0
        var basicBlock = false
        var endSequence = false
        var opIndex = 0
        var isa = 0
        var discriminator = 0
        var segment = 0L
        var opCount = 0

        fun reset() {
            address = 0L; fileIndex = 1; line = 1; column = 0
            isStmt = defaultIsStmt != 0; basicBlock = false; endSequence = false
            opIndex = 0; isa = 0; discriminator = 0; segment = 0L
        }
        fun emitRow() {
            val file = files.getOrNull(fileIndex - 1)
            rows.add(LineRow(address, false, file, fileIndex, line, column, isStmt, opIndex, isa, discriminator))
        }
        fun adjustOpcode(adv: Int) {
            val newOp = opIndex + adv
            address += minInsnLen.toLong() * (newOp / maxOpsPerInsn)
            opIndex = newOp % maxOpsPerInsn
        }

        while (r.pos < unitEnd) {
            if (++opCount > MAX_OPS) throw DwarfParseException(".debug_line: opcode budget exceeded")
            val opcode = r.u8()
            if (opcode == 0) {
                val extLen = r.uleb128().toInt()
                val extEnd = r.pos + extLen
                val sub = r.u8()
                when (sub) {
                    LNE.END_SEQUENCE -> {
                        endSequence = true
                        val file = files.getOrNull(fileIndex - 1)
                        rows.add(LineRow(address, true, file, fileIndex, line, column, isStmt, opIndex, isa, discriminator))
                        sequences.add(LineSequence(rows, cuOffset))
                        rows = ArrayList()
                        reset()
                    }
                    LNE.SET_ADDRESS -> {
                        if (segmentSelectorSize > 0) segment = readFixed(segmentSelectorSize, r)
                        address = readFixed(addressSize, r)
                        opIndex = 0
                    }
                    LNE.DEFINE_FILE -> {
                        val name = readStringInSection(section, r, bundle, inLineStr = version < 5)
                        r.uleb128(); r.uleb128(); r.uleb128()
                        files.add(LineFile("", name))
                    }
                    LNE.SET_DISCRIMINATOR -> discriminator = r.uleb128().toInt()
                    else -> {}
                }
                r.seek(extEnd)
            } else if (opcode < opcodeBase) {
                when (opcode) {
                    LNS.COPY -> { emitRow(); basicBlock = false; discriminator = 0 }
                    LNS.ADVANCE_PC -> { val adv = r.uleb128().toInt(); adjustOpcode(adv) }
                    LNS.ADVANCE_LINE -> line += r.sleb128().toInt()
                    LNS.SET_FILE -> fileIndex = r.uleb128().toInt()
                    LNS.SET_COLUMN -> column = r.uleb128().toInt()
                    LNS.NEGATE_STMT -> isStmt = !isStmt
                    LNS.SET_BASIC_BLOCK -> basicBlock = true
                    LNS.CONST_ADD_PC -> adjustOpcode((255 - opcodeBase) / lineRange)
                    LNS.FIXED_ADVANCE_PC -> { address += r.u16().toLong(); opIndex = 0 }
                    LNS.SET_PROLOGUE_END -> {}
                    LNS.SET_ISA -> isa = r.uleb128().toInt()
                    else -> repeat(stdOpcodeLengths.getOrElse(opcode) { 0 }) { r.uleb128() }
                }
            } else {
                val adjusted = opcode - opcodeBase
                val advOp = adjusted / lineRange
                val advLine = (adjusted % lineRange) + lineBase
                line += advLine
                adjustOpcode(advOp)
                emitRow()
                basicBlock = false
                discriminator = 0
            }
        }
        if (rows.isNotEmpty()) {
            notes.add(".debug_line: program ended without DW_LNE_end_sequence")
            sequences.add(LineSequence(rows, cuOffset))
        }
        return LineProgram(version, addressSize, segmentSelectorSize, files, sequences, cuOffset, notes)
    }

    private fun Long.toIntOrBail2(): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseException(".debug_line: bad 64-bit length")
        return toInt()
    }

    private fun readFixed(size: Int, r: ByteReader): Long = when (size) {
        1 -> r.u8().toLong(); 2 -> r.u16().toLong(); 4 -> r.u32(); 8 -> r.u64()
        else -> throw DwarfParseException(".debug_line: bad fixed size $size")
    }

    private fun readStringInSection(
        lineSection: ByteArray,
        r: ByteReader,
        bundle: DebugBundle,
        inLineStr: Boolean
    ): String {
        // v4/v3: inline NUL string
        val start = r.pos
        var end = start
        while (end < lineSection.size && lineSection[end].toInt() != 0) end++
        if (end >= lineSection.size) throw DwarfParseException(".debug_line: unterminated inline string")
        r.pos = end + 1
        return String(lineSection, start, end - start, Charsets.UTF_8)
    }

    private fun readContent(form: Int, r: ByteReader, bundle: DebugBundle, notes: MutableList<String>): AttrValue {
        return when (form) {
            DW.FORM_STRING -> readInline(r)
            DW.FORM_LINE_STRP -> readLineStr(r, bundle)
            DW.FORM_STRP -> readDebugStr(r, bundle)
            DW.FORM_DATA1 -> AttrValue.Constant(r.u8().toLong())
            DW.FORM_DATA2 -> AttrValue.Constant(r.u16().toLong())
            DW.FORM_DATA4 -> AttrValue.Constant(r.u32())
            DW.FORM_DATA8, DW.FORM_DATA16 -> AttrValue.Constant(r.u64())
            DW.FORM_UDATA -> AttrValue.Constant(r.uleb128().toLong())
            else -> {
                notes.add("unsupported line content form 0x${form.toString(16)}; file table unreliable from this point")
                AttrValue.Unsupported
            }
        }
    }

    private fun readInline(r: ByteReader): AttrValue.StringVal {
        val s = r.cStringAt(r.pos)
        r.pos += s.toByteArray().size + 1
        return AttrValue.StringVal(s)
    }

    private fun readLineStr(r: ByteReader, bundle: DebugBundle): AttrValue.StringVal {
        val off = r.u32()
        val data = bundle.valLineStr ?: bundle.lineStrDwo
        ?: throw DwarfParseException(".debug_line_str referenced but section missing")
        val sr = ByteReader(data, bundle.elf.bigEndian, ".debug_line_str")
        return AttrValue.StringVal(sr.cStringAt(off.toIntSafe()))
    }

    private fun readDebugStr(r: ByteReader, bundle: DebugBundle): AttrValue.StringVal {
        val off = r.u32()
        val data = bundle.str ?: bundle.strDwo
        ?: throw DwarfParseException(".debug_str referenced but section missing")
        val sr = ByteReader(data, bundle.elf.bigEndian, ".debug_str")
        return AttrValue.StringVal(sr.cStringAt(off.toIntSafe()))
    }

    private fun Long.toIntSafe(): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseException("string offset too large")
        return toInt()
    }
}
