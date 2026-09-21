package compass.dwarf

import compass.binary.ByteReader
import compass.binary.DwarfParseException

private data class EntryFormat(val contentType: Int, val form: Int)

internal class LineRegs(defaultIsStmt: Boolean) {
    var address: Long = 0
    var file: Int = 1
    var line: Int = 1
    var column: Int = 0
    var isStmt: Boolean = defaultIsStmt
    var basicBlock: Boolean = false
    var endSequence: Boolean = false
    var prologueEnd: Boolean = false
    var epilogueBegin: Boolean = false
    var isa: Int = 0
    var discriminator: Int = 0
    fun reset(defaultIsStmt: Boolean) {
        address = 0; file = 1; line = 1; column = 0; isStmt = defaultIsStmt
        basicBlock = false; endSequence = false; prologueEnd = false
        epilogueBegin = false; isa = 0; discriminator = 0
    }
}

internal data class LineHeader(
    val version: Int,
    val defaultIsStmt: Boolean,
    val minInsnLen: Int,
    val maxOps: Int,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val files: List<FileEntry>,
    val dirs: List<String>,
    val programStart: Int,
    val unitEnd: Int,
)

class LineProgramParser(val sections: DwarfSections) {

    private fun cstringAt(sec: ByteArray, off: Int, warnings: MutableList<String>): String {
        if (off < 0 || off >= sec.size) { warnings.add("行程序字符串越界 off=$off"); return "" }
        var end = off
        while (end < sec.size && sec[end].toInt() != 0) end++
        return String(sec, off, end - off, Charsets.UTF_8)
    }

    private fun formReader(r: ByteReader, warnings: MutableList<String>) = FormReader(
        r = r, sections = sections, version = 5, offsetSize = 4, addressSize = 8,
        addrBase = null, strOffsetsBase = null,
        strOffsetsTables = AddrTables.scanStrOffsets(sections.strOffsets),
        warnings = warnings,
    )

    fun parse(cuIndex: Int, stmtList: Long, addressSize: Int, warnings: MutableList<String>): LineProgram? {
        val line = sections.line ?: return null
        if (stmtList < 0 || stmtList >= line.size) {
            warnings.add("DW_AT_stmt_list 偏移越界 offset=$stmtList")
            return null
        }
        val r = ByteReader(line, stmtList.toInt(), line.size)
        val hdr = parseHeader(r, warnings)
        val bounded = ByteReader(line, hdr.programStart, hdr.unitEnd)
        val seqs = runProgram(bounded, hdr, cuIndex, addressSize)
        return LineProgram(
            cuIndex = cuIndex, version = hdr.version, files = hdr.files,
            includeDirs = hdr.dirs, sequences = seqs,
            defaultIsStmt = hdr.defaultIsStmt,
            minimumInstructionLength = hdr.minInsnLen,
            maximumOperationsPerInstruction = hdr.maxOps,
        )
    }

    private fun parseHeader(r: ByteReader, warnings: MutableList<String>): LineHeader {
        val unitStart = r.pos
        val firstLength = r.u32()
        val offsetSize: Int
        val contentLength: Long
        if (firstLength == 0xffffffffL) { offsetSize = 8; contentLength = r.u64() }
        else { offsetSize = 4; contentLength = firstLength }
        val lengthFieldBytes = if (offsetSize == 8) 12 else 4
        val unitEnd = (unitStart + lengthFieldBytes + contentLength).toInt()
        if (unitEnd > r.sectionEnd) throw DwarfParseException(".debug_line 单元长度越界")

        val version = r.u16()
        if (version < 2 || version > 5) throw DwarfParseException("不支持的 line program 版本 $version")

        var minInsnLen = 1
        var maxOps = 1
        var defaultIsStmt = true
        var lineBase = -5
        var lineRange = 14
        var opcodeBase = 13
        var dirs: List<String> = emptyList()
        var files: List<FileEntry> = emptyList()
        var programStart = unitEnd

        if (version >= 5) {
            r.u8() // address_size
            r.u8() // segment_selector_size
            val headerLength = if (offsetSize == 8) r.u64() else r.u32()
            programStart = r.pos + headerLength.toInt()
            minInsnLen = r.u8()
            maxOps = r.u8().let { if (it == 0) 1 else it }
            defaultIsStmt = r.u8() != 0
            lineBase = r.s8()
            lineRange = r.u8()
            opcodeBase = r.u8()
            repeat(opcodeBase - 1) { r.u8() }
            val dirFormats = readEntryFormats(r)
            val fileFormats = readEntryFormats(r)
            val dirList = ArrayList<String>()
            readV5Entries(r, dirFormats) { path, dirIdx, ts, sz ->
                dirList += normalizeDir(path)
            }
            val fileList = ArrayList<FileEntry>()
            var syntheticIdx = 0
            readV5Entries(r, fileFormats) { path, dirIdx, _, _ ->
                fileList += FileEntry(path, dirIdx, joinPath(dirList.getOrNull(dirIdx) ?: "", path))
                syntheticIdx++
            }
            dirs = dirList
            files = fileList
        } else {
            // DWARF 2/3/4: minimum_instruction_length, then default_is_stmt;
            // there is NO maximum_operations_per_instruction field before DWARF 5.
            minInsnLen = r.u8()
            maxOps = 1
            defaultIsStmt = r.s8() != 0
            lineBase = r.s8()
            lineRange = r.u8()
            opcodeBase = r.u8()
            repeat(opcodeBase - 1) { r.u8() }
            // include directories
            val dirList = ArrayList<String>()
            while (true) {
                val s = r.cstring()
                if (s.isEmpty()) break
                dirList += normalizeDir(s)
            }
            // file names
            val fileList = ArrayList<FileEntry>()
            while (true) {
                val name = r.cstring()
                if (name.isEmpty()) break
                val dirIdx = r.uleb().toInt()
                r.uleb() // mtime
                r.uleb() // size
                fileList += FileEntry(name, dirIdx, joinPath(dirList.getOrNull(dirIdx - 1) ?: "", name))
            }
            dirs = dirList
            files = fileList
            programStart = r.pos
        }

        return LineHeader(version, defaultIsStmt, minInsnLen, maxOps, lineBase, lineRange,
            opcodeBase, files, dirs, programStart, unitEnd)
    }

    private fun readEntryFormats(r: ByteReader): List<EntryFormat> {
        val count = r.u8()
        val list = ArrayList<EntryFormat>(count)
        repeat(count) { list += EntryFormat(r.uleb().toInt(), r.uleb().toInt()) }
        return list
    }

    private fun readV5Entries(
        r: ByteReader, formats: List<EntryFormat>,
        sink: (path: String, dirIdx: Int, timestamp: Long, size: Long) -> Unit,
    ) {
        var guard = 0
        while (true) {
            if (++guard > MAX_ENTRIES) throw DwarfParseException("v5 路径表条目过多")
            if (r.u8() == 0) break
            r.pos -= 1
            var path = ""
            var dirIdx = 0
            var timestamp = 0L
            var size = 0L
            for (f in formats) {
                val fr = formReader(r, ArrayList())
                when (f.contentType) {
                    DW.LNCT.path -> path = readPath(f.form, fr)
                    DW.LNCT.directory_index -> dirIdx = readIndex(f.form, fr).toInt()
                    DW.LNCT.timestamp -> timestamp = readIndex(f.form, fr)
                    DW.LNCT.size -> size = readIndex(f.form, fr)
                    else -> consumeByForm(f.form, fr)
                }
            }
            sink(path, dirIdx, timestamp, size)
        }
    }

    private fun readPath(form: Int, fr: FormReader): String = when (form) {
        DW.FORM.string -> fr.r.cstring()
        DW.FORM.line_strp -> cstringAt(sections.lineStr ?: ByteArray(0), fr.readOffsetSized().toInt(), fr.warnings)
        DW.FORM.strp -> cstringAt(sections.str ?: ByteArray(0), fr.readOffsetSized().toInt(), fr.warnings)
        else -> if (FormIO.isStringForm(form)) fr.readStringForm(form) else throw UnknownFormException(form)
    }

    private fun readIndex(form: Int, fr: FormReader): Long = try {
        fr.readNumeric(form)
    } catch (e: UnknownFormException) {
        // A path encoded with a non-numeric form under index type is malformed; isolate.
        throw DwarfParseException("路径表索引使用了非数值 form 0x${form.toString(16)}")
    }

    private fun consumeByForm(form: Int, fr: FormReader) {
        if (FormIO.isStringForm(form)) readPath(form, fr) else fr.readNumeric(form)
    }

    private fun normalizeDir(d: String): String = if (d.isEmpty() || d.endsWith("/")) d else "$d/"
    private fun joinPath(dir: String, name: String): String {
        if (dir.isEmpty() || name.startsWith("/")) return name
        return normalizeDir(dir) + name
    }

    private fun snapshot(regs: LineRegs, endSequence: Boolean) = LineRow(
        regs.address, regs.file, regs.line, regs.column, regs.isStmt, endSequence,
        regs.basicBlock, regs.prologueEnd, regs.epilogueBegin, regs.isa, regs.discriminator,
    )

    private fun runProgram(r: ByteReader, hdr: LineHeader, cuIndex: Int, addressSize: Int): List<LineSequence> {
        val regs = LineRegs(hdr.defaultIsStmt)
        val rows = ArrayList<LineRow>()
        val seqs = ArrayList<LineSequence>()
        var seqIndex = 0
        val advUnit = hdr.minInsnLen.toLong() * hdr.maxOps
        var guard = 0
        while (r.remaining > 0) {
            if (++guard > MAX_OPCODES) throw DwarfParseException("line program opcode 过多")
            val opcode = r.u8()
            when {
                opcode == 0 -> {
                    // DWARF: length includes the extended opcode byte, so after
                    // consuming that byte the operands occupy len-1 bytes.
                    val len = r.uleb().toInt()
                    val instrStart = r.pos
                    val ext = r.u8()
                    val payloadEnd = instrStart + len
                    if (payloadEnd > r.sectionEnd) throw DwarfParseException("扩展 opcode 越界")
                    when (ext) {
                        DW.LNE.end_sequence -> {
                            val addr = r.addr(addressSize)
                            regs.address = addr
                            rows += snapshot(regs, true)
                            if (rows.isNotEmpty()) {
                                seqs += LineSequence(seqIndex, rows.toList(),
                                    rows.first().address, addr, cuIndex)
                                seqIndex++
                            }
                            rows.clear()
                            regs.reset(hdr.defaultIsStmt)
                            r.pos = payloadEnd
                        }
                        DW.LNE.set_address -> {
                            regs.address = r.addr(addressSize)
                            r.pos = payloadEnd
                        }
                        DW.LNE.set_discriminator -> {
                            regs.discriminator = r.uleb().toInt()
                            r.pos = payloadEnd
                        }
                        else -> r.pos = payloadEnd
                    }
                }
                opcode < hdr.opcodeBase -> when (opcode) {
                    DW.LNS.copy -> {
                        // append a row, then reset ONLY the transient registers;
                        // address/line/column/file/is_stmt/isa persist per spec.
                        rows += snapshot(regs, false)
                        regs.basicBlock = false
                        regs.prologueEnd = false
                        regs.epilogueBegin = false
                        regs.discriminator = 0
                    }
                    DW.LNS.advance_pc -> regs.address += r.uleb() * advUnit
                    DW.LNS.line -> regs.line += r.sleb().toInt()
                    DW.LNS.file -> regs.file = r.uleb().toInt()
                    DW.LNS.set_column -> regs.column = r.uleb().toInt()
                    DW.LNS.negate_stmt -> regs.isStmt = !regs.isStmt
                    DW.LNS.set_basic_block -> regs.basicBlock = true
                    DW.LNS.const_add_pc -> {
                        val adj = (256 - hdr.opcodeBase) / hdr.lineRange
                        regs.address += adj.toLong() * advUnit
                    }
                    DW.LNS.fixed_add_pc -> regs.address += advUnit
                    DW.LNS.set_prologue_end -> regs.prologueEnd = true
                    DW.LNS.set_epilogue_begin -> regs.epilogueBegin = true
                    DW.LNS.set_isa -> regs.isa = r.uleb().toInt()
                    else -> throw DwarfParseException("未知标准 opcode $opcode")
                }
                else -> {
                    val adjusted = opcode - hdr.opcodeBase
                    val opAdvance = Math.floorDiv(adjusted, hdr.lineRange)
                    regs.address += opAdvance.toLong() * advUnit
                    // floor-modulo so negative adjusted values still wrap correctly
                    val lineMod = Math.floorMod(adjusted, hdr.lineRange)
                    regs.line += lineMod + hdr.lineBase
                    rows += snapshot(regs, false)
                    regs.basicBlock = false; regs.prologueEnd = false
                    regs.epilogueBegin = false; regs.discriminator = 0
                }
            }
        }
        if (rows.isNotEmpty()) {
            // Unterminated sequence (truncated data). Best-effort: use last row.
            seqs += LineSequence(seqIndex, rows.toList(), rows.first().address,
                rows.last().address + 1, cuIndex)
        }
        return seqs
    }

    companion object {
        const val MAX_OPCODES = 1 shl 24
        const val MAX_ENTRIES = 1 shl 20
    }
}
