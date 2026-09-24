package luopan.dwarf

import luopan.model.LineFile
import luopan.model.LineSequence
import luopan.model.LineStep

/**
 * 解析一个 CU 的 .debug_line / .debug_line.dwo 程序。
 * - DWARF4: include_directories + file_names 两种旧表
 * - DWARF5: directory_entry_format / file_name_entry_format（支持 path & string 内容类型）
 * - special opcode: opcode_base + adjusted
 * 每个产生输出行的步骤（含 end_sequence）都记录为 [LineStep]。
 */
class LineProgramParser(
    private val sections: DebugSections,
    private val unitOffset: Long,
    private val cuName: String?
) {
    data class FileEntry(val name: String, val dir: String, val lineStr: Boolean)

    fun parse(offset: Long, isDwo: Boolean = false): Result {
        val sectionName = if (isDwo) ".debug_line.dwo" else ".debug_line"
        val data = sections.bytes(sectionName)
            ?: return Result(null, "section $sectionName missing")
        val r = ByteReader.of(data, sections.littleEndian)
        try {
            r.seek(offset.toInt())
            val (unitLength, contentStart, dwarf64) = r.initialLength()
            val version = r.u16().also { if (it !in 2..5) throw DwarfFormatException("unsupported line version $it") }
            val addressSize: Int
            val segSelectorSize: Int
            val minInstrLen: Int
            val maxOpsPerInstr: Int
            val defaultIsStmt: Boolean
            val lineBase: Int
            val lineRange: Int
            val opcodeBase: Int
            if (version >= 5) {
                addressSize = r.u8()
                segSelectorSize = r.u8()
                r.readFixed(if (dwarf64) 8 else 4) // header_length
                minInstrLen = r.u8()
                maxOpsPerInstr = r.u8()
                defaultIsStmt = r.u8() != 0
                lineBase = r.u8().toByte().toInt()
                lineRange = r.u8()
                opcodeBase = r.u8()
                repeat(opcodeBase - 1) { r.u8() }
            } else {
                r.readFixed(if (dwarf64) 8 else 4) // header_length
                minInstrLen = r.u8()
                maxOpsPerInstr = r.u8()
                defaultIsStmt = r.u8() != 0
                lineBase = r.u8().toByte().toInt()
                lineRange = r.u8()
                opcodeBase = r.u8()
                repeat(opcodeBase - 1) { r.u8() }
                addressSize = 0
                segSelectorSize = 0
            }
            val dirs = ArrayList<String>()
            val files = ArrayList<FileEntry>()
            if (version >= 5) parseV5Tables(r, dirs, files, dwarf64)
            else parseV4Tables(r, dirs, files)

            val sequences = runProgram(
                r, contentStart, unitLength, version, addressSize,
                segSelectorSize, minInstrLen, maxOpsPerInstr, defaultIsStmt,
                lineBase, lineRange, opcodeBase, dirs, files
            )
            return Result(LineProgram(version, files, dirs, sequences), null)
        } catch (e: DwarfBoundsException) {
            return Result(null, "line program truncated at offset $offset: ${e.message}")
        } catch (e: DwarfFormatException) {
            return Result(null, "line program error at offset $offset: ${e.message}")
        }
    }

    private fun parseV4Tables(
        r: ByteReader, dirs: ArrayList<String>, files: ArrayList<FileEntry>
    ) {
        dirs += "" // dir index 0 = comp_dir
        while (true) {
            val s = r.nullTerminatedString()
            if (s.isEmpty()) break
            dirs += s
        }
        while (true) {
            val name = r.nullTerminatedString()
            if (name.isEmpty()) break
            val dirIdx = r.uleb128().first
            r.uleb128() // mtime
            r.uleb128() // size
            val dir = dirs.getOrNull(dirIdx.toInt()) ?: ""
            files += FileEntry(name, dir, false)
        }
    }

    private fun parseEntryFormat(
        r: ByteReader, dwarf64: Boolean
    ): List<Pair<Int, Int>> {
        val count = r.u8()
        return (0 until count).map {
            val contentType = r.uleb128().first.toInt()
            val form = r.uleb128().first.toInt()
            contentType to form
        }
    }

    private fun parsePath(
        r: ByteReader, form: Int, dwarf64: Boolean, lineStrings: Boolean
    ): String? {
        val fr = FormReader(r, 4, dwarf64, null)
        val v = fr.read(form)
        return when (v) {
            is FormValue.InString -> v.v
            is FormValue.StrRef -> sections.resolve(v)
            else -> null
        }
    }

    private fun skipForm(r: ByteReader, form: Int, dwarf64: Boolean) {
        FormReader(r, 4, dwarf64, null).read(form)
    }

    private fun parseV5Tables(
        r: ByteReader, dirs: ArrayList<String>, files: ArrayList<FileEntry>, dwarf64: Boolean
    ) {
        val dirFormat = parseEntryFormat(r, dwarf64)
        val dirsCount = r.uleb128().first
        dirs += "" // index 0 = comp_dir
        repeat(dirsCount.toInt()) {
            var dir = ""
            for ((ct, form) in dirFormat) {
                if (ct == 1 /* DW_LNCT_path */) dir = parsePath(r, form, dwarf64, true) ?: ""
                else skipForm(r, form, dwarf64)
            }
            dirs += dir
        }
        val fileFormat = parseEntryFormat(r, dwarf64)
        val filesCount = r.uleb128().first
        repeat(filesCount.toInt()) {
            var name = ""
            var dirIdx = 0
            for ((ct, form) in fileFormat) {
                when (ct) {
                    1 /* path */ -> {
                        val fr = FormReader(r, 4, dwarf64, null)
                        val v = fr.read(form)
                        name = sections.resolve(v) ?: (v as? FormValue.InString)?.v ?: ""
                    }
                    2 /* directory index */ -> {
                        dirIdx = FormReader(r, 4, dwarf64, null).read(form).let {
                            (it as? FormValue.Num)?.v?.toInt() ?: 0
                        }
                    }
                    else -> skipForm(r, form, dwarf64)
                }
            }
            files += FileEntry(name, dirs.getOrNull(dirIdx) ?: "", true)
        }
    }

    @Suppress("UNUSED_PARAMETER")
    private fun runProgram(
        r: ByteReader, contentStart: Int, unitLength: Long, version: Int,
        addressSizeHeader: Int, segSelSize: Int,
        minInstrLenH: Int, maxOpsPerInstrH: Int, defaultIsStmtH: Boolean,
        lineBaseH: Int, lineRangeH: Int, opcodeBaseH: Int,
        dirs: List<String>, files: List<FileEntry>
    ): List<LineSequence> {
        // CU 级地址尺寸从 v5 header 拿到；v2-v4 用调用方默认（由 info 解析时回填 8/4）
        val addressSize = if (addressSizeHeader != 0) addressSizeHeader else this.addressSizeFallback
        val state = LineState(
            version, addressSize, minInstrLenH, maxOpsPerInstrH, defaultIsStmtH,
            lineBaseH, lineRangeH, opcodeBaseH
        )
        val sequences = ArrayList<LineSequence>()
        var seqStart = 0L
        val programEnd = contentStart + unitLength
        var steps = ArrayList<LineStep>()
        var guard = 0
        val maxOps = MAX_LINE_OPS

        fun fileName(idx: Int): String {
            if (idx <= 0 || idx > files.size) return "<unknown:$idx>"
            val f = files[idx - 1]
            return if (f.dir.isEmpty()) f.name else "${f.dir}/${f.name}"
        }
        fun flush(end: Boolean) {
            val step = LineStep(
                state.address,
                fileName(state.file),
                state.line, state.column,
                end, state.isa, state.discriminator,
                state.lastOpcode
            )
            steps += step
        }

        while (r.pos < programEnd) {
            if (++guard > maxOps) throw DwarfFormatException("line program too many operations")
            val opcode = r.u8()
            if (opcode == 0) {
                val (len0, _) = r.uleb128()
                val len = len0.toInt()
                if (len < 1) throw DwarfFormatException("bad extended opcode length")
                val subEnd = r.pos + len
                val sub = r.u8()
                try {
                    when (sub) {
                    DwLne.END_SEQUENCE -> {
                        if (segSelSize > 0) r.readFixed(segSelSize)
                        state.address = r.readFixed(addressSize)
                        state.lastOpcode = "DW_LNE_end_sequence"
                        flush(true)
                        sequences += LineSequence(
                            seqStart, state.address, 0L,
                            steps.toList(), version, cuName
                        )
                        steps = ArrayList()
                        state.resetDefault()
                    }
                    DwLne.SET_ADDRESS -> {
                        if (segSelSize > 0) r.seek(r.pos + segSelSize)
                        state.address = r.readFixed(addressSize)
                        seqStart = state.address
                        state.lastOpcode = "DW_LNE_set_address"
                    }
                    DwLne.SET_FILE -> {
                        state.file = r.uleb128().first.toInt().coerceAtLeast(0)
                        state.lastOpcode = "DW_LNE_set_file"
                    }
                    DwLne.SET_DISCRIMINATOR -> {
                        state.discriminator = r.uleb128().first.toInt()
                        state.lastOpcode = "DW_LNE_set_discriminator"
                    }
                    else -> {
                        // 未知扩展 opcode：按长度整体跳过，游标不允许错位
                        state.lastOpcode = "DW_LNE_unknown(0x${sub.toString(16)})"
                    }
                    }
                } finally {
                    // 无论识别与否，游标必须精确落在本扩展操作末尾
                    if (r.pos != subEnd) r.seek(subEnd)
                }
            } else if (opcode < state.opcodeBase) {
                when (opcode) {
                    DwLns.COPY -> { state.lastOpcode = "DW_LNS_copy"; flush(false) }
                    DwLns.ADVANCE_PC -> {
                        val adv = r.uleb128().first
                        state.address += state.minInstrLen.toLong() *
                            ((state.opIndex + adv.toInt()) / state.maxOpsPerInstr)
                        state.opIndex = (state.opIndex + adv.toInt()) % state.maxOpsPerInstr
                        state.lastOpcode = "DW_LNS_advance_pc"
                    }
                    DwLns.LINE -> { state.line += r.sleb128().first.toInt(); state.lastOpcode = "DW_LNS_advance_line" }
                    DwLns.FILE -> { state.file = r.uleb128().first.toInt(); state.lastOpcode = "DW_LNS_set_file" }
                    DwLns.SET_COLUMN -> { state.column = r.uleb128().first.toInt(); state.lastOpcode = "DW_LNS_set_column" }
                    DwLns.NEGATE_STMT -> { state.isStmt = !state.isStmt; state.lastOpcode = "DW_LNS_negate_stmt" }
                    DwLns.SET_BASIC_BLOCK -> { state.basicBlock = true; state.lastOpcode = "DW_LNS_set_basic_block" }
                    DwLns.CONST_ADD_PC -> {
                        val adjusted = 255 - state.opcodeBase + 1
                        state.address += state.minInstrLen.toLong() *
                            (((state.opIndex + adjusted / state.lineRange) / state.maxOpsPerInstr))
                        state.opIndex = 0
                        state.lastOpcode = "DW_LNS_const_add_pc"
                    }
                    DwLns.FIXED_ADVANCE_PC -> {
                        state.address += r.u16().toLong()
                        state.opIndex = 0
                        state.lastOpcode = "DW_LNS_fixed_advance_pc"
                    }
                    DwLns.SET_PROLOGUE_END -> state.lastOpcode = "DW_LNS_set_prologue_end"
                    DwLns.SET_ISA -> { state.isa = r.uleb128().first.toInt(); state.lastOpcode = "DW_LNS_set_isa" }
                    DwLns.MAX_STEPS_OP -> { // DW_LNS_max_steps_to_remove (v6) 不应出现
                        throw DwarfFormatException("unexpected DW_LNS_max_steps_op in DWARF$version")
                    }
                    else -> throw DwarfFormatException("unknown standard opcode $opcode")
                }
            } else {
                val adjusted = opcode - state.opcodeBase
                val addrAdv = adjusted / state.lineRange
                val lineAdv = state.lineBase + (adjusted % state.lineRange)
                state.address += state.minInstrLen.toLong() *
                    ((state.opIndex + addrAdv) / state.maxOpsPerInstr)
                state.opIndex = (state.opIndex + addrAdv) % state.maxOpsPerInstr
                state.line += lineAdv
                state.lastOpcode = "special($opcode)"
                flush(false)
                state.basicBlock = false
                state.discriminator = 0
                state.prologueEnd = false
            }
        }
        return sequences
    }

    var addressSizeFallback: Int = 8

    companion object {
        const val MAX_LINE_OPS = 50_000_000
    }
}

data class LineProgram(
    val version: Int,
    val files: List<LineProgramParser.FileEntry>,
    val dirs: List<String>,
    val sequences: List<LineSequence>
)

data class Result(val program: LineProgram?, val error: String?)

private class LineState(
    val version: Int, val addressSize: Int,
    val minInstrLen: Int, val maxOpsPerInstr: Int, defaultIsStmt: Boolean,
    val lineBase: Int, val lineRange: Int, val opcodeBase: Int
) {
    var address = 0L
    var opIndex = 0
    var file = 1
    var line = 1
    var column = 0
    var isStmt = defaultIsStmt
    var basicBlock = false
    var endSequence = false
    var prologueEnd = false
    var isa = 0
    var discriminator = 0
    var lastOpcode = ""

    fun resetDefault() {
        address = 0L; opIndex = 0; file = 1; line = 1; column = 0; isStmt = true
        basicBlock = false; endSequence = false; prologueEnd = false
        isa = 0; discriminator = 0; lastOpcode = ""
    }
}
