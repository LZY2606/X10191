package compass.dwarf

import compass.elf.Reader
import compass.model.Endian
import compass.model.LineRow

data class LineFile(val name: String?, val dirIndex: Int, val fullPath: String?)

data class ParsedSequence(
    val startAddress: Long,
    val endAddress: Long,
    val selector: Long,
    val rows: List<LineRow>,
)

class LineProgramResult(val version: Int, val files: List<LineFile>, val sequences: List<ParsedSequence>)

/** Parses and executes the line program at `offset` in .debug_line(.dwo). */
object LineProgram {

    fun parse(
        sections: DebugSections,
        sectionName: String,
        offset: Long,
        endian: Endian,
        addrSize: Int,
        cuName: String?,
        cuCompDir: String?,
    ): LineProgramResult? {
        val data = sections[sectionName] ?: return null
        if (data.isEmpty() || offset < 0 || offset >= data.size) return null
        val r = Reader(data, endian)
        r.seek(offset.toInt())
        val unit = r.initialLength()
        val dwarf64 = unit.dwarf64
        val version = when (val v = r.u16()) {
            in 2..5 -> v
            else -> throw BadLineProgram("unsupported line program version $v")
        }
        var addressSize = addrSize
        var segmentSize = 0
        if (version >= 5) {
            addressSize = r.u8()
            segmentSize = r.u8()
        }
        val headerLength = if (dwarf64) r.u64() else r.u32()
        val headerEnd = r.pos.toLong() + headerLength
        if (headerEnd > unit.end) throw BadLineProgram("line header exceeds unit")

        val minInsLen = r.u8()
        val maxOpsPerIns: Int = if (version >= 4) r.u8() else 1
        val defaultIsStmt = r.u8()
        val lineBase = r.i8()
        val lineRange = r.u8()
        if (lineRange == 0) throw BadLineProgram("line_range == 0")
        val opcodeBase = r.u8()
        val stdOpcodeLengths = IntArray(opcodeBase.coerceAtLeast(16))
        for (i in 1 until opcodeBase) stdOpcodeLengths[i] = r.u8()

        val includeDirs = ArrayList<String>()
        val files = ArrayList<LineFile>()

        if (version < 5) {
            while (true) {
                val d = readNulString(r); if (d.isEmpty()) break
                includeDirs.add(d)
            }
            while (true) {
                val name = readNulString(r); if (name.isEmpty()) break
                val dirIdx = r.uleb128().toInt()
                r.uleb128(); r.uleb128() // timestamp, size
                val dir = if (dirIdx == 0) cuCompDir else includeDirs.getOrNull(dirIdx - 1)
                files.add(LineFile(name, dirIdx, joinPath(dir, name)))
            }
            if (cuName != null) files.add(0, LineFile(cuName, 0, joinPath(cuCompDir, cuName)))
        } else {
            data class PathForm(val code: Int, val form: Int)
            val dirForms = ArrayList<PathForm>()
            repeat(r.u8()) { dirForms.add(PathForm(r.uleb128().toInt(), r.uleb128().toInt())) }
            repeat(r.uleb128().toInt()) {
                var path: String? = null
                for (pf in dirForms) {
                    val v = readLineForm(r, sections, endian, dwarf64)
                    if (pf.code == DW.LN_path_path && v is FormValue.Text) path = v.v
                }
                includeDirs.add(path ?: "")
            }
            val fileForms = ArrayList<PathForm>()
            repeat(r.u8()) { fileForms.add(PathForm(r.uleb128().toInt(), r.uleb128().toInt())) }
            repeat(r.uleb128().toInt()) {
                var name: String? = null
                var dirIdx = 0
                for (pf in fileForms) {
                    val v = readLineForm(r, sections, endian, dwarf64)
                    when (pf.code) {
                        DW.LN_path_path -> if (v is FormValue.Text) name = v.v
                        DW.LN_directory_index -> if (v is FormValue.Constant) dirIdx = v.v.toInt()
                    }
                }
                files.add(LineFile(name, dirIdx, joinPath(includeDirs.getOrNull(dirIdx), name)))
            }
        }
        if (r.pos.toLong() != headerEnd) r.seek(headerEnd.toInt())

        val sequences = ArrayList<ParsedSequence>()
        var rows = ArrayList<LineRow>()
        var address = 0L
        var selector = 0L
        var fileIndex = 0
        var line = 1
        var column = 0
        var isStmt = defaultIsStmt != 0
        var endSeq = false
        var isa = 0
        var discriminator = 0
        var opIndex = 0

        fun reset() {
            address = 0; fileIndex = 1; line = 1; column = 0
            isStmt = defaultIsStmt != 0; endSeq = false; isa = 0
            discriminator = 0; opIndex = 0
        }
        fun emit() {
            val file = files.getOrNull(fileIndex)
            rows.add(LineRow(address, fileIndex, file?.fullPath ?: file?.name, line, column,
                endSeq, isa, discriminator, opIndex))
            discriminator = 0
        }

        var guard = 0
        while (r.pos < unit.end) {
            if (guard++ > 5_000_000) throw BadLineProgram("line program op guard")
            val opcode = r.u8()
            when {
                opcode == 0 -> {
                    val len = r.uleb128().toInt()
                    val opEnd = r.pos + len
                    if (opEnd > unit.end) throw BadLineProgram("extended op exceeds unit")
                    val ext = r.u8()
                    when (ext) {
                        DW.LNE_end_sequence -> {
                            endSeq = true
                            emit()
                            val start = rows.firstOrNull()?.address ?: 0L
                            sequences.add(ParsedSequence(start, address, selector, rows))
                            rows = ArrayList()
                            reset(); selector = 0L
                        }
                        DW.LNE_set_address -> {
                            if (segmentSize > 0) selector = Forms.readAddr(r, segmentSize.coerceAtMost(8))
                            address = Forms.readAddr(r, addressSize)
                        }
                        DW.LNE_set_discriminator -> discriminator = r.uleb128().toInt()
                        DW.LNE_define_file -> {
                            val name = readNulString(r)
                            val dirIdx = r.uleb128().toInt()
                            r.uleb128(); r.uleb128()
                            val dir = if (dirIdx == 0) cuCompDir else includeDirs.getOrNull(dirIdx - 1)
                            files.add(LineFile(name, dirIdx, joinPath(dir, name)))
                        }
                        else -> { /* unknown extended op: length keeps the cursor aligned */ }
                    }
                    r.seek(opEnd)
                }
                opcode < opcodeBase -> {
                    val operands = stdOpcodeLengths.getOrNull(opcode) ?: 0
                    when (opcode) {
                        DW.LINE_copy -> emit()
                        DW.LINE_advance_pc -> {
                            address += minInsLen * (opIndex + r.uleb128().toLong())
                            opIndex = 0
                        }
                        DW.LINE_advance_line -> line += r.sleb128().toInt()
                        DW.LINE_set_file -> fileIndex = r.uleb128().toInt()
                        DW.LINE_set_column -> column = r.uleb128().toInt()
                        DW.LINE_negate_stmt -> isStmt = !isStmt
                        DW.LINE_set_basic_block -> r.uleb128() // has no operands normally; no-op state
                        DW.LINE_const_add_pc -> {
                            address += minInsLen * (opIndex + (255 - opcodeBase) / lineRange)
                            opIndex = 0
                        }
                        DW.LINE_fixed_advance_pc -> { address += r.u16().toLong() and 0xffff; opIndex = 0 }
                        DW.LINE_set_prologue_end -> { /* boolean marker, no state kept beyond rows */ }
                        DW.LINE_set_epilogue_begin -> {}
                        DW.LINE_set_isa -> isa = r.uleb128().toInt()
                        DW.LINE_set_file_entry -> fileIndex = r.uleb128().toInt()
                        DW.LINE_set_address -> {
                            if (segmentSize > 0) selector = Forms.readAddr(r, segmentSize.coerceAtMost(8))
                            address = Forms.readAddr(r, addressSize)
                        }
                        else -> repeat(operands) { r.uleb128() }
                    }
                }
                else -> {
                    val adj = opcode - opcodeBase
                    val opAdvance = adj / lineRange
                    val lineAdv = lineBase + adj % lineRange
                    if (maxOpsPerIns > 0) {
                        address += minInsLen * ((opIndex + opAdvance) / maxOpsPerIns)
                        opIndex = (opIndex + opAdvance) % maxOpsPerIns
                    } else {
                        address += minInsLen * opAdvance.toLong()
                    }
                    line += lineAdv
                    emit()
                }
            }
        }
        // A program without end_sequence is malformed; discard its dangling rows
        // rather than fabricate a sequence boundary.
        return LineProgramResult(version, files, sequences)
    }

    private fun readNulString(r: Reader): String {
        val start = r.pos
        while (true) {
            if (r.remaining() == 0) throw BadLineProgram("unterminated string")
            if (r.u8() == 0) break
        }
        return String(r.data, start, r.pos - 1 - start, Charsets.UTF_8)
    }

    private fun readLineForm(r: Reader, sections: DebugSections, endian: Endian, dwarf64: Boolean): FormValue {
        val form = r.uleb128().toInt()
        return when (form) {
            DW.FORM_string -> {
                val start = r.pos
                while (r.u8() != 0) {}
                FormValue.Text(String(r.data, start, r.pos - 1 - start, Charsets.UTF_8))
            }
            DW.FORM_line_strp -> {
                val off = if (dwarf64) r.u64() else r.u32()
                val sec = sections.require(".debug_line_str")
                FormValue.Text(if (sec.isEmpty() || off >= sec.size) "" else Reader(sec, endian).cStringAt(off.toInt()))
            }
            DW.FORM_strp -> {
                val off = if (dwarf64) r.u64() else r.u32()
                val sec = sections.require(".debug_str")
                FormValue.Text(if (sec.isEmpty() || off >= sec.size) "" else Reader(sec, endian).cStringAt(off.toInt()))
            }
            DW.FORM_data1 -> FormValue.Constant(r.u8().toLong())
            DW.FORM_data2 -> FormValue.Constant(r.u16().toLong() and 0xffff)
            DW.FORM_data4 -> FormValue.Constant(r.u32())
            DW.FORM_data8 -> FormValue.Constant(r.u64())
            DW.FORM_udata -> FormValue.Constant(r.uleb128())
            DW.FORM_flag -> FormValue.Flag(r.u8() != 0)
            DW.FORM_flag_present -> FormValue.Flag(true)
            else -> throw UnknownFormException(form)
        }
    }

    private fun joinPath(dir: String?, name: String?): String? {
        if (name == null) return null
        if (dir.isNullOrEmpty() || name.startsWith('/')) return name
        return if (dir.endsWith('/')) "$dir$name" else "$dir/$name"
    }
}

class BadLineProgram(message: String) : RuntimeException(message)
