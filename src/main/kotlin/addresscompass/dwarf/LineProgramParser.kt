package addresscompass.dwarf

import addresscompass.model.Addr
import addresscompass.model.LineFile
import addresscompass.model.LineProgram
import addresscompass.model.LineRow
import addresscompass.model.LineSequence
import addresscompass.model.LineStep
import addresscompass.model.FormValue
import addresscompass.model.ParseIssue
import addresscompass.model.Severity
import java.nio.ByteOrder

data class LineContext(
    val line: ByteArray?,
    val lineStr: ByteArray?,
    val str: ByteArray?,
    val endian: ByteOrder,
)

object LineProgramParser {

    /** Returns null when the header itself is unreadable; the caller records an isolated issue. */
    fun parseAt(ctx: LineContext, cuOffset: Long, offset: Long, declaredVersion: Int): LineProgram? {
        val section = ctx.line ?: return null
        if (offset < 0 || offset >= section.size) return null
        val issues = mutableListOf<ParseIssue>()
        val r = ByteReader(section, endian = ctx.endian)
        return try {
            r.seek(offset.toInt())
            parseBody(ctx, r, cuOffset, offset, issues)
        } catch (e: SectionTruncatedException) {
            issues += ParseIssue(Severity.ERROR, ".debug_line", offset, e.message ?: "truncated", true)
            null
        } catch (e: OutOfBoundsReferenceException) {
            issues += ParseIssue(Severity.ERROR, ".debug_line", offset, e.message ?: "bad reference", true)
            null
        }
    }

    private fun parseBody(ctx: LineContext, r: ByteReader, cuOffset: Long, sectionOffset: Long, issues: MutableList<ParseIssue>): LineProgram {
        val unitStart = r.pos
        val lengthWord = r.u32()
        val dwarf64: Boolean
        val bodyLen: Long
        if (lengthWord == 0xffffffffL) {
            dwarf64 = true
            bodyLen = r.u64()
        } else {
            dwarf64 = false
            bodyLen = lengthWord
        }
        val headerLenFieldEnd = r.pos
        val unitEnd = headerLenFieldEnd + bodyLen
        if (unitEnd > sectionSize(r)) throw SectionTruncatedException("line unit extends past section")
        val b = r.sliceReader(r.pos, bodyLen.toInt())

        val version = b.u16()
        var addressSize = 8
        if (version >= 5) {
            addressSize = b.u8()
            b.u8() // segment_selector_size (we track selector only via set_address encoding)
        }
        val headerLength = b.u32()
        val headerEnd = b.pos + headerLength.toInt()
        val minInsnLen = b.u8()
        val maxOps = if (version >= 5) b.u8().coerceAtLeast(1) else 1
        val defaultIsStmt = b.u8() != 0
        val lineBase = b.i8()
        val lineRange = b.u8().coerceAtLeast(1)
        val opcodeBase = b.u8().coerceAtLeast(1)
        val stdLen = IntArray(opcodeBase)
        for (i in 1 until opcodeBase) stdLen[i] = b.u8()

        val dirs = mutableListOf<String>()
        val files = mutableListOf<LineFile>()
        if (version >= 5) {
            parseV5DirList(b, ctx) { dirs += it }
            parseV5FileList(b, ctx) { path, dir -> files += LineFile(path, dir, null) }
        } else {
            while (true) {
                val s = b.readNULString(1 shl 20)
                if (s.isEmpty()) break
                dirs += s
            }
            while (true) {
                val name = b.readNULString(1 shl 20)
                if (name.isEmpty()) break
                val dirIndex = b.uleb().toInt()
                b.uleb(); b.uleb()
                files += LineFile(name, dirIndex, null)
            }
        }

        b.seek(headerEnd)

        val steps = mutableListOf<LineStep>()
        val sequences = mutableListOf<LineSequence>()
        var rows = mutableListOf<LineRow>()

        var address = 0L; var selector = 0
        var file = 1; var line = 1; var column = 0; var opIndex = 0
        var isa = 0; var discriminator = 0; var isStmt = defaultIsStmt
        var prologueEnd = false
        var ord = 0

        fun step(opName: String, emitted: Boolean, end: Boolean) {
            steps += LineStep(ord, opName, Addr(selector, address), file, line, column, opIndex, isStmt, prologueEnd, emitted, end)
        }

        fun emit(end: Boolean) {
            rows += LineRow(Addr(selector, address), file.coerceAtLeast(1), line, column, opIndex, isa, discriminator, prologueEnd, end)
        }

        fun reset() {
            address = 0L; selector = 0; file = 1; line = 1; column = 0; opIndex = 0
            isa = 0; discriminator = 0; isStmt = defaultIsStmt; prologueEnd = false
        }

        fun advance(operandAdvance: Int) {
            if (maxOps <= 1) {
                address += minInsnLen.toLong() * operandAdvance
            } else {
                val total = opIndex + operandAdvance
                address += minInsnLen.toLong() * (total / maxOps)
                opIndex = total % maxOps
            }
        }

        while (b.remaining > 0) {
            val opcode = b.u8()
            ord++
            when {
                opcode == 0 -> {
                    val extLen = b.uleb().toInt()
                    val sub = b.sliceReader(b.pos, extLen)
                    b.seek(b.pos + extLen)
                    when (sub.u8()) {
                        LineConstants.DW_LNE_end_sequence -> {
                            step("end_sequence", false, true)
                            emit(true)
                            sequences += LineSequence(sequences.size, sectionOffset, rows, Addr(selector, address))
                            rows = mutableListOf()
                            reset()
                        }
                        LineConstants.DW_LNE_set_address -> {
                            address = sub.sizedInt(addressSize)
                            opIndex = 0
                            step("set_address", false, false)
                        }
                        LineConstants.DW_LNE_define_file -> {
                            val nm = sub.readNULString(1 shl 20)
                            val di = sub.uleb().toInt(); sub.uleb(); sub.uleb()
                            files += LineFile(nm, di, null)
                            step("define_file", false, false)
                        }
                        LineConstants.DW_LNE_set_discriminator -> {
                            discriminator = sub.uleb().toInt()
                            step("set_discriminator", false, false)
                        }
                        else -> step("extended_${sub.u8()}", false, false)
                    }
                }
                opcode < opcodeBase -> when (opcode) {
                    LineConstants.DW_LNS_copy -> {
                        step("copy", true, false); emit(false)
                        prologueEnd = false; discriminator = 0
                    }
                    LineConstants.DW_LNS_advance_pc -> { advance(b.uleb().toInt()); step("advance_pc", false, false) }
                    LineConstants.DW_LNS_advance_line -> { line += b.sleb().toInt(); step("advance_line", false, false) }
                    LineConstants.DW_LNS_set_file -> { file = b.uleb().toInt(); step("set_file", false, false) }
                    LineConstants.DW_LNS_set_column -> { column = b.uleb().toInt(); step("set_column", false, false) }
                    LineConstants.DW_LNS_negate_stmt -> { isStmt = !isStmt; step("negate_stmt", false, false) }
                    LineConstants.DW_LNS_set_basic_block -> { step("set_basic_block", false, false) }
                    LineConstants.DW_LNS_const_add_pc -> {
                        advance((255 - opcodeBase) / lineRange); step("const_add_pc", false, false)
                    }
                    LineConstants.DW_LNS_fixed_advance_pc -> {
                        address += b.u16().toLong(); opIndex = 0; step("fixed_advance_pc", false, false)
                    }
                    LineConstants.DW_LNS_set_prologue_end -> { prologueEnd = true; step("set_prologue_end", false, false) }
                    LineConstants.DW_LNS_set_isa -> { isa = b.uleb().toInt(); step("set_isa", false, false) }
                    else -> {
                        repeat(stdLen.getOrElse(opcode) { 0 }) { b.uleb() }
                        step("standard_$opcode", false, false)
                    }
                }
                else -> {
                    val adjusted = opcode - opcodeBase
                    advance(adjusted / lineRange)
                    line += lineBase + adjusted % lineRange
                    step("special_$opcode", true, false)
                    emit(false)
                    prologueEnd = false; discriminator = 0
                }
            }
        }

        if (rows.isNotEmpty()) {
            issues += ParseIssue(Severity.WARNING, ".debug_line", sectionOffset, "missing end_sequence; rows may run past image")
            sequences += LineSequence(sequences.size, sectionOffset, rows, Addr(selector, address))
        }

        return LineProgram(
            cuOffset = cuOffset, sectionOffset = sectionOffset, version = version, addressSize = addressSize,
            minInstructionLength = minInsnLen, maxOpsPerInstruction = maxOps, defaultIsStmt = defaultIsStmt,
            lineBase = lineBase, lineRange = lineRange, opcodeBase = opcodeBase,
            compDir = null, dirs = dirs, files = files, sequences = sequences, steps = steps, issues = issues,
        )
    }

    private fun sectionSize(r: ByteReader): Int = r.remaining + r.pos

    // ---- DWARF 5 entry lists ----

    private fun readFormats(b: ByteReader): List<Pair<Int, Int>> {
        val n = b.u8()
        return List(n) { b.uleb().toInt() to b.uleb().toInt() }
    }

    private fun parseV5DirList(b: ByteReader, ctx: LineContext, sink: (String) -> Unit) {
        val formats = readFormats(b)
        val count = b.u8().toLong()
        repeat(count.toInt()) {
            var path: String? = null
            for ((ct, form) in formats) {
                if (ct == LineConstants.DW_LNCT_path) path = readPath(b, form, ctx)
                else skipLineForm(b, form, ctx)
            }
            sink(path ?: "")
        }
    }

    private fun parseV5FileList(b: ByteReader, ctx: LineContext, sink: (String, Int) -> Unit) {
        val formats = readFormats(b)
        val count = b.u8().toLong()
        repeat(count.toInt()) {
            var path: String? = null
            var dir = 0
            for ((ct, form) in formats) {
                when (ct) {
                    LineConstants.DW_LNCT_path -> path = readPath(b, form, ctx)
                    LineConstants.DW_LNCT_directory_index -> dir = readUdata(b, form).toInt()
                    else -> skipLineForm(b, form, ctx)
                }
            }
            sink(path ?: "<unknown>", dir)
        }
    }

    private fun readUdata(b: ByteReader, form: Int): Long {
        val v = FormReader.read(b, form, FormLayout(5, false, 8, false))
        return (v as? FormValue.Udata)?.v ?: 0L
    }

    private fun readPath(b: ByteReader, form0: Int, ctx: LineContext): String {
        var form = form0
        if (form == Dwarf.DW_FORM_indirect) form = b.uleb().toInt()
        return when (form) {
            Dwarf.DW_FORM_string -> b.readNULString(1 shl 20)
            Dwarf.DW_FORM_line_strp -> cString(ctx.lineStr, b.sizedInt(4).toInt())
            Dwarf.DW_FORM_strp -> cString(ctx.str, b.sizedInt(4).toInt())
            else -> {
                val v = FormReader.read(b, form, FormLayout(5, false, 8, false))
                (v as? FormValue.Str)?.s ?: "<path?>"
            }
        }
    }

    private fun skipLineForm(b: ByteReader, form0: Int, ctx: LineContext) {
        var form = form0
        if (form == Dwarf.DW_FORM_indirect) form = b.uleb().toInt()
        when (form) {
            Dwarf.DW_FORM_string -> b.readNULString(1 shl 20)
            Dwarf.DW_FORM_line_strp, Dwarf.DW_FORM_strp -> b.sizedInt(4)
            else -> FormReader.read(b, form, FormLayout(5, false, 8, false))
        }
    }

    private fun cString(section: ByteArray?, off: Int): String {
        if (section == null) throw SectionTruncatedException("string section missing")
        if (off < 0 || off >= section.size) throw OutOfBoundsReferenceException("line string offset 0x${off.toString(16)} OOB")
        var end = off
        while (end < section.size && section[end].toInt() != 0) end++
        return String(section, off, end - off, Charsets.UTF_8)
    }
}
