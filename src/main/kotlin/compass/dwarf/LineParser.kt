package compass.dwarf

import compass.ByteReader
import compass.DwarfFormatException
import compass.unitLength

/** Parses .debug_line / .debug_line.dwo line-number programs, DWARF 4 and 5. */
class LineParser(private val obj: DebugObject) {

    private val line = obj.section(".debug_line") ?: obj.section(".debug_line.dwo")
    private val maxPrograms = 100_000

    fun parse(): List<LineProgram> {
        if (line == null) return emptyList()
        val programs = mutableListOf<LineProgram>()
        val outer = ByteReader(line, 0, line.size, obj.littleEndian)
        var guard = 0
        while (!outer.exhausted) {
            if (++guard > maxPrograms) {
                obj.issues += DebugIssue(DebugIssue.Severity.ERROR, "too_many_line_programs", "limit reached")
                break
            }
            val start = outer.pos
            programs += parseOne(outer, start)
        }
        return programs
    }

    private fun parseOne(outer: ByteReader, start: Int): LineProgram {
        val issues = mutableListOf<DebugIssue>()
        val ul = try {
            outer.unitLength()
        } catch (e: DwarfFormatException) {
            return corrupted(outer, outer.limit, start, 2, obj.addressSize, "unit_length: ${e.message}")
        }
        val end = ul.end.coerceAtMost(outer.limit)
        if (ul.end > outer.limit) {
            issues += DebugIssue(DebugIssue.Severity.ERROR, "line_truncated",
                "program at $start declares end ${ul.end} > section ${outer.limit}", start.toLong(), ".debug_line")
        }
        return try {
            val version = outer.u16()
            var addressSize = obj.addressSize
            var segSelector = 0
            val minInsnLen: Int
            var maxOpsPerInsn = 1
            val defaultStmt: Boolean
            val lineBase: Int
            val lineRange: Int
            val opcodeBase: Int
            val stdLengths: IntArray
            if (version >= 5) {
                addressSize = outer.u8()
                segSelector = outer.u8()
                @Suppress("UNUSED_VARIABLE") val headerLength = readOff(outer, ul.is64Bit)
                minInsnLen = outer.u8()
                maxOpsPerInsn = outer.u8()
                defaultStmt = outer.u8() != 0
                lineBase = outer.u8().toByte().toInt()
                lineRange = outer.u8()
                opcodeBase = outer.u8()
                stdLengths = IntArray((opcodeBase - 1).coerceAtLeast(0)) { outer.u8() }
                val (dirs, files) = parseV5FileNames(outer, ul.is64Bit)
                val prog = LineProgram(
                    null, start.toLong(), version, addressSize, segSelector, minInsnLen,
                    maxOpsPerInsn.coerceAtLeast(1), defaultStmt, lineBase, lineRange, opcodeBase,
                    stdLengths, dirs, files, emptyList(), issues,
                )
                val seqs = LineMachine(prog, obj, ul.is64Bit).run(outer, end, issues)
                finalize(outer, end, prog, seqs)
            } else {
                @Suppress("UNUSED_VARIABLE") val headerLength = readOff(outer, ul.is64Bit)
                minInsnLen = outer.u8()
                defaultStmt = outer.u8() != 0
                lineBase = outer.u8().toByte().toInt()
                lineRange = outer.u8()
                opcodeBase = outer.u8()
                stdLengths = IntArray((opcodeBase - 1).coerceAtLeast(0)) { outer.u8() }
                val (dirs, files) = parseV4IncludeDirsAndFiles(outer)
                val prog = LineProgram(
                    null, start.toLong(), version, addressSize, 0, minInsnLen,
                    1, defaultStmt, lineBase, lineRange, opcodeBase, stdLengths, dirs, files,
                    emptyList(), issues,
                )
                val seqs = LineMachine(prog, obj, ul.is64Bit).run(outer, end, issues)
                finalize(outer, end, prog, seqs)
            }
        } catch (e: DwarfFormatException) {
            corrupted(outer, end, start, 4, addressSizeSafe(outer), e.message ?: "parse error")
        }
    }

    private fun addressSizeSafe(r: ByteReader) = obj.addressSize

    private fun finalize(outer: ByteReader, end: Int, prog: LineProgram, seqs: List<LineSequence>): LineProgram {
        outer.seek(end)
        val finished = LineProgram(
            null, prog.sectionOffset, prog.version, prog.addressSize, prog.segmentSelectorSize,
            prog.minimumInstructionLength, prog.maximumOperationsPerInstruction, prog.defaultIsStatement,
            prog.lineBase, prog.lineRange, prog.opcodeBase, prog.standardOpcodeLengths,
            prog.directories, prog.files, seqs, prog.issues,
        )
        return finished
    }

    private fun parseV4IncludeDirsAndFiles(r: ByteReader): Pair<List<String>, List<LineFile>> {
        val dirs = mutableListOf("") // index 0 = compilation directory
        while (true) {
            val s = r.nullTerminatedString()
            if (s.isEmpty()) break
            dirs += s
        }
        val files = mutableListOf(LineFile("", 0, "")) // v4 file numbers start at 1
        var guard = 0
        while (true) {
            if (++guard > 10_000_000) throw DwarfFormatException("too many v4 file entries")
            val name = r.nullTerminatedString()
            if (name.isEmpty()) break
            val dirIndex = r.uleb128().toInt()
            r.uleb128() // mtime
            r.uleb128() // size
            val dir = dirs.getOrNull(dirIndex) ?: ""
            files += LineFile(name, dirIndex, joinPath(dir, name))
        }
        return dirs to files
    }

    private fun parseV5FileNames(r: ByteReader, is64: Boolean): Pair<List<String>, List<LineFile>> {
        val dirDescs = readFormDescs(r)
        val dirCount = r.uleb128().toInt()
        val dirs = ArrayList<String>(dirCount + 1).also { it += "" }
        repeat(dirCount) { dirs += readEntry(r, dirDescs, is64) ?: "" }

        val fileDescs = readFormDescs(r)
        val fileCount = r.uleb128().toInt()
        val files = ArrayList<LineFile>(fileCount + 1).also { it += LineFile("", 0, "") }
        repeat(fileCount) {
            var path: String? = null
            var dirIdx = 0
            for ((contentType, form) in fileDescs) {
                when (contentType) {
                    DW.LNCT_PATH -> path = readContentString(r, form, is64)
                    DW.LNCT_DIRECTORY_INDEX -> dirIdx = readContentLong(r, form, is64)?.toInt() ?: 0
                    else -> skipContent(r, form, is64)
                }
            }
            val name = path ?: ""
            val dir = dirs.getOrNull(dirIdx) ?: ""
            files += LineFile(name, dirIdx, joinPath(dir, name))
        }
        return dirs to files
    }

    private fun readFormDescs(r: ByteReader): List<Pair<Int, Int>> {
        val count = r.u8()
        return List(count) { r.uleb128().toInt() to r.uleb128().toInt() }
    }

    private fun readEntry(r: ByteReader, descs: List<Pair<Int, Int>>, is64: Boolean): String? {
        var path: String? = null
        for ((contentType, form) in descs) {
            when (contentType) {
                DW.LNCT_PATH -> path = readContentString(r, form, is64)
                else -> skipContent(r, form, is64)
            }
        }
        return path
    }

    private fun readContentString(r: ByteReader, form: Int, is64: Boolean): String? = when (form) {
        DW.FORM_STRING -> r.nullTerminatedString()
        DW.FORM_LINE_STRP -> readNul(obj.section(".debug_line_str"), readOff(r, is64))
        DW.FORM_STRP -> readNul(obj.section(".debug_str"), readOff(r, is64))
        DW.FORM_STRX, DW.FORM_GNU_STR_INDEX -> strxForLine(r.uleb128())
        DW.FORM_STRX1 -> strxForLine(r.u8().toULong())
        DW.FORM_STRX2 -> strxForLine(r.u16().toULong())
        DW.FORM_STRX3 -> strxForLine(r.u32().toULong())
        DW.FORM_STRX4 -> strxForLine(r.u64().toULong())
        else -> { skipContent(r, form, is64); null }
    }

    private fun readContentLong(r: ByteReader, form: Int, is64: Boolean): Long? = when (form) {
        DW.FORM_DATA1 -> r.u8().toLong()
        DW.FORM_DATA2 -> r.u16().toLong()
        DW.FORM_DATA4 -> r.u32()
        DW.FORM_DATA8 -> r.u64()
        DW.FORM_UDATA -> r.uleb128().toLong()
        DW.FORM_SDATA -> r.sleb128()
        DW.FORM_LINE_STRP, DW.FORM_STRP, DW.FORM_SEC_OFFSET -> readOff(r, is64)
        else -> { skipContent(r, form, is64); null }
    }

    private fun skipContent(r: ByteReader, form: Int, is64: Boolean) {
        when (form) {
            DW.FORM_STRING -> r.nullTerminatedString()
            DW.FORM_LINE_STRP, DW.FORM_STRP, DW.FORM_SEC_OFFSET,
            DW.FORM_STRX4, DW.FORM_ADDRX4, DW.FORM_REF4, DW.FORM_DATA4 -> readOff(r, is64)
            DW.FORM_DATA1, DW.FORM_FLAG, DW.FORM_STRX1, DW.FORM_ADDRX1, DW.FORM_REF1 -> r.u8()
            DW.FORM_DATA2, DW.FORM_STRX2, DW.FORM_ADDRX2, DW.FORM_REF2 -> r.u16()
            DW.FORM_DATA8, DW.FORM_REF8, DW.FORM_REF_SIG8 -> r.u64()
            DW.FORM_UDATA, DW.FORM_SDATA, DW.FORM_STRX, DW.FORM_ADDRX,
            DW.FORM_GNU_STR_INDEX, DW.FORM_GNU_ADDR_INDEX,
            DW.FORM_REF_UDATA, DW.FORM_RNGLISTX, DW.FORM_LOCLISTX -> r.uleb128()
            DW.FORM_BLOCK1 -> r.bytes(r.u8())
            DW.FORM_BLOCK2 -> r.bytes(r.u16())
            DW.FORM_BLOCK, DW.FORM_EXPRLOC -> r.bytes(r.uleb128().toInt())
            DW.FORM_BLOCK4 -> r.bytes(r.u32().toInt())
            DW.FORM_DATA16 -> r.bytes(16)
            DW.FORM_FLAG_PRESENT, DW.FORM_IMPLICIT_CONST -> Unit
            else -> throw UnsupportedFormException(form)
        }
    }

    private fun strxForLine(index: ULong): String? {
        val section = obj.section(".debug_str_offsets") ?: return null
        for (cu in obj.cus) {
            val base = strOffsetsBase(obj, cu) ?: continue
            val entrySize = if (cu.is64BitDwarf) 8 else 4
            val off = base + index.toLong() * entrySize
            if (off < 0 || off + entrySize > section.size) continue
            val br = ByteReader(section, off.toInt(), section.size, obj.littleEndian)
            val target = if (entrySize == 8) br.u64() else br.u32()
            return readNul(obj.section(".debug_str"), target)
        }
        return null
    }

    private fun readOff(r: ByteReader, is64: Boolean): Long = if (is64) r.u64() else r.u32()

    private fun readNul(sec: ByteArray?, off: Long): String? {
        if (sec == null || off < 0 || off >= sec.size) return null
        val end = (off.toInt() until sec.size).firstOrNull { sec[it].toInt() == 0 } ?: return null
        return String(sec, off.toInt(), end - off.toInt(), Charsets.UTF_8)
    }

    private fun joinPath(dir: String, name: String): String =
        if (dir.isEmpty()) name else if (name.startsWith("/")) name else "$dir/$name"

    private fun corrupted(
        outer: ByteReader, end: Int, start: Int, version: Int, addressSize: Int, message: String,
    ): LineProgram {
        outer.seek(end.coerceAtMost(outer.limit))
        val issues = mutableListOf(
            DebugIssue(DebugIssue.Severity.ERROR, "line_corrupt", message, start.toLong(), ".debug_line"),
        )
        return LineProgram(
            cu = null, sectionOffset = start.toLong(), version = version, addressSize = addressSize,
            segmentSelectorSize = 0, minimumInstructionLength = 1, maximumOperationsPerInstruction = 1,
            defaultIsStatement = true, lineBase = -5, lineRange = 14, opcodeBase = 13,
            standardOpcodeLengths = IntArray(12), directories = emptyList(), files = emptyList(),
            sequences = emptyList(), issues = issues, corrupt = true,
        )
    }
}
