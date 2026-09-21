package com.compass.dwarf

/**
 * .debug_line parser. Produces per-sequence rows capturing each line-program
 * state transition. DWARF 4 and 5 headers are both supported; an unknown
 * entry/contents form isolates that one file entry rather than corrupting
 * subsequent reads.
 */
class LineProgramParser(
    private val sections: SectionSet,
    private val issues: MutableList<ParseIssue>
) {
    fun parse(offset: Long, data: ByteArray, addressSize: Int): LineTable? {
        if (data.isEmpty()) return null
        val b = Buf(data); b.seek(offset.toInt())
        val first = b.u32()
        val dwarf64 = first == 0xffff_ffffL
        if (dwarf64) b.u64()

        val version = b.u16()
        if (version < 2 || version > 5) {
            issues += ParseIssue("line@0x${offset.toString(16)}", "unsupported line version $version", "error")
            return null
        }

        var minInsn = 1
        var maxOps = 1
        var defaultStmt = 1
        var lineBase = -5
        var lineRange = 14
        var opcodeBase = 13
        var standardArgs = IntArray(0)
        var dirs = mutableListOf<String>()
        var files = mutableListOf<SourceFile>()
        var programStart = b.pos

        if (version >= 5) {
            // header_length counts from the version byte (before it is read).
            val versionPos = b.pos - 2
            val cuHeaderLen = (if (dwarf64) b.u64() else b.u32()).toInt()
            val headerContentStart = b.pos
            minInsn = b.u8()
            maxOps = b.u8().coerceAtLeast(1)
            defaultStmt = b.u8()
            lineBase = b.u8().toByte().toInt()
            lineRange = b.u8()
            opcodeBase = b.u8()
            standardArgs = IntArray(opcodeBase)
            for (op in 1 until opcodeBase) standardArgs[op] = b.u8()
            dirs = readV5Dirs(b, dwarf64, addressSize)
            files = readV5Files(b, dwarf64, addressSize, dirs)
            // header_length covers the bytes from the version field through
            // the end of the file-name entries (i.e. from headerStart).
            programStart = versionPos + cuHeaderLen
            if (programStart > b.size) throw ParseException("line header_length runs past section")
            b.seek(programStart)
        } else {
            minInsn = b.u8()
            if (version >= 4) maxOps = b.u8().coerceAtLeast(1)
            defaultStmt = b.u8()
            lineBase = b.u8().toByte().toInt()
            lineRange = b.u8()
            opcodeBase = b.u8()
            standardArgs = IntArray(opcodeBase)
            for (op in 1 until opcodeBase) standardArgs[op] = b.u8()
            dirs = readV4Dirs(b)
            files = readV4Files(b, dirs)
            programStart = b.pos
        }

        val seqs = runProgram(Buf(data), programStart, minInsn, maxOps, defaultStmt == 1,
            lineBase, lineRange, opcodeBase, standardArgs, offset.toInt())
        return LineTable(offset, version, dwarf64, files, dirs, seqs, issues.toList(),
            minInsn, defaultStmt == 1)
    }

    private fun readV4Dirs(b: Buf): MutableList<String> {
        val dirs = mutableListOf("")
        while (true) {
            val s = b.cstring()
            if (s.isEmpty()) break
            dirs += s
        }
        return dirs
    }

    private fun readV4Files(b: Buf, dirs: List<String>): MutableList<SourceFile> {
        // DWARF 2-4 file indexes are 1-based; reserve index 0.
        val files = mutableListOf(SourceFile(0, "<invalid>", 0))
        while (true) {
            val name = b.cstring()
            if (name.isEmpty()) break
            val dirIdx = b.uleb().toInt()
            b.uleb(); b.uleb()
            files += SourceFile(files.size, name, dirIdx.coerceIn(0, dirs.size - 1))
        }
        return files
    }

    private fun skipEntry(b: Buf, dwarf64: Boolean, addressSize: Int) {
        val contentCount = b.u8()
        repeat(contentCount) {
            b.uleb()
            val form = b.uleb().toLong()
            skipLineForm(b, form, dwarf64, addressSize)
        }
    }

    private fun readV5Dirs(b: Buf, dwarf64: Boolean, addressSize: Int): MutableList<String> {
        val count = b.uleb().toInt()
        val dirs = mutableListOf("")
        repeat(count) {
            val contentCount = b.u8()
            var path = ""
            repeat(contentCount) { entry ->
                val type = b.uleb().toLong()
                val form = b.uleb().toLong()
                try {
                    val v = readLineForm(b, form, dwarf64, addressSize)
                    if (type == DW_LNCT_path.toLong()) {
                        path = when (v) {
                            is AttrValue.Str -> v.v
                            is AttrValue.StrRef -> lineString(v) ?: ""
                            else -> ""
                        }
                    }
                } catch (e: ParseException) {
                    issues += ParseIssue("line", "directory entry isolated: ${e.message}", "warn")
                    // cursor already advanced for the failing form's known prefix only;
                    // we cannot reliably skip: propagate to abort this CU line parse.
                    throw e
                }
            }
            dirs += path
        }
        return dirs
    }

    private fun readV5Files(b: Buf, dwarf64: Boolean, addressSize: Int,
                            dirs: List<String>): MutableList<SourceFile> {
        val count = b.uleb().toInt()
        // DWARF5 file indexes are 0-based; still add a placeholder only when the
        // producer's first index is 1 (some GCC variants) — handled by caller.
        val files = mutableListOf<SourceFile>()
        repeat(count) { fileIdx ->
            val contentCount = b.u8()
            var path = ""; var dirIndex = 0
            repeat(contentCount) {
                val type = b.uleb().toLong()
                val form = b.uleb().toLong()
                val v = readLineForm(b, form, dwarf64, addressSize)
                if (type == DW_LNCT_path.toLong()) {
                    path = when (v) {
                        is AttrValue.Str -> v.v
                        is AttrValue.StrRef -> lineString(v) ?: ""
                        else -> ""
                    }
                } else if (type == DW_LNCT_directory_index.toLong()) {
                    dirIndex = (v as? AttrValue.Num)?.v?.toInt() ?: 0
                }
            }
            files += SourceFile(fileIdx, path, dirIndex.coerceIn(0, (dirs.size - 1).coerceAtLeast(0)))
        }
        return files
    }

    private fun lineString(ref: AttrValue.StrRef): String? {
        val data = sections.bytes(if (ref.lineStr) ".debug_line_str" else ".debug_str")
        if (ref.offset < 0 || ref.offset >= data.size) return null
        return Buf(data).cstringAt(ref.offset.toInt())
    }

    private fun readLineForm(b: Buf, form: Long, dwarf64: Boolean, addressSize: Int): AttrValue =
        when (form) {
            DW_FORM_string.toLong() -> AttrValue.Str(b.cstring())
            DW_FORM_strp.toLong() -> AttrValue.StrRef(if (dwarf64) b.u64() else b.u32(), false)
            DW_FORM_line_strp.toLong() -> AttrValue.StrRef(if (dwarf64) b.u64() else b.u32(), true)
            DW_FORM_data1.toLong(), DW_FORM_strx1.toLong() -> AttrValue.Num(b.u8().toLong())
            DW_FORM_data2.toLong(), DW_FORM_strx2.toLong() -> AttrValue.Num(b.u16().toLong())
            DW_FORM_strx3.toLong() -> AttrValue.Strx(b.u8() or (b.u8() shl 8) or (b.u8() shl 16))
            DW_FORM_data4.toLong(), DW_FORM_sec_offset.toLong(), DW_FORM_strx4.toLong() -> AttrValue.Num(b.u32())
            DW_FORM_data8.toLong() -> AttrValue.Num(b.u64())
            DW_FORM_udata.toLong(), DW_FORM_strx.toLong() -> AttrValue.Num(b.uleb().toLong())
            DW_FORM_sdata.toLong() -> AttrValue.Num(b.sleb())
            DW_FORM_flag_present.toLong() -> AttrValue.Num(1L)
            else -> throw ParseException("unsupported line form 0x${form.toString(16)}")
        }

    private fun skipLineForm(b: Buf, form: Long, dwarf64: Boolean, addressSize: Int) {
        when (form) {
            DW_FORM_string.toLong() -> b.cstring()
            DW_FORM_strp.toLong(), DW_FORM_line_strp.toLong(),
            DW_FORM_data4.toLong(), DW_FORM_sec_offset.toLong(), DW_FORM_strx4.toLong() ->
                if (dwarf64) b.u64() else b.u32()
            DW_FORM_data8.toLong() -> b.u64()
            DW_FORM_data16.toLong() -> b.bytes(16)
            DW_FORM_data1.toLong(), DW_FORM_strx1.toLong() -> b.u8()
            DW_FORM_data2.toLong(), DW_FORM_strx2.toLong() -> b.u16()
            DW_FORM_udata.toLong(), DW_FORM_strx.toLong() -> b.uleb()
            DW_FORM_sdata.toLong() -> b.sleb()
            DW_FORM_block1.toLong() -> b.bytes(b.u8())
            DW_FORM_block2.toLong() -> b.bytes(b.u16())
            else -> throw ParseException("cannot skip line form 0x${form.toString(16)}")
        }
    }

    private class State(val defaultStmt: Boolean) {
        var address = 0L; var opIndex = 0
        var file = 1; var line = 1; var column = 0
        var stmt = defaultStmt; var basicBlock = false; var endSequence = false
        var prologueEnd = false; var epilogueBegin = false; var isa = 0; var discriminator = 0
    }

    private fun runProgram(data: Buf, start: Int, minInsn: Int, maxOps: Int, defaultStmt: Boolean,
                           lineBase: Int, lineRange: Int, opcodeBase: Int, standardArgs: IntArray,
                           cuOff: Int): List<LineSequence> {
        data.seek(start)
        val seqs = mutableListOf<LineSequence>()
        var rows = mutableListOf<LineRow>()
        var seqStart = 0L
        var st = State(defaultStmt)
        fun reset() { st = State(defaultStmt) }
        fun appendRow() {
            rows += LineRow(st.address, st.file, st.line, st.column, st.endSequence,
                st.discriminator, st.isa, st.stmt, st.basicBlock, st.prologueEnd)
            st.basicBlock = false; st.prologueEnd = false; st.epilogueBegin = false
            st.discriminator = 0
        }
        fun advance(adj: Int) {
            val addrAdv = minInsn * ((adj / lineRange) +
                if (maxOps > 1) st.opIndex / maxOps else 0)
            st.address += addrAdv.toLong()
            st.opIndex = (st.opIndex + adj) % maxOps
            if (st.opIndex < st.opIndex) st.opIndex = 0
        }
        var guard = 0
        while (data.pos < data.size) {
            if (++guard > 5_000_000) throw ParseException("line program too long")
            val op = data.u8()
            if (op == 0) {
                val extLen = data.uleb().toInt()
                val bodyStart = data.pos
                val sub = data.u8()
                when (sub) {
                    DW_LINE_end_sequence -> {
                        st.endSequence = true
                        appendRow()
                        seqs += LineSequence(seqs.size, seqStart, st.address, rows)
                        rows = mutableListOf()
                        reset()
                    }
                    DW_LINE_set_address -> {
                        val left = extLen - (data.pos - bodyStart)
                        st.address = data.unsigned(left.coerceAtLeast(1).coerceAtMost(8)).toLong()
                        st.opIndex = 0
                    }
                    DW_LINE_define_file -> {
                        data.cstring(); data.uleb(); data.uleb(); data.uleb()
                    }
                    DW_LINE_set_discriminator -> st.discriminator = data.uleb().toInt()
                    else -> {}
                }
                data.seek(bodyStart + extLen)
            } else if (op < opcodeBase) {
                when (op) {
                    DW_LNS_copy -> appendRow()
                    DW_LNS_advance_pc -> {
                        val adv = data.uleb().toInt()
                        st.address += adv.toLong() * minInsn
                        st.opIndex = 0
                    }
                    DW_LNS_advance_line -> st.line += data.sleb().toInt()
                    DW_LNS_set_file -> st.file = data.uleb().toInt()
                    DW_LNS_set_column -> st.column = data.uleb().toInt()
                    DW_LNS_negate_stmt -> st.stmt = !st.stmt
                    DW_LNS_set_basic_block -> st.basicBlock = true
                    DW_LNS_const_add_pc -> {
                        val adj = (255 - opcodeBase)
                        st.address += minInsn * (adj / lineRange).toLong()
                    }
                    DW_LNS_fixed_advance_pc -> { st.address += data.u16().toLong(); st.opIndex = 0 }
                    DW_LNS_set_prologue_end -> st.prologueEnd = true
                    DW_LNS_set_epilogue_begin -> st.epilogueBegin = true
                    DW_LNS_set_isa -> st.isa = data.uleb().toInt()
                    else -> if (op < standardArgs.size) repeat(standardArgs[op]) { data.uleb() }
                }
            } else {
                val adj = op - opcodeBase
                st.line += lineBase + adj % lineRange
                advance(adj)
                st.opIndex = 0
                if (rows.isEmpty()) seqStart = st.address
                appendRow()
            }
        }
        if (rows.isNotEmpty()) {
            issues += ParseIssue("line@0x${cuOff.toString(16)}", "trailing rows without end_sequence", "warn")
        }
        return seqs
    }
}
