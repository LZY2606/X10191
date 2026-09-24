package compass.dwarf

data class LineFile(val name: String, val dirIndex: Long, val dir: String?)

data class LineHeader(
    val version: Int,
    val addrSize: Int,
    val minInstLen: Int,
    val maxOpsPerInst: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val stdOpcodeLengths: IntArray,
    val directories: List<String>,
    val files: List<LineFile>,
    val headerEnd: Int,
    val unitEnd: Int
)

data class LineRow(
    val sequence: Int,
    val address: Long,
    val endAddress: Long,
    val fileIndex: Int,
    val file: String,
    val line: Long,
    val column: Long,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Long,
    val discriminator: Long
) {
    val zeroLength: Boolean get() = !endSequence && endAddress == address
}

object LineProgram {
    const val MAX_ROWS = 500_000

    private fun readLnctValue(r: Reader, form: Int, ctx: FormContext): AttrValue =
        Forms.read(r, form, ctx, "line_header_entry")

    private fun resolveString(
        v: AttrValue,
        debugStr: ByteArray?,
        debugLineStr: ByteArray?,
        diagnostics: MutableList<String>
    ): String? {
        fun at(section: ByteArray?, off: Long, secName: String): String? {
            if (section == null) {
                diagnostics.add("missing $secName for string at $off")
                return null
            }
            if (off < 0 || off >= section.size) {
                diagnostics.add("string offset $off out of bounds in $secName (size ${section.size})")
                return null
            }
            var p = off.toInt()
            val start = p
            while (p < section.size && section[p].toInt() != 0) p++
            return String(section, start, p - start, Charsets.UTF_8)
        }
        return when (v) {
            is AttrValue.Str -> v.s
            is AttrValue.Strp -> at(debugStr, v.offset, ".debug_str")
            is AttrValue.LineStrp -> at(debugLineStr, v.offset, ".debug_line_str")
            is AttrValue.Strx -> {
                diagnostics.add("strx form in line header unsupported without .debug_str_offsets")
                null
            }
            else -> null
        }
    }

    fun parseHeader(
        section: ByteArray,
        offset: Int,
        littleEndian: Boolean = true,
        debugStr: ByteArray? = null,
        debugLineStr: ByteArray? = null,
        diagnostics: MutableList<String> = mutableListOf()
    ): LineHeader {
        val r = Reader(section, offset, section.size, littleEndian)
        var unitLen = r.u32()
        val dwarf64 = unitLen == 0xFFFF_FFFFL
        if (dwarf64) unitLen = r.u64()
        if (unitLen < 0 || r.pos + unitLen > section.size) {
            throw DwarfParseException("line program unit length $unitLen out of bounds at $offset")
        }
        val unitEnd = (r.pos + unitLen).toInt()
        val version = r.u16()
        if (version < 2 || version > 5) throw DwarfParseException("unsupported line table version $version")
        var addrSize = 8
        if (version >= 5) {
            addrSize = r.u8()
            r.u8() // segment selector size
        }
        val headerLen = if (dwarf64) r.u64() else r.u32()
        val headerEnd = (r.pos + headerLen).toInt()
        if (headerEnd > unitEnd) throw DwarfParseException("line header length out of bounds")
        val minInstLen = r.u8()
        val maxOps = if (version >= 4) r.u8() else 1
        val defaultIsStmt = r.u8() != 0
        val lineBase = r.i8()
        val lineRange = r.u8()
        val opcodeBase = r.u8()
        if (opcodeBase < 1 || opcodeBase > 64) throw DwarfParseException("bad opcode_base $opcodeBase")
        val stdLens = IntArray(opcodeBase - 1) { r.u8() }
        val ctx = FormContext(addrSize, dwarf64, version)
        val directories = ArrayList<String>()
        val files = ArrayList<LineFile>()
        if (version >= 5) {
            val dirFmtCount = r.u8()
            val dirFmts = ArrayList<Pair<Int, Int>>()
            repeat(dirFmtCount) { dirFmts.add(r.uleb().toInt() to r.uleb().toInt()) }
            val dirCount = r.uleb()
            if (dirCount > 100_000) throw LimitExceededException("too many directories")
            for (i in 0 until dirCount) {
                var path: String? = null
                for ((contentType, form) in dirFmts) {
                    val v = readLnctValue(r, form, ctx)
                    if (contentType == Dw.LNCT_path) {
                        path = resolveString(v, debugStr, debugLineStr, diagnostics)
                    }
                }
                directories.add(path ?: "")
            }
            val fileFmtCount = r.u8()
            val fileFmts = ArrayList<Pair<Int, Int>>()
            repeat(fileFmtCount) { fileFmts.add(r.uleb().toInt() to r.uleb().toInt()) }
            val fileCount = r.uleb()
            if (fileCount > 100_000) throw LimitExceededException("too many files")
            for (i in 0 until fileCount) {
                var name: String? = null
                var dirIdx = 0L
                for ((contentType, form) in fileFmts) {
                    val v = readLnctValue(r, form, ctx)
                    when (contentType) {
                        Dw.LNCT_path -> name = resolveString(v, debugStr, debugLineStr, diagnostics)
                        Dw.LNCT_directory_index -> if (v is AttrValue.UInt) dirIdx = v.v
                    }
                }
                val dir = if (dirIdx >= 0 && dirIdx < directories.size) directories[dirIdx.toInt()] else null
                files.add(LineFile(name ?: "<unknown>", dirIdx, dir))
            }
        } else {
            while (true) {
                val s = r.cstring()
                if (s.isEmpty()) break
                directories.add(s)
            }
            while (true) {
                val name = r.cstring()
                if (name.isEmpty()) break
                val dirIdx = r.uleb()
                r.uleb() // mtime
                r.uleb() // size
                val dir = if (dirIdx in 1..directories.size) directories[(dirIdx - 1).toInt()] else null
                files.add(LineFile(name, dirIdx, dir))
            }
        }
        return LineHeader(
            version, addrSize, minInstLen, maxOps, defaultIsStmt, lineBase, lineRange,
            opcodeBase, stdLens, directories, files, headerEnd, unitEnd
        )
    }

    private class State(h: LineHeader) {
        var address = 0L
        var opIndex = 0
        var file = 1
        var line = 1L
        var column = 0L
        var isStmt = h.defaultIsStmt
        var basicBlock = false
        var endSequence = false
        var prologueEnd = false
        var epilogueBegin = false
        var isa = 0L
        var discriminator = 0L

        fun reset(h: LineHeader) {
            address = 0; opIndex = 0; file = 1; line = 1; column = 0
            isStmt = h.defaultIsStmt
            basicBlock = false; endSequence = false; prologueEnd = false; epilogueBegin = false
            isa = 0; discriminator = 0
        }
    }

    fun parse(
        section: ByteArray,
        offset: Int,
        littleEndian: Boolean = true,
        debugStr: ByteArray? = null,
        debugLineStr: ByteArray? = null,
        diagnostics: MutableList<String> = mutableListOf()
    ): Pair<LineHeader, List<LineRow>> {
        val h = parseHeader(section, offset, littleEndian, debugStr, debugLineStr, diagnostics)
        val r = Reader(section, h.headerEnd, h.unitEnd, littleEndian)
        val st = State(h)
        val rows = ArrayList<LineRow>()
        var sequence = 0

        fun fileName(idx: Int): String {
            val i = if (h.version >= 5) idx else idx - 1
            return h.files.getOrNull(i)?.name ?: "<file#$idx>"
        }

        fun emit(endSeq: Boolean) {
            if (rows.size >= MAX_ROWS) throw LimitExceededException("too many line rows")
            rows.add(
                LineRow(
                    sequence, st.address, st.address, st.file, fileName(st.file), st.line, st.column,
                    st.isStmt, st.basicBlock, endSeq, st.prologueEnd, st.epilogueBegin, st.isa, st.discriminator
                )
            )
        }

        while (r.remaining() > 0) {
            val op = r.u8()
            if (op == 0) {
                val len = r.uleb()
                val end = r.pos + len.toInt()
                if (end > h.unitEnd) throw DwarfParseException("extended opcode overruns unit")
                if (len == 0L) continue
                val sub = r.u8()
                when (sub) {
                    Dw.LNE_end_sequence -> {
                        st.endSequence = true
                        emit(true)
                        sequence++
                        st.reset(h)
                    }
                    Dw.LNE_set_address -> {
                        st.address = Forms.read(r, Dw.FORM_addr, FormContext(h.addrSize, false, h.version), "set_address")
                            .let { (it as AttrValue.Addr).v }
                        st.opIndex = 0
                    }
                    Dw.LNE_define_file -> {
                        // rare; consume best-effort
                        r.cstring(); r.uleb(); r.uleb(); r.uleb()
                    }
                    Dw.LNE_set_discriminator -> {
                        st.discriminator = r.uleb()
                    }
                    else -> {
                        diagnostics.add("unknown extended line opcode $sub, skipping payload")
                    }
                }
                r.pos = end
            } else if (op < h.opcodeBase) {
                when (op) {
                    Dw.LNS_copy -> {
                        emit(false)
                        st.discriminator = 0; st.basicBlock = false
                        st.prologueEnd = false; st.epilogueBegin = false
                    }
                    Dw.LNS_advance_pc -> {
                        val adv = r.uleb()
                        st.address += (h.minInstLen.toLong() * ((st.opIndex + adv) / h.maxOpsPerInst))
                        st.opIndex = ((st.opIndex + adv) % h.maxOpsPerInst).toInt()
                    }
                    Dw.LNS_advance_line -> st.line += r.sleb()
                    Dw.LNS_set_file -> st.file = r.uleb().toInt()
                    Dw.LNS_set_column -> st.column = r.uleb()
                    Dw.LNS_negate_stmt -> st.isStmt = !st.isStmt
                    Dw.LNS_set_basic_block -> st.basicBlock = true
                    Dw.LNS_const_add_pc -> {
                        val adjusted = 255 - h.opcodeBase
                        val adv = adjusted / h.lineRange
                        st.address += (h.minInstLen.toLong() * ((st.opIndex + adv) / h.maxOpsPerInst))
                        st.opIndex = ((st.opIndex + adv) % h.maxOpsPerInst).toInt()
                    }
                    Dw.LNS_fixed_advance_pc -> {
                        st.address += r.u16()
                        st.opIndex = 0
                    }
                    Dw.LNS_set_prologue_end -> st.prologueEnd = true
                    Dw.LNS_set_epilogue_begin -> st.epilogueBegin = true
                    Dw.LNS_set_isa -> st.isa = r.uleb()
                    else -> {
                        // Unknown standard opcode: skip its declared operands.
                        val idx = op - 1
                        val n = if (idx < h.stdOpcodeLengths.size) h.stdOpcodeLengths[idx] else 0
                        repeat(n) { r.uleb() }
                        diagnostics.add("unknown standard line opcode $op, skipped $n operands")
                    }
                }
            } else {
                val adjusted = op - h.opcodeBase
                val opAdv = adjusted / h.lineRange
                st.address += (h.minInstLen.toLong() * ((st.opIndex + opAdv) / h.maxOpsPerInst))
                st.opIndex = ((st.opIndex + opAdv) % h.maxOpsPerInst).toInt()
                st.line += h.lineBase + (adjusted % h.lineRange)
                emit(false)
                st.basicBlock = false; st.prologueEnd = false; st.epilogueBegin = false
                st.discriminator = 0
            }
        }

        // Compute end addresses: within a sequence, a row spans to the next row's address.
        val out = ArrayList<LineRow>(rows.size)
        for (i in rows.indices) {
            val row = rows[i]
            if (row.endSequence) {
                out.add(row)
            } else {
                var end = row.address
                var j = i + 1
                while (j < rows.size && rows[j].sequence == row.sequence) {
                    end = rows[j].address
                    break
                }
                out.add(row.copy(endAddress = end))
            }
        }
        return h to out
    }
}
