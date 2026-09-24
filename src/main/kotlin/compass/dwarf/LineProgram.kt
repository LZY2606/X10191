package compass.dwarf

/** 单个 .debug_line 程序（一个 CU 一个，自包含头与状态机） */
class LineProgramParser(private val sections: SectionSet, private val le: Boolean) {

    fun parse(offset: Long, cuOffset: Long?): LineProgram? {
        val data = sections[".debug_line"] ?: return null
        return try {
            doParse(data, offset, cuOffset)
        } catch (e: ParseException) {
            LineProgram(offset, 0, false, 4, 0, emptyList(), emptyList(), emptyList(), emptyList(), cuOffset, e.message)
        }
    }

    private fun doParse(data: ByteArray, offset: Long, cuOffset: Long?): LineProgram {
        val r = BinReader(data, offset.toInt(), le)
        val startPos = r.pos
        val lenField = r.u32()
        val dwarf64 = lenField == 0xffffffffL
        val unitLen = if (dwarf64) r.u64() else lenField
        val programEnd = r.pos + unitLen.toInt()
        val version = r.u16()
        var addressSize = 4
        var segmentSize = 0
        if (version >= 5) {
            addressSize = r.u8()
            segmentSize = r.u8()
        }
        val headerLen = if (dwarf64) r.u64() else r.u32()
        val headerEnd = r.pos + headerLen.toInt()

        var minInsnLen = 1
        var maxOpsPerInsn = 1
        var defaultIsStmt = 1
        var lineBase = 0
        var lineRange = 1
        var opcodeBase = 13
        var stdOpcodeLengths = intArrayOf(0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1)
        if (version <= 4) {
            minInsnLen = r.u8()
            if (version >= 4) r.u8() // max_ops_per_insn
            defaultIsStmt = r.u8()
            lineBase = r.i8()
            lineRange = r.u8()
            opcodeBase = r.u8()
            if (opcodeBase > 1) {
                stdOpcodeLengths = IntArray(opcodeBase)
                for (i in 1 until opcodeBase) stdOpcodeLengths[i] = r.u8()
            }
        } else {
            minInsnLen = r.u8()
            maxOpsPerInsn = r.u8()
            defaultIsStmt = r.u8()
            lineBase = r.i8()
            lineRange = r.u8()
            opcodeBase = r.u8()
            stdOpcodeLengths = IntArray(opcodeBase)
            for (i in 1 until opcodeBase) stdOpcodeLengths[i] = r.u8()
            // v5 directories / files 在头内
        }

        val directories = mutableListOf<String>()
        val files = mutableListOf<FileEntry>()
        val str: ByteArray = sections[".debug_str"] ?: ByteArray(0)
        val lineStr: ByteArray = sections[".debug_line_str"] ?: ByteArray(0)
        fun readString(form: Int, formData: Long): String = when (form) {
            DW_FORM.STRING -> r.cstring()
            DW_FORM.LINE_STRP -> BinReader(lineStr, formData.toInt(), le).cstring()
            DW_FORM.STRP -> BinReader(str, formData.toInt(), le).cstring()
            else -> throw ParseException("line header 不支持的字符串 form 0x${form.toString(16)}")
        }
        fun readFormVal(form: Int): Long = when (form) {
            DW_FORM.STRING -> { val p = r.pos; r.cstring(); p.toLong() }
            DW_FORM.LINE_STRP, DW_FORM.STRP -> r.uword(if (dwarf64) 8 else 4)
            DW_FORM.DATA1, DW_FORM.UDATA -> r.uleb()
            DW_FORM.DATA2 -> r.u16().toLong()
            DW_FORM.DATA4 -> r.u32()
            DW_FORM.DATA8 -> r.u64()
            else -> { r.uleb() } // 未使用的内容类型
        }

        if (version <= 4) {
            // include_directories
            while (true) {
                val s = r.cstring()
                if (s.isEmpty()) break
                directories.add(s)
            }
            // file_names：条目 0 隐式为 CU 根文件名
            files.add(FileEntry("", 0))
            while (true) {
                if (r.pos >= headerEnd) break
                val name = r.cstring()
                if (name.isEmpty()) break
                val dirIdx = r.uleb().toInt()
                r.uleb(); r.uleb() // timestamp, size
                files.add(FileEntry(name, dirIdx))
            }
        } else {
            // directories
            val dirEntryFormatCount = r.u8()
            val dirForms = ArrayList<Pair<Int, Int>>()
            for (i in 0 until dirEntryFormatCount) dirForms.add(r.uleb().toInt() to r.uleb().toInt())
            val dirsDone = r.uleb()
            repeat(dirsDone.toInt()) {
                var path = ""
                var dIdx = 0
                for ((ct, form) in dirForms) {
                    val fv = readFormVal(form)
                    if (ct == DW_LNCT.PATH) path = readString(form, fv)
                    else if (ct == DW_LNCT.DIRECTORY_INDEX) dIdx = fv.toInt()
                }
                directories.add(path)
            }
            // files
            files.add(FileEntry("", 0))
            val fileEntryFormatCount = r.u8()
            val fileForms = ArrayList<Pair<Int, Int>>()
            for (i in 0 until fileEntryFormatCount) fileForms.add(r.uleb().toInt() to r.uleb().toInt())
            val filesDone = r.uleb()
            repeat(filesDone.toInt()) {
                var path = ""
                var dIdx = 0
                for ((ct, form) in fileForms) {
                    val fv = readFormVal(form)
                    if (ct == DW_LNCT.PATH) path = readString(form, fv)
                    else if (ct == DW_LNCT.DIRECTORY_INDEX) dIdx = fv.toInt()
                }
                files.add(FileEntry(path, dIdx))
            }
        }
        r.seek(headerEnd)

        // 状态机
        val rows = mutableListOf<LineRow>()
        val sequences = mutableListOf<LineSequence>()
        var address = 0L
        var segment = 0
        var file = 1
        var line = 1
        var column = 0
        var opIndex = 0
        var isa = 0
        var discriminator = 0
        var isStmt = defaultIsStmt != 0
        var basicBlock = false
        var prologueEnd = false
        var epilogueBegin = false
        var seqStartRow = 0
        var seqLow = Long.MAX_VALUE
        var seqHigh = 0L
        var seqIndex = 0

        fun emit(endSeq: Boolean) {
            rows.add(LineRow(address, segment, file, line, column, opIndex, isa, discriminator,
                isStmt, basicBlock, prologueEnd, epilogueBegin, endSeq, seqIndex))
            if (address < seqLow) seqLow = address
            val endExclusive = if (endSeq) address else address
            if (address > seqHigh) seqHigh = address
            basicBlock = false; prologueEnd = false; epilogueBegin = false
            discriminator = 0
        }

        while (r.pos < programEnd) {
            val opcode = r.u8()
            if (opcode >= opcodeBase) {
                val adjusted = opcode - opcodeBase
                val advAddr = adjusted / lineRange
                val advLine = lineBase + (adjusted % lineRange)
                address += (minInsnLen * (opIndex + advAddr)).toLong()
                opIndex = 0
                line += advLine
                emit(false)
            } else when (opcode) {
                0 -> {
                    val extLen = r.uleb().toInt()
                    val extEnd = r.pos + extLen
                    val sub = r.u8()
                    when (sub) {
                        DW_LNE.END_SEQUENCE -> {
                            emit(true)
                            if (seqStartRow < rows.size) {
                                sequences.add(LineSequence(seqIndex, seqStartRow, rows.size, seqLow, seqHigh))
                            }
                            seqIndex++
                            seqStartRow = rows.size
                            seqLow = Long.MAX_VALUE; seqHigh = 0L
                            address = 0L; segment = 0; file = 1; line = 1; column = 0
                            opIndex = 0; isa = 0; discriminator = 0; isStmt = defaultIsStmt != 0
                            basicBlock = false; prologueEnd = false; epilogueBegin = false
                        }
                        DW_LNE.SET_ADDRESS -> {
                            if (version >= 5 && segmentSize > 0) {
                                val sel = r.uword(segmentSize).toInt()
                                segment = sel
                                address = r.uword(addressSize)
                            } else {
                                address = r.uword(addressSize)
                            }
                            opIndex = 0
                        }
                        DW_LNE.DEFINE_FILE -> {
                            if (version <= 4) {
                                val name = r.cstring()
                                val d = r.uleb().toInt(); r.uleb(); r.uleb()
                                files.add(FileEntry(name, d))
                            }
                        }
                        DW_LNE.SET_DISCRIMINATOR -> discriminator = r.uleb().toInt()
                        else -> { /* 未知扩展 opcode：按长度跳过，不丢同步 */ }
                    }
                    r.seek(extEnd)
                }
                DW_LNS.COPY -> emit(false)
                DW_LNS.ADVANCE_PC -> {
                    val adv = r.uleb().toInt()
                    address += (minInsnLen * (opIndex + adv)).toLong(); opIndex = 0
                }
                DW_LNS.ADVANCE_LINE -> line += r.sleb().toInt()
                DW_LNS.SET_FILE -> file = r.uleb().toInt()
                DW_LNS.SET_COLUMN -> column = r.uleb().toInt()
                DW_LNS.NEGATE_STMT -> isStmt = !isStmt
                DW_LNS.SET_BASIC_BLOCK -> basicBlock = true
                DW_LNS.CONST_ADD_PC -> {
                    val adv = (255 - opcodeBase) / lineRange
                    address += (minInsnLen * (opIndex + adv)).toLong(); opIndex = 0
                }
                DW_LNS.FIXED_ADVANCE_PC -> { address += r.u16().toLong(); opIndex = 0 }
                DW_LNS.SET_PROLOGUE_END -> prologueEnd = true
                DW_LNS.EPILOGUE_BEGIN -> epilogueBegin = true
                DW_LNS.SET_ISA -> isa = r.uleb().toInt()
                else -> {
                    // 未知标准 opcode：按声明操作数个数跳过
                    val n = stdOpcodeLengths.getOrElse(opcode) { 0 }
                    repeat(n) { r.uleb() }
                }
            }
        }
        return LineProgram(offset, version, dwarf64, addressSize, segmentSize, directories, files, rows, sequences, cuOffset)
    }
}
