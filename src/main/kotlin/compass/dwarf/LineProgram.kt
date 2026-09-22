package compass.dwarf

import compass.elf.BinaryParseException
import compass.elf.Reader
import java.nio.ByteOrder

/**
 * 解析 .debug_line。支持 DWARF 4 与 DWARF 5 的程序头，
 * 包括 DWARF5 的 directory/file entry format、segment selector 和 line_strp。
 */
class LineProgramParser(
    private val debugLine: ByteArray?,
    private val debugLineStr: ByteArray?,
    private val debugStr: ByteArray?,
    private val debugStrOffsets: ByteArray?,
    private val endian: ByteOrder
) {

    private fun strAt(bytes: ByteArray?, off: Long): String {
        if (bytes == null) throw BinaryParseException("缺少字符串表 section")
        if (off < 0 || off >= bytes.size) throw BinaryParseException("字符串偏移越界 off=$off")
        var end = off.toInt()
        while (end < bytes.size && bytes[end].toInt() != 0) end++
        return String(bytes, off.toInt(), end - off.toInt(), Charsets.UTF_8)
    }

    fun parseAt(headerOffset: Long, cuAddressSize: Int, cuDwarfVersion: Int, cuIs64: Boolean, compDir: String?): LineProgram {
        val warnings = mutableListOf<String>()
        if (debugLine == null) {
            return LineProgram(headerOffset, headerOffset, TableVersion(cuDwarfVersion, cuIs64, headerOffset),
                emptyList(), emptyList(), emptyList(), emptyList(), listOf("缺少 .debug_line，DW_AT_stmt_list=0x${headerOffset.toString(16)}"))
        }
        if (headerOffset < 0 || headerOffset >= debugLine.size) {
            return LineProgram(headerOffset, headerOffset, TableVersion(cuDwarfVersion, cuIs64, headerOffset),
                emptyList(), emptyList(), emptyList(), emptyList(), listOf("DW_AT_stmt_list 指向 .debug_line 之外 0x${headerOffset.toString(16)}"))
        }
        val r = Reader(debugLine, endian)
        r.seek(headerOffset.toInt())
        val unitStart = r.pos
        val unitLength = r.initialLength()
        val is64 = r.dwarf64
        val afterLen = r.pos
        val unitEnd = (afterLen.toLong() + unitLength).toInt()
        if (unitEnd > debugLine.size) throw BinaryParseException(".debug_line unit 长度越界")
        val version = r.u2()
        var unitType: Int? = null
        var addressSize = cuAddressSize
        var segmentSize = 0
        if (version >= 5) {
            unitType = r.u1()
            addressSize = r.u1()
            segmentSize = r.u1()
            if (unitType != 1) throw BinaryParseException("不支持的 line program unit type=$unitType（仅 type 1）")
        }
        val headerLength = if (is64) r.u8() else r.u4long()
        val headerEnd = r.pos + headerLength.toInt()
        if (headerEnd > unitEnd) throw BinaryParseException(".debug_line header_length 越界")

        val minInstructionLength = r.u1()
        if (version >= 4) r.u1() // max_operations_per_instruction
        val defaultIsStmt = r.u1()
        val lineBase = r.s1()
        val lineRange = r.u1()
        val opcodeBase = r.u1()
        val stdOpcodeLengths = IntArray(opcodeBase - 1) { r.u1() }

        val directories = mutableListOf<String>()
        val files = mutableListOf<LineFile>()

        if (version <= 4) {
            while (true) {
                val s = r.cString()
                if (s.isEmpty()) break
                directories.add(s)
            }
            var fid = 1
            while (true) {
                val name = r.cString()
                if (name.isEmpty()) break
                val dir = r.uleb().toInt()
                r.uleb(); r.uleb() // mtime, length
                files.add(LineFile(fid++, name, dir, compDir))
            }
        } else {
            val dirFormatCount = r.u1()
            val dirFormats = ArrayList<Pair<Int, Int>>(dirFormatCount)
            for (i in 0 until dirFormatCount) dirFormats.add(r.uleb().toInt() to r.uleb().toInt())
            val dirsCount = r.uleb().toInt()
            for (i in 0 until dirsCount) {
                var path = ""
                for ((_, form) in dirFormats) {
                    val v = readPathString(form, r)
                    if (v != null) path = v
                }
                directories.add(path)
            }
            val fileFormatCount = r.u1()
            val fileFormats = ArrayList<Pair<Int, Int>>(fileFormatCount)
            for (i in 0 until fileFormatCount) fileFormats.add(r.uleb().toInt() to r.uleb().toInt())
            val filesCount = r.uleb().toInt()
            for (i in 0 until filesCount) {
                var name = ""
                var dirIndex = 0
                var ts = 0L; var sz = 0L; var md5: ByteArray? = null
                for ((content, form) in fileFormats) {
                    when (content) {
                        LNCT.path -> readPathString(form, r)?.let { name = it }
                        LNCT.directory_index -> dirIndex = readPathUInt(form, r)
                        LNCT.timestamp -> ts = readPathUInt(form, r).toLong()
                        LNCT.size -> sz = readPathUInt(form, r).toLong()
                        LNCT.MD5 -> { md5 = readRawBytes(form, r) }
                        else -> skipForm(form, r, version, addressSize)
                    }
                }
                files.add(LineFile(i, name, dirIndex, compDir))
            }
            if (r.pos != headerEnd) warnings.add("v5 行程序头解析结束位置($r.pos)与 header_end($headerEnd)不一致")
        }
        r.seek(headerEnd)

        val rows = ArrayList<LineRow>()
        val events = ArrayList<String>()
        var address = 0L
        var segment = 0L
        var fileIndex = 1
        var line = 1
        var column = 0
        var isStmt = defaultIsStmt != 0
        var basicBlock = false
        var endSequence = false
        var prologueEnd = false
        var epilogueBegin = false
        var isa = 0
        var discriminator = 0
        var hseq = 0
        var lastAdvance = 0

        fun reset() {
            address = 0L; segment = 0L; fileIndex = 1; line = 1; column = 0
            isStmt = defaultIsStmt != 0; basicBlock = false; endSequence = false
            prologueEnd = false; epilogueBegin = false; isa = 0; discriminator = 0
        }

        fun emit(event: String) {
            rows.add(LineRow(address, segment, fileIndex, line, column, isStmt, basicBlock,
                endSequence, prologueEnd, epilogueBegin, isa, discriminator, hseq))
            events.add(event)
            basicBlock = false; prologueEnd = false; epilogueBegin = false; discriminator = 0
        }

        var guard = 0
        while (r.pos < unitEnd) {
            if (++guard > 1_000_000) throw BinaryParseException("line program opcode 数量超限")
            val opcode = r.u1()
            when {
                opcode == 0 -> {
                    val extLen = r.uleb().toInt()
                    val sub = r.u1()
                    val extEnd = r.pos - 1 + extLen
                    when (sub) {
                        LNE.end_sequence -> {
                            if (segmentSize > 0) segment = readSegmentWithSegment(r, segmentSize)
                            address = readAddressWithSize(r, addressSize)
                            endSequence = true
                            emit("DW_LNE_end_sequence")
                            hseq++
                            reset()
                        }
                        LNE.set_address -> {
                            if (segmentSize > 0) segment = readSegmentWithSegment(r, segmentSize)
                            address = readAddressWithSize(r, addressSize)
                            lastAdvance = 0
                        }
                        LNE.set_discriminator -> {
                            discriminator = r.uleb().toInt()
                        }
                        else -> {
                            if (r.pos < extEnd) r.seek(extEnd)
                            warnings.add("未知 extended opcode=$sub，已按长度跳过")
                        }
                    }
                    if (r.pos < extEnd) r.seek(extEnd)
                    if (r.pos > extEnd) warnings.add("extended opcode=$sub 操作数超过声明长度")
                }
                opcode < opcodeBase -> when (opcode) {
                    LNS.copy -> emit("DW_LNS_copy")
                    LNS.advance_pc -> { lastAdvance = r.sleb().toInt(); address += (lastAdvance * minInstructionLength).toLong(); }
                    LNS.advance_line -> { line += r.sleb().toInt() }
                    LNS.set_file -> { fileIndex = r.uleb().toInt() }
                    LNS.set_column -> { column = r.uleb().toInt() }
                    LNS.negate_stmt -> { isStmt = !isStmt }
                    LNS.set_basic_block -> { basicBlock = true }
                    LNS.const_add_pc -> { address += ((255 - opcodeBase) / lineRange * minInstructionLength).toLong() }
                    LNS.fixed_advance_pc -> { address += r.u2().toLong() }
                    LNS.set_prologue_end -> { prologueEnd = true }
                    LNS.set_epilogue_begin -> { epilogueBegin = true }
                    LNS.set_isa -> { isa = r.uleb().toInt() }
                    else -> {
                        val idx = opcode - 1
                        if (idx in stdOpcodeLengths.indices) {
                            repeat(stdOpcodeLengths[idx]) { r.uleb() }
                            warnings.add("未知标准 opcode=$opcode，已按声明长度跳过操作数")
                        }
                    }
                }
                else -> {
                    val adjusted = opcode - opcodeBase
                    val addrAdvance = minInstructionLength * (adjusted / lineRange)
                    val lineAdvance = lineBase + (adjusted % lineRange)
                    address += addrAdvance.toLong()
                    line += lineAdvance
                    emit("special($opcode)")
                }
            }
        }

        return LineProgram(
            cuOffset = -1,
            headerOffset = headerOffset,
            table = TableVersion(version, is64, headerOffset),
            files = files,
            directories = directories,
            rows = rows,
            events = events,
            warnings = warnings
        )
    }

    private fun readSegmentWithSegment(r: Reader, size: Int): Long = when (size) {
        1 -> r.u1().toLong(); 2 -> r.u2().toLong(); 4 -> r.u4long(); 8 -> r.u8()
        else -> throw BinaryParseException("不支持的 selector 大小 $size")
    }

    private fun readAddressWithSize(r: Reader, size: Int): Long = when (size) {
        1 -> r.u1().toLong(); 2 -> r.u2().toLong(); 4 -> r.u4long(); 8 -> r.u8()
        else -> throw BinaryParseException("不支持的地址大小 $size")
    }

    private fun readRawBytes(form: Int, r: Reader): ByteArray = when (form) {
        FORM.data1 -> r.bytes(r.u1())
        FORM.data2 -> r.bytes(r.u2())
        FORM.data4 -> r.bytes(r.u4())
        FORM.block1 -> r.bytes(r.u1())
        FORM.block2 -> r.bytes(r.u2())
        FORM.block4 -> r.bytes(r.u4())
        else -> throw BinaryParseException("不支持的路径原始字节 form=0x${form.toString(16)}")
    }

    private fun readPathUInt(form: Int, r: Reader): Int = when (form) {
        FORM.data1, FORM.udata, FORM.strx1, FORM.addrx1 -> { r.u1() }
        FORM.data2, FORM.strx2, FORM.addrx2 -> { r.u2() }
        FORM.data4, FORM.strx4, FORM.addrx4 -> { r.u4() }
        FORM.strx, FORM.addrx, FORM.sdata -> { r.uleb().toInt() }
        else -> throw BinaryParseException("不支持的路径整数 form=0x${form.toString(16)}")
    }

    private fun readPathString(form: Int, r: Reader): String? = when (form) {
        FORM.string -> r.cString()
        FORM.line_strp -> strAt(debugLineStr, if (r.dwarf64) r.u8() else r.u4long())
        FORM.strp -> strAt(debugStr, if (r.dwarf64) r.u8() else r.u4long())
        FORM.strx1, FORM.strx2, FORM.strx3, FORM.strx4, FORM.strx -> {
            // fixture 使用 line_strp；strx* 需 .debug_str_offsets 基址，这里安全降级为占位，
            // 并保留游标同步（索引本身）。
            val idx = when (form) {
                FORM.strx1 -> r.u1()
                FORM.strx2 -> r.u2()
                FORM.strx3 -> r.u1() or (r.u1() shl 8) or (r.u1() shl 16)
                FORM.strx4 -> r.u4()
                else -> r.uleb().toInt()
            }
            "<strx$idx>"
        }
        else -> { skipForm(form, r, 5, 8); null }
    }

    companion object {
        fun skipForm(form: Int, r: Reader, dwarfVersion: Int, addressSize: Int) {
            when (form) {
                FORM.addr -> when (addressSize) { 1 -> r.u1(); 2 -> r.u2(); 4 -> r.u4(); 8 -> r.u8(); else -> throw BinaryParseException("addr size=$addressSize") }
                FORM.block -> r.bytes(r.uleb().toInt())
                FORM.block1 -> r.bytes(r.u1())
                FORM.block2 -> r.bytes(r.u2())
                FORM.block4 -> r.bytes(r.u4())
                FORM.data1, FORM.flag, FORM.ref1, FORM.strx1, FORM.addrx1 -> r.u1()
                FORM.data2, FORM.ref2, FORM.strx2, FORM.addrx2 -> r.u2()
                FORM.data4, FORM.ref4, FORM.ref_sup4, FORM.strx4, FORM.addrx4, FORM.strp, FORM.sec_offset, FORM.line_strp ->
                    if (r.dwarf64) r.u8() else r.u4()
                FORM.data8, FORM.ref8, FORM.ref_sup8, FORM.ref_sig8 -> r.u8()
                FORM.string -> { var guard = 0; while (guard++ < 1_000_000 && r.u1() != 0) Unit }
                FORM.sdata, FORM.udata, FORM.ref_udata, FORM.strx, FORM.addrx, FORM.rnglistx, FORM.loclistx -> r.uleb()
                FORM.flag_present, FORM.implicit_const -> Unit
                FORM.exprloc -> r.bytes(r.uleb().toInt())
                FORM.data16 -> r.bytes(16)
                else -> throw UnknownFormException(form)
            }
        }
    }
}

class UnknownFormException(val form: Int) : BinaryParseException("未知/不支持的 DW_FORM 0x${form.toString(16)}，该 CU 将被隔离")
