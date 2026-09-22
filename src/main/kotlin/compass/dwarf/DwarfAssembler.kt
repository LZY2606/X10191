package compass.dwarf

/**
 * 最小 DWARF 汇编器：为测试/演示手工生成 .debug_abbrev / .debug_info / .debug_line 等。
 * 不依赖系统工具链；每个不同 (tag, hasChildren, attrs 形状) 自动生成一条 abbrev。
 */
class Attr(val attr: Int, val form: Int, val bytes: ByteArray = ByteArray(0), val implicit: Long? = null)

object Attrs {
    fun addr(v: Long, size: Int = 4): Attr {
        val b = ByteBuilder()
        when (size) { 1 -> b.u8(v.toInt()); 2 -> b.u16(v.toInt()); 4 -> b.u32(v); 8 -> b.u64(v) }
        return Attr(DW.AT_LOW_PC, DW.FORM_ADDR, b.build())
    }
    fun custom(attr: Int, form: Int, bytes: ByteArray = ByteArray(0), implicit: Long? = null) = Attr(attr, form, bytes, implicit)
    fun data(attr: Int, v: Long, bytes: Int): Attr {
        val b = ByteBuilder()
        when (bytes) { 1 -> b.u8(v.toInt()); 2 -> b.u16(v.toInt()); 4 -> b.u32(v); 8 -> b.u64(v) }
        return Attr(attr, mapDataForm(bytes), b.build())
    }
    private fun mapDataForm(n: Int) = when (n) { 1 -> DW.FORM_DATA1; 2 -> DW.FORM_DATA2; 4 -> DW.FORM_DATA4; else -> DW.FORM_DATA8 }
    fun udata(attr: Int, v: Long) = Attr(attr, DW.FORM_UDATA, ByteBuilder().uleb(v).build())
    fun flagPresent(attr: Int) = Attr(attr, DW.FORM_FLAG_PRESENT)
    fun strp(attr: Int, offset: Long) = Attr(attr, DW.FORM_STRP, ByteBuilder().u32(offset).build())
    fun lineStrp(attr: Int, offset: Long) = Attr(attr, DW.FORM_LINE_STRP, ByteBuilder().u32(offset).build())
    fun secOffset(attr: Int, offset: Long) = Attr(attr, DW.FORM_SEC_OFFSET, ByteBuilder().u32(offset).build())
    fun string(attr: Int, s: String) = Attr(attr, DW.FORM_STRING, ByteBuilder().cstr(s).build())
    fun refAddr(offset: Long) = Attr(DW.AT_ABSTRACT_ORIGIN, DW.FORM_REF_ADDR, ByteBuilder().u32(offset).build())
    fun refAddrAttr(attr: Int, offset: Long) = Attr(attr, DW.FORM_REF_ADDR, ByteBuilder().u32(offset).build())
}

/** 单个 CU 的汇编器。unitStart 为该 CU 在 .debug_info 中的全局偏移（ref 换算用）。 */
class UnitAssembler(val version: Int, val unitStart: Long, val addressSize: Int = 4, val is64: Boolean = false) {
    val body = ByteBuilder()
    val abbrev = ByteBuilder()
    private val shapeCodes = HashMap<String, Long>()
    private var nextCode = 1L
    private var depth = 0
    val refPatches = mutableListOf<Triple<Int, Int, Long>>() // body pos, size, target

    private data class Shape(val tag: Int, val children: Boolean, val attrs: List<Pair<Int, Int>>, val implicit: Map<Int, Long>)

    private fun shapeCode(tag: Int, children: Boolean, attrs: List<Attr>): Long {
        val key = tag.toString() + "|" + children + "|" + attrs.joinToString(",") { "${it.attr}:${it.form}:${it.implicit}" }
        return shapeCodes.getOrPut(key) {
            val code = nextCode++
            abbrev.uleb(code).uleb(tag.toLong()).u8(if (children) 1 else 0)
            for (a in attrs) {
                abbrev.uleb(a.attr.toLong()).uleb(a.form.toLong())
                if (a.form == DW.FORM_IMPLICIT_CONST) abbrev.sleb(a.implicit ?: 0L)
            }
            abbrev.uleb(0).uleb(0)
            code
        }
    }

    /** DIE 在 .debug_info 中的当前全局偏移。 */
    fun currentOffset(): Long = unitStart + headerLength() + body.size

    private fun headerLength(): Int = if (version >= 5) (if (is64) 24 else 11) else (if (is64) 23 else 10)

    /** 写一个 ref（CU 相对 ref4 或全局 ref_addr），目标偏移稍后可回填。返回 patch 句柄。 */
    fun ref4Placeholder(attr: Int): Int {
        body.uleb(0) // replaced? no — need code & attrs order first; caller must place via begin() attrs
        return -1
    }

    fun begin(tag: Int, attrs: List<Attr> = emptyList(), children: Boolean = false) {
        val code = shapeCode(tag, children, attrs)
        body.uleb(code)
        for (a in attrs) body.bytes(a.bytes)
        if (children) depth++
    }

    fun endChildren() {
        body.uleb(0)
        depth--
    }

    fun finish(): ByteArray {
        check(depth == 0) { "DIE 子节点未闭合: $depth" }
        val h = ByteBuilder()
        if (version >= 5) {
            // length(4) version(2) utype(1) asize(1) abbrev(4)
            val len = 11 - 4 + body.size
            h.u32(len.toLong()).u16(version).u8(1).u8(addressSize).u32(0)
        } else {
            val len = 10 - 4 + body.size
            h.u32(len.toLong()).u16(version).u32(0).u8(addressSize)
        }
        return h.build() + body.build()
    }
}

/**
 * .debug_line 汇编器：固定使用 set_address + set_file + 行列增量 + copy，
 * 并可在某步插入 special opcode 以覆盖 special-opcode 解析路径。
 */
class LineAssembler(
    val version: Int = 4,
    val compDir: String = "/proj",
    val fileNames: List<String> = listOf("main.c"),
    val lineBase: Int = -5,
    val lineRange: Int = 14,
    val opcodeBase: Int = 13,
    val stdLengths: List<Int> = listOf(0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1),
    val addressSize: Int = 4,
    val segmentSize: Int = 0
) {
    data class Step(val address: Long, val line: Int, val column: Int = 0, val file: Int = 1,
                    val special: Boolean = false, val stmt: Boolean? = null)

    private val lineStr = ByteBuilder()
    private val lineStrOffsets = LinkedHashMap<String, Long>()
    private fun lineStrOff(s: String): Long = lineStrOffsets.getOrPut(s) {
        val o = lineStr.size.toLong(); lineStr.cstr(s); o
    }

    /** 生成一个完整 sequence；endAddr 为 end_sequence 的终止地址。 */
    fun sequence(base: Long, steps: List<Step>, endAddr: Long, segment: Long = 0): ByteArray {
        val program = ByteBuilder()
        fun fixedAddr(v: Long) {
            when (addressSize) { 1 -> program.u8(v.toInt()); 2 -> program.u16(v.toInt()); 4 -> program.u32(v); 8 -> program.u64(v) }
        }
        // extended set_address: len, 2, addr
        val addrLen = addressSize + (if (version >= 5) segmentSize else 0)
        program.u8(0).uleb((2 + addrLen).toLong()).u8(DW.LNE_SET_ADDRESS)
        if (version >= 5 && segmentSize > 0) when (segmentSize) { 1 -> program.u8(segment.toInt()); 4 -> program.u32(segment); else program.u64(segment) }
        fixedAddr(base)

        var curAddr = base
        var curLine = 1
        var curFile = 1
        var curCol = 0
        var curStmt = true
        for (st in steps) {
            if (st.file != curFile) { program.u8(DW.LN_SET_FILE); program.uleb(st.file.toLong()); curFile = st.file }
            val dLine = st.line - curLine
            val dAddr = st.address - curAddr
            if (st.special && dAddr % 1 == 0L) {
                val advOp = (dAddr / 1).toInt()
                val adjLine = dLine - lineBase
                val spec = opcodeBase + advOp * lineRange + adjLine
                require(spec in opcodeBase..255) { "special opcode 越界: $spec (dLine=$dLine advOp=$advOp)" }
                program.u8(spec)
            } else {
                if (dAddr != 0L) { program.u8(DW.LN_ADVANCE_PC); program.uleb(dAddr) }
                if (dLine != 0) { program.u8(DW.LN_ADVANCE_LINE); program.sleb(dLine.toLong()) }
                if (st.column != curCol) { program.u8(DW.LN_SET_COLUMN); program.uleb(st.column.toLong()); curCol = st.column }
                if (st.stmt != null && st.stmt != curStmt) { program.u8(DW.LN_NEGATE_STMT); curStmt = st.stmt!! }
                program.u8(DW.LN_COPY)
            }
            curAddr = st.address
            curLine = st.line
        }
        program.u8(0).uleb((2 + addrLen).toLong()).u8(DW.LNE_END_SEQUENCE)
        if (version >= 5 && segmentSize > 0) when (segmentSize) { 1 -> program.u8(segment.toInt()); 4 -> program.u32(segment); else program.u64(segment) }
        fixedAddr(endAddr)
        return wrap(program.build())
    }

    private fun wrap(program: ByteArray): ByteArray {
        val h = ByteBuilder()
        if (version >= 5) {
            // header contents after unit length
            val hdr = ByteBuilder()
            hdr.u16(5).u8(addressSize).u8(segmentSize)
            hdr.u8(1) // minimum_instruction_length
            hdr.u8(1) // maximum_operations_per_instruction
            hdr.u8(if (true) 1 else 0) // default_is_stmt
            hdr.u8(lineBase.toByte().toInt() and 0xff)
            hdr.u8(lineRange)
            hdr.u8(opcodeBase)
            stdLengths.forEach { hdr.u8(it) }
            // directories: entry_format = 1 (LNCT_path, line_strp); count=1
            hdr.u8(1).uleb(0x1).uleb(DW.FORM_LINE_STRP.toLong())
            hdr.uleb(1).u32(lineStrOff(compDir))
            // files: entry_format = 2 (path line_strp, directory_index data1)
            hdr.u8(2).uleb(0x1).uleb(DW.FORM_LINE_STRP.toLong()).uleb(0x2).uleb(DW.FORM_DATA1.toLong())
            hdr.uleb(fileNames.size.toLong())
            fileNames.forEach { hdr.u32(lineStrOff(it)).u8(1) }
            val hb = hdr.build()
            h.u32((hb.size + program.size).toLong())
            return h.build() + hb + program
        } else {
            val hdr = ByteBuilder()
            hdr.u16(version)
            hdr.u8(1) // min insn
            hdr.u8(if (true) 1 else 0)
            hdr.u8(lineBase.toByte().toInt() and 0xff)
            hdr.u8(lineRange)
            hdr.u8(opcodeBase)
            stdLengths.forEach { hdr.u8(it) }
            hdr.cstr(compDir)
            hdr.u8(0)
            fileNames.forEachIndexed { i, n -> hdr.cstr(n).uleb(1).uleb(0).uleb(0) }
            hdr.u8(0)
            val hb = hdr.build()
            h.u32((hb.size + program.size).toLong())
            return h.build() + hb + program
        }
    }

    fun lineStrSection(): ByteArray = lineStr.build()
    fun hasLineStr(): Boolean = lineStr.size > 0
}
