@file:Suppress("ArrayInDataClass")
package compass.fixture

/**
 * Builds .debug_line programs for fixtures.
 */
class LineProgramBuilder(val version: Int) {
    var minInstructionLength = 1
    var maxOpsPerInstruction = 1
    var defaultIsStmt = true
    var lineBase = -5
    var lineRange = 14
    var opcodeBase = 13
    var addressSize = 8
    var segmentSelectorSize = 0

    // v4 tables
    private val v4Dirs = ArrayList<String>()
    private data class V4File(val name: String, val dirIdx: Int, val mtime: Long = 0, val size: Long = 0)
    private val v4Files = ArrayList<V4File>()
    // v5 tables
    private data class V5File(val path: String, val dirIdx: Int = 0, val size: Long = 0, val mtime: Long = 0)
    private val v5Dirs = ArrayList<String>()
    private val v5Files = ArrayList<V5File>()

    private val body = BytesBuilder()

    fun v4Dir(name: String) = apply { v4Dirs += name }
    fun v4File(name: String, dirIdx: Int = 0) = apply { v4Files += V4File(name, dirIdx) }
    fun v5Dir(path: String) = apply { v5Dirs += path }
    fun v5File(path: String, dirIdx: Int = 0) = apply { v5Files += V5File(path, dirIdx) }

    // ---- opcodes ----
    fun copy() = apply { body.u8(1) }
    fun advancePc(v: Long) = apply { body.u8(2).uleb(v) }
    fun advanceLine(v: Long) = apply { body.u8(3).sleb(v) }
    fun setFile(index: Long) = apply { body.u8(4).uleb(index) }
    fun setColumn(v: Long) = apply { body.u8(5).uleb(v) }
    fun negateStmt() = apply { body.u8(6) }
    fun setBasicBlock() = apply { body.u8(7) }
    fun constAddPc() = apply { body.u8(8) }
    fun setPrologueEnd() = apply { body.u8(10) }
    fun special(op: Int) = apply { body.u8(op) }
    fun extended(bytes: ByteArray) = apply {
        body.u8(0).uleb(bytes.size.toLong()).bytes(bytes)
    }
    fun setAddress(addr: Long, segment: Int? = null): LineProgramBuilder {
        // content = sub-opcode byte + optional segment selector + address; length excludes itself
        val b = BytesBuilder().u8(2)
        if (version >= 5 && segment != null && segmentSelectorSize > 0) {
            when (segmentSelectorSize) {
                1 -> b.u8(segment)
                2 -> b.u16(segment)
                4 -> b.u32(segment.toLong())
                8 -> b.u64(segment.toLong())
                else -> error("bad selector size")
            }
        }
        b.u64(addr)
        val content = b.build()
        body.u8(0).uleb(content.size.toLong()).bytes(content)
        return this
    }
    fun endSequence() = apply { extended(byteArrayOf(1)) }
    fun raw(b: ByteArray) = apply { body.bytes(b) }

    fun build(): ByteArray {
        val prologue = BytesBuilder()
        if (version >= 5) {
            prologue.u8(addressSize).u8(segmentSelectorSize)
            prologue.u32(0) // placeholder: header_length
            val proEndPos = prologue.size - 4
            prologue.u8(minInstructionLength)
            prologue.u8(maxOpsPerInstruction)
            prologue.u8(if (defaultIsStmt) 1 else 0)
            prologue.u8(lineBase and 0xff)
            prologue.u8(lineRange)
            prologue.u8(opcodeBase)
            // standard opcode lengths for opcodes 1..opcodeBase-1
            val stdLens = v5StdLengths()
            for (l in stdLens) prologue.u8(l)
            // directories: one entry-format (DW_LNCT_path=1, DW_FORM_string=8)
            prologue.u8(1).uleb(1).uleb(8)
            prologue.uleb(v5Dirs.size.toLong())
            for (d in v5Dirs) prologue.str(d)
            // files: path(DW_FORM_string) + directory index(DW_LNCT_directory=2, udata)
            prologue.u8(2).uleb(1).uleb(8).uleb(2).uleb(0x0f)
            prologue.uleb(v5Files.size.toLong())
            for (f in v5Files) { prologue.str(f.path).uleb(f.dirIdx.toLong()) }
            val proBytes = prologue.build()
            // patch prologue length placeholder (4 bytes)
            val len = proBytes.size - (proEndPos + 4)
            for (i in 0..3) proBytes[proEndPos + i] = ((len ushr (i * 8)) and 0xff).toByte()
            val hdr = BytesBuilder().u16(version).bytes(proBytes).build()
            return dwarf32Unit(hdr + body.build())
        } else {
            prologue.u8(minInstructionLength)
            if (version >= 4) prologue.u8(if (defaultIsStmt) 1 else 0)
            prologue.u8(lineBase and 0xff).u8(lineRange).u8(opcodeBase)
            val stdLens = v4StdLengths()
            for (l in stdLens) prologue.u8(l)
            for (d in v4Dirs) prologue.str(d)
            prologue.u8(0)
            for (f in v4Files) {
                prologue.str(f.name).uleb(f.dirIdx.toLong()).uleb(f.mtime).uleb(f.size)
            }
            prologue.u8(0)
            val proBytes = prologue.build()
            val hdr = BytesBuilder().u16(version).u32(proBytes.size.toLong()).bytes(proBytes).build()
            return dwarf32Unit(hdr + body.build())
        }
    }


    private fun v5StdLengths(): IntArray = intArrayOf(
        0, // 1 copy
        1, // 2 advance_pc
        1, // 3 advance_line
        1, // 4 set_file
        1, // 5 set_column
        0, // 6 negate_stmt
        0, // 7 set_basic_block
        0, // 8 const_add_pc
        1, // 9 fixed_advance_pc
        0, // 10 set_prologue_end
        1, // 11 set_isa
        0  // 12 set_epilogue_begin
    )

    private fun v4StdLengths(): IntArray = intArrayOf(
        0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0
    )
}
