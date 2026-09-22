package compass.fixture

import java.io.ByteArrayOutputStream

/**
 * Builds one .debug_line program (v4 or v5 header) with a small opcode DSL.
 * Files are indexed 0..n-1 in v5, 1..n in v4.
 */
class LineProgramBuilder(private val fx: DwarfFixture) {
    data class FileEntry(val name: String, val dir: String = "")

    val files = ArrayList<FileEntry>()
    private val ops = ByteArrayOutputStream()
    private var defaultIsStmt = 1
    private var lineBase = -5
    private var lineRange = 14
    private var minInsnLen = 1
    private var maxOpsPerInsn = 1

    fun file(name: String, dir: String = ""): Int {
        files.add(FileEntry(name, dir))
        return if (fx.version >= 5) files.size - 1 else files.size
    }

    fun setAddress(addr: Long) {
        ops.write(0)
        val payload = ByteArrayOutputStream()
        payload.write(2) // LNE_set_address
        if (fx.addressSize == 8) DwarfFixture.writeU64(payload, addr)
        else DwarfFixture.writeU32(payload, addr)
        DwarfFixture.writeUleb(ops, payload.size().toLong())
        ops.write(payload.toByteArray())
    }

    fun copy() = ops.write(1) // LNS_copy
    fun advancePc(n: Long) {
        ops.write(2); DwarfFixture.writeUleb(ops, n)
    }
    fun constAddPc() = ops.write(8)
    fun advanceLine(n: Long) {
        ops.write(3); DwarfFixture.writeSleb(ops, n)
    }
    fun setFile(idx: Long) { ops.write(4); DwarfFixture.writeUleb(ops, idx) }
    fun setColumn(c: Long) { ops.write(5); DwarfFixture.writeUleb(ops, c) }
    fun negateStmt() = ops.write(6)
    fun fixedAdvancePc(v: Int) { ops.write(9); DwarfFixture.writeU16(ops, v.toLong() and 0xffff) }
    fun setDiscriminator(d: Long) {
        ops.write(0)
        val payload = ByteArrayOutputStream()
        payload.write(4); DwarfFixture.writeUleb(payload, d)
        DwarfFixture.writeUleb(ops, payload.size().toLong())
        ops.write(payload.toByteArray())
    }

    /** Emit a special opcode that yields (lineDelta, addrAdvance) if representable. */
    fun special(lineDelta: Int, addrAdvance: Long = 0) {
        val opcodeBase = 13
        val adjusted = lineDelta - lineBase
        require(adjusted in 0 until lineRange) { "lineDelta $lineDelta outside special range" }
        val opAdv = addrAdvance / (minInsnLen.toLong() * maxOpsPerInsn.toLong())
        val opcode = opcodeBase + (lineRange * opAdv.toInt()) + adjusted
        require(opcode in opcodeBase..255) { "special opcode $opcode out of range" }
        ops.write(opcode)
    }

    fun endSequence() {
        ops.write(0); DwarfFixture.writeUleb(ops, 1); ops.write(1)
    }

    fun build(version: Int, addressSize: Int): ByteArray {
        val header = ByteArrayOutputStream()
        writeU16(header, version)
        if (version >= 5) {
            header.write(addressSize)
            header.write(0) // segment selector size
        }
        header.write(maxOpsPerInsn)
        header.write(minInsnLen)
        header.write(defaultIsStmt)
        header.write(lineBase)
        header.write(lineRange)
        val opcodeBase = 13
        header.write(opcodeBase)
        // standard opcode lengths (index 1..12)
        header.write(0) // copy
        header.write(1) // advance_pc
        header.write(1) // advance_line
        header.write(1) // set_file
        header.write(1) // set_column
        header.write(0) // negate_stmt
        header.write(0) // set_basic_block
        header.write(0) // const_add_pc
        header.write(1) // fixed_advance_pc
        header.write(0) // prologue_end
        header.write(0) // epilogue_begin
        header.write(1) // set_isa

        if (version <= 4) {
            // include directories: one entry CWD then terminator
            header.write(0)
            // file names
            for (f in files) {
                header.write(f.name.toByteArray()); header.write(0)
                DwarfFixture.writeUleb(header, 0) // dir index
                DwarfFixture.writeUleb(header, 0) // mtime
                DwarfFixture.writeUleb(header, 0) // size
            }
            header.write(0)
        } else {
            // directories: one entry via path (line_strp would need section; use FORM_string)
            header.write(1) // directory_entry_format_count
            DwarfFixture.writeUleb(header, 1) // DW_LNCT_path
            header.write(0x08) // DW_FORM_string
            DwarfFixture.writeUleb(header, 1) // directories_count
            header.write("/tmp".toByteArray()); header.write(0)

            // file names
            header.write(1) // file_name_entry_format_count
            DwarfFixture.writeUleb(header, 1) // path
            header.write(0x08) // FORM_string
            DwarfFixture.writeUleb(header, files.size.toLong())
            for (f in files) {
                header.write(f.name.toByteArray()); header.write(0)
            }
        }

        val out = ByteArrayOutputStream()
        val payloadLen = header.size() + ops.size()
        DwarfFixture.writeU32(out, payloadLen.toLong() and 0xffffffffL)
        out.write(header.toByteArray())
        out.write(ops.toByteArray())
        return out.toByteArray()
    }

    private fun writeU16(out: ByteArrayOutputStream, v: Int) {
        out.write(v and 0xff); out.write((v ushr 8) and 0xff)
    }
}
