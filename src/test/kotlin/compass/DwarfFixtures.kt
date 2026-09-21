package compass

import compass.dwarf.DW_AT
import compass.dwarf.DW_FORM
import compass.dwarf.DW_LNE
import compass.dwarf.DW_LNS
import compass.dwarf.DW_TAG

/**
 * Hand-built minimal DWARF 4 compile unit:
 *   DW_TAG_compile_unit (name, comp_dir, low_pc, stmt_list)
 *     DW_TAG_subprogram [name, low_pc, high_pc...]
 *       optional DW_TAG_inlined_subroutine children
 */
class Dwarf4Fixture(
    val base: Long = 0x401000,
    val fileName: String = "hello.c",
    val dirName: String = "/proj/src"
) {
    var abbrevData = ByteArray(0)
    var infoData = ByteArray(0)
    var lineData = ByteArray(0)
    var rangesData: ByteArray? = null
    var strData: ByteArray? = null
    var textBase: Long = base

    // abbrev table layout
    private var abbrevCode = 1
    private val abbrev = BinBuilder()
    private val abbrevOffsets = HashMap<String, Long>()
    private var done = false

    // ---- line program ----
    /** program bytes; sequence auto-ended */
    fun lineProgram(
        startAddr: Long,
        rows: List<LineRowSpec>,
        endAddr: Long,
        file: String = fileName,
        dir: String = dirName,
        dwarfVersion: Int = 4
    ): ByteArray {
        val prog = BinBuilder()
        // set address
        prog.u8(0).uleb(1 + 8).u8(DW_LNE.SET_ADDRESS).u64(startAddr)
        var curAddr = startAddr
        var curLine = 1
        var curCol = 0
        var curFile = if (dwarfVersion >= 5) 0 else 1
        for (r in rows) {
            if (r.address != curAddr) {
                val delta = (r.address - curAddr).toInt()
                if (delta != 0) prog.u8(DW_LNS.ADVANCE_PC).uleb(delta.toLong())
                curAddr = r.address
            }
            if (r.line != curLine) {
                prog.u8(DW_LNS.ADVANCE_LINE).sleb((r.line - curLine).toLong()); curLine = r.line
            }
            if (r.column != curCol) {
                prog.u8(DW_LNS.SET_COLUMN).uleb(r.column.toLong()); curCol = r.column
            }
            if (dwarfVersion < 5 && r.fileId != null && r.fileId != curFile) {
                prog.u8(DW_LNS.SET_FILE).uleb(r.fileId.toLong()); curFile = r.fileId
            }
            prog.u8(DW_LNS.COPY)
        }
        if (endAddr != curAddr) {
            // end_sequence uses DW_LNE_set_address semantics: last row address becomes end
            val delta = (endAddr - curAddr).toInt()
            if (delta > 0) prog.u8(DW_LNS.ADVANCE_PC).uleb(delta.toLong())
        }
        prog.u8(0).uleb(1).u8(DW_LNE.END_SEQUENCE)
        val program = prog.build()

        val header = BinBuilder()
        header.u16(dwarfVersion)
        if (dwarfVersion >= 5) { header.u8(8); header.u8(0) } // address_size, segment_selector_size
        // header_length placeholder
        val hlPos = header.size
        header.u32(0)
        val prologue = BinBuilder()
        prologue.u8(1) // min_insn_length
        if (dwarfVersion >= 5) prologue.u8(1) // max_ops_per_insn
        prologue.u8(1) // default_is_stmt
        prologue.bytes(0) // line_base -5
        prologue.u8(14) // line_range
        prologue.u8(13) // opcode_base
        // standard_opcode_lengths for 1..12
        prologue.bytes(0,1,1,1,1,0,0,0,1,0,0,1)
        if (dwarfVersion >= 5) {
            // include_directories: count 0
            prologue.u8(0)
            // file_names: 1 entry, 1 format (path, line_strp/string)
            prologue.u8(1)            // file_name_entry_format_count
            prologue.u16(0x01)       // DW_LNCT_path
            prologue.u16(DW_FORM.STRING)
            prologue.u32(1)          // file count
            prologue.str(file)
        } else {
            prologue.str(dir)
            prologue.str("")
            prologue.str(file)
            prologue.uleb(1).uleb(0).uleb(0)
            prologue.str("")
        }
        val pb = prologue.build()
        // patch header_length
        header.u32(0) // no-op? need patch: rewrite via fresh builder
        val fullHeader = BinBuilder()
        fullHeader.u16(dwarfVersion)
        if (dwarfVersion >= 5) { fullHeader.u8(8); fullHeader.u8(0) }
        fullHeader.u32(pb.size.toLong())
        fullHeader.blob(pb)
        return dwarfUnit { blob(fullHeader.build()); blob(program) }
    }

    /** Emit a second independent sequence in the same .debug_line blob. */
    fun multiSequenceLine(seqs: List<Triple<Long, List<LineRowSpec>, Long>>): ByteArray {
        // Multiple sequences live inside ONE line program unit (one header).
        val prog = BinBuilder()
        var curAddr = 0L; var curLine = 1
        for ((start, rows, end) in seqs) {
            prog.u8(0).uleb(9).u8(DW_LNE.SET_ADDRESS).u64(start)
            curAddr = start; curLine = 1
            for (r in rows) {
                if (r.address != curAddr) prog.u8(DW_LNS.ADVANCE_PC).uleb((r.address-curAddr))
                curAddr = r.address
                if (r.line != curLine) prog.u8(DW_LNS.ADVANCE_LINE).sleb((r.line-curLine).toLong())
                curLine = r.line
                if (r.column != 0) prog.u8(DW_LNS.SET_COLUMN).uleb(r.column.toLong())
                prog.u8(DW_LNS.COPY)
            }
            if (end != curAddr) prog.u8(DW_LNS.ADVANCE_PC).uleb((end-curAddr))
            prog.u8(0).uleb(1).u8(DW_LNE.END_SEQUENCE)
        }
        val prologue = BinBuilder()
        prologue.u8(1).u8(1).bytes(0).u8(14).u8(13)
        prologue.bytes(0,1,1,1,1,0,0,0,1,0,0,1)
        prologue.str(dirName).str("")
        prologue.str(fileName).uleb(1).uleb(0).uleb(0).str("")
        val pb = prologue.build()
        val hdr = BinBuilder().u16(4).u32(pb.size.toLong()).blob(pb).build()
        return dwarfUnit { blob(hdr); blob(prog.build()) }
    }

    /**
     * Build info+abbrev for CU with subprograms. `specs` describe DIEs in pre-order.
     */
    fun cuWithDies(specs: List<DieSpec>, lineOffset: Long = 0,
                   cuLowPc: Long = base, extraCuAttrs: List<Triple<Int, Int, Any>> = emptyList()): Dwarf4Fixture {
        // Abbrev codes: 1=CU, 2=subprogram(high=addr), 3=subprogram(high=const),
        // 4=inlined_subroutine, 5=CU with ranges
        val ab = BinBuilder()
        // code 1: CU
        ab.uleb(1).uleb(DW_TAG.COMPILATION_UNIT).u8(1)
        ab.uleb(DW_AT.NAME).uleb(DW_FORM.STRING)
        ab.uleb(DW_AT.COMP_DIR).uleb(DW_FORM.STRING)
        ab.uleb(DW_AT.LOW_PC).uleb(DW_FORM.ADDR)
        ab.uleb(DW_AT.STMT_LIST).uleb(DW_FORM.SEC_OFFSET)
        for ((a,f,_) in extraCuAttrs) ab.uleb(a).uleb(f)
        ab.uleb(0).uleb(0)
        var code = 2
        val codeByKind = HashMap<String, Int>()
        fun hasChildWithKind(list: List<DieSpec>, kind: String): Boolean =
            list.any { it.kind == kind && it.children.isNotEmpty() } ||
                list.any { hasChildWithKind(it.children, kind) }
        for (kind in specs.map { it.kind }.distinct()) {
            ab.uleb(code.toLong()).uleb(tagFor(kind)).u8(if (hasChildWithKind(specs, kind)) 1 else 0)
            emitAbbrevAttrs(ab, kind, specs.first { it.kind == kind })
            ab.uleb(0).uleb(0)
            codeByKind[kind] = code++
        }
        ab.uleb(0)
        abbrevData = ab.build()

        val body = BinBuilder()
        body.u16(4)               // version
        body.u32(0)               // debug_abbrev_offset
        body.u8(8)                // address_size
        // root DIE abbrev 1
        body.uleb(1).str(fileName).str(dirName).u64(cuLowPc).u32(lineOffset)
        for ((_,_,v) in extraCuAttrs) emitAttrValue(body, v)
        emitDies(body, specs, codeByKind)
        body.uleb(0) // end children of CU
        infoData = dwarfUnit { blob(body.build()) }
        return this
    }

    private fun emitDies(body: BinBuilder, specs: List<DieSpec>, codes: Map<String, Int>,
                          childKinds: Map<String, Boolean> = emptyMap()) {
        fun kindHasChildren(kind: String): Boolean = childKinds[kind]
            ?: specs.any { it.kind == kind && it.children.isNotEmpty() }
        for (spec in specs) {
            body.uleb(codes[spec.kind]!!.toLong())
            emitDieAttrs(body, spec)
            if (spec.children.isNotEmpty()) {
                emitDies(body, spec.children, codes, childKinds)
                body.uleb(0) // close children block
            } else if (kindHasChildren(spec.kind)) {
                // abbrev declares children but this instance has none -> still needs terminator
                body.uleb(0)
            }
        }
    }

    private fun emitAbbrevAttrs(ab: BinBuilder, kind: String, sample: DieSpec) {
        ab.uleb(DW_AT.NAME).uleb(if (kind.endsWith("Inline")) DW_FORM.STRING else DW_FORM.STRING)
        ab.uleb(DW_AT.LOW_PC).uleb(DW_FORM.ADDR)
        when (sample.highKind) {
            HighKind.ADDR -> ab.uleb(DW_AT.HIGH_PC).uleb(DW_FORM.ADDR)
            HighKind.CONST -> ab.uleb(DW_AT.HIGH_PC).uleb(DW_FORM.UDATA)
            HighKind.RANGES -> ab.uleb(DW_AT.RANGES).uleb(DW_FORM.SEC_OFFSET)
            HighKind.NONE -> {}
        }
        if (sample.declLine != null) {
            ab.uleb(DW_AT.DECL_LINE).uleb(DW_FORM.UDATA)
            ab.uleb(DW_AT.DECL_COLUMN).uleb(DW_FORM.UDATA)
        }
        if (kind.endsWith("Inline")) {
            ab.uleb(DW_AT.CALL_FILE).uleb(DW_FORM.UDATA)
            ab.uleb(DW_AT.CALL_LINE).uleb(DW_FORM.UDATA)
            ab.uleb(DW_AT.CALL_COLUMN).uleb(DW_FORM.UDATA)
        }
    }

    private fun emitDieAttrs(body: BinBuilder, spec: DieSpec) {
        body.str(spec.name).u64(spec.low)
        when (spec.highKind) {
            HighKind.ADDR -> body.u64(spec.high)
            HighKind.CONST -> body.uleb(spec.high - spec.low)
            HighKind.RANGES -> body.u32(spec.rangesOffset)
            HighKind.NONE -> {}
        }
        if (spec.declLine != null) { body.uleb(spec.declLine.toLong()).uleb((spec.declColumn ?: 0).toLong()) }
        if (spec.kind.endsWith("Inline")) {
            body.uleb(1).uleb(spec.callLine.toLong()).uleb((spec.callColumn ?: 0).toLong())
        }
    }

    private fun emitAttrValue(body: BinBuilder, v: Any) = when (v) {
        is Long -> body.u64(v)
        is Int -> body.u32(v.toLong())
        is String -> body.str(v)
        else -> error("unsupported attr $v")
    }

    private fun tagFor(kind: String) = when {
        kind == "sub" -> DW_TAG.SUBPROGRAM
        kind.endsWith("Inline") -> 29
        kind == "block" -> 11
        else -> DW_TAG.SUBPROGRAM
    }
}

data class LineRowSpec(
    val address: Long, val line: Int, val column: Int = 0, val fileId: Int? = null
)

enum class HighKind { ADDR, CONST, RANGES, NONE }

data class DieSpec(
    val kind: String, val name: String, val low: Long, val high: Long,
    val highKind: HighKind = if (high != 0L) HighKind.CONST else HighKind.NONE,
    val rangesOffset: Long = 0,
    val declLine: Int? = null, val declColumn: Int? = null,
    val callLine: Int = 0, val callColumn: Int? = null,
    val children: List<DieSpec> = emptyList()
)
