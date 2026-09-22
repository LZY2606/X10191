package compass.dwarf

import compass.ByteReader
import compass.DwarfFormatException

/**
 * Executes one line-number program, materialising rows and keeping a short human-readable
 * trace per row ("what opcode produced this state") so the UI can show state transitions.
 */
class LineMachine(
    private val prog: LineProgram,
    private val obj: DebugObject,
    private val is64: Boolean,
) {
    private class State(
        var address: Long = 0L,
        var segment: Long = 0L,
        var file: Int = 1,
        var line: Int = 1,
        var column: Int = 0,
        var isStmt: Boolean,
        var basicBlock: Boolean = false,
        var endSequence: Boolean = false,
        var prologueEnd: Boolean = false,
        var epilogueBegin: Boolean = false,
        var isa: Int = 0,
        var discriminator: Int = 0,
    )

    fun run(r: ByteReader, end: Int, issues: MutableList<DebugIssue>): List<LineSequence> {
        val sequences = mutableListOf<LineSequence>()
        var rows = mutableListOf<LineRow>()
        var state = State(isStmt = prog.defaultIsStatement)
        val opAdvance = prog.minimumInstructionLength.toLong().coerceAtLeast(1)
        var rowGuard = 0
        val trace = mutableListOf<String>()

        fun reset() {
            state = State(isStmt = prog.defaultIsStatement)
            trace.clear()
        }

        fun emitRow(why: String) {
            if (++rowGuard > 5_000_000) throw DwarfFormatException("line row limit exceeded")
            val t = (trace + why).toList()
            rows += LineRow(
                address = state.address, segment = state.segment, fileIndex = state.file,
                file = prog.file(state.file) ?: prog.file(state.file - 1),
                line = state.line, column = state.column, isStatement = state.isStmt,
                basicBlock = state.basicBlock, endSequence = state.endSequence,
                prologueEnd = state.prologueEnd, epilogueBegin = state.epilogueBegin,
                isa = state.isa, discriminator = state.discriminator, trace = t,
            )
        }

        while (r.pos < end) {
            val opcode = r.u8()
            when {
                opcode == 0 -> {
                    // extended opcode
                    val insnLen = r.uleb128().toInt()
                    val insnEnd = r.pos + insnLen
                    val sub = r.u8()
                    when (sub) {
                        DW.LNE_END_SEQUENCE -> {
                            state.endSequence = true
                            emitRow("extended: end_sequence @ 0x${state.address.toString(16)}")
                            sequences += LineSequence(prog, rows)
                            rows = mutableListOf()
                            reset()
                        }
                        DW.LNE_SET_ADDRESS -> {
                            // remainder of instruction: optional segment selector (v4 with
                            // segment_selector_size) then address of prog.addressSize bytes.
                            if (prog.version < 5 && prog.segmentSelectorSize > 0) {
                                state.segment = when (prog.segmentSelectorSize) {
                                    1 -> r.u8().toLong(); 2 -> r.u16().toLong()
                                    4 -> r.u32(); 8 -> r.u64()
                                    else -> throw DwarfFormatException("bad segment selector size")
                                }
                            }
                            state.address = when (prog.addressSize) {
                                1 -> r.u8().toLong(); 2 -> r.u16().toLong()
                                4 -> r.u32(); 8 -> r.u64()
                                else -> throw DwarfFormatException("bad address size ${prog.addressSize}")
                            }
                            trace += "extended: set_address 0x${state.address.toString(16)}"
                        }
                        DW.LNE_DEFINE_FILE -> {
                            // DWARF 4 only; append to file table is out of scope for a state
                            // machine, consume remainder.
                            val skipped = insnEnd - r.pos
                            if (skipped > 0) r.bytes(skipped)
                            trace += "extended: define_file (ignored)"
                        }
                        DW.LNE_SET_DISCRIMINATOR -> {
                            state.discriminator = r.uleb128().toInt()
                            trace += "extended: set_discriminator ${state.discriminator}"
                        }
                        else -> {
                            val skipped = insnEnd - r.pos
                            if (skipped > 0) r.bytes(skipped)
                            trace += "extended: unknown(0x${sub.toString(16)})"
                        }
                    }
                    if (r.pos > insnEnd) throw DwarfFormatException("extended opcode overran its length")
                    if (r.pos != insnEnd) r.seek(insnEnd)
                }
                opcode < prog.opcodeBase -> {
                    when (opcode) {
                        DW.LNS_COPY -> emitRow("standard: copy")
                        DW.LNS_ADVANCE_PC -> {
                            val advance = r.uleb128().toLong()
                            state.address += advance * opAdvance
                            trace += "advance_pc +$advance"
                        }
                        DW.LNS_ADVANCE_LINE -> {
                            val delta = r.sleb128()
                            state.line += delta.toInt()
                            trace += "advance_line $delta"
                        }
                        DW.LNS_SET_FILE -> {
                            state.file = r.uleb128().toInt()
                            trace += "set_file ${state.file}"
                        }
                        DW.LNS_SET_COLUMN -> {
                            state.column = r.uleb128().toInt()
                            trace += "set_column ${state.column}"
                        }
                        DW.LNS_NEGATE_STMT -> {
                            state.isStmt = !state.isStmt
                            trace += "negate_stmt"
                        }
                        DW.LNS_SET_BASIC_BLOCK -> {
                            state.basicBlock = true
                            trace += "set_basic_block"
                        }
                        DW.LNS_CONST_ADD_PC -> {
                            val adjust = specialAdjust(255)
                            state.address += adjust * opAdvance
                            trace += "const_add_pc (0x${(adjust * opAdvance).toString(16)})"
                        }
                        DW.LNS_FIXED_ADVANCE_PC -> {
                            val adv = r.u16().toLong()
                            state.address += adv
                            trace += "fixed_advance_pc +$adv"
                        }
                        DW.LNS_SET_PROLOGUE_END -> {
                            state.prologueEnd = true
                            trace += "set_prologue_end"
                        }
                        DW.LNS_SET_EPILOGUE_BEGIN -> {
                            state.epilogueBegin = true
                            trace += "set_epilogue_begin"
                        }
                        DW.LNS_SET_ISA -> {
                            state.isa = r.uleb128().toInt()
                            trace += "set_isa ${state.isa}"
                        }
                        else -> {
                            // Unknown standard opcode: use standard_opcode_lengths to skip operands.
                            val idx = opcode - 1
                            if (idx < 0 || idx >= prog.standardOpcodeLengths.size) {
                                throw DwarfFormatException("standard opcode $opcode has no arity entry")
                            }
                            repeat(prog.standardOpcodeLengths[idx]) { r.uleb128() }
                            trace += "unknown standard opcode $opcode"
                        }
                    }
                    // basic block / prologue etc. flags reset after a copy: copy itself emits
                    // then on next emission cycle we reset the transient flags lazily:
                    if (opcode == DW.LNS_COPY) {
                        state.basicBlock = false
                        state.prologueEnd = false
                        state.epilogueBegin = false
                        state.discriminator = 0
                        trace.clear()
                    }
                }
                else -> {
                    // special opcode
                    val adjusted = opcode - prog.opcodeBase
                    val addrAdvance = adjusted / prog.lineRange
                    val lineAdvance = prog.lineBase + (adjusted % prog.lineRange)
                    state.address += addrAdvance * opAdvance
                    state.line += lineAdvance
                    emitRow("special opcode $opcode (addr+$addrAdvance, line${if (lineAdvance >= 0) "+" else ""}$lineAdvance)")
                    state.basicBlock = false
                    state.prologueEnd = false
                    state.epilogueBegin = false
                    state.discriminator = 0
                    trace.clear()
                }
            }
        }
        if (rows.isNotEmpty()) {
            issues += DebugIssue(
                DebugIssue.Severity.WARNING, "unterminated_sequence",
                "line program at ${prog.sectionOffset} ended without end_sequence; ${rows.size} rows dropped",
                prog.sectionOffset, ".debug_line",
            )
        }
        return sequences
    }

    private fun specialAdjust(opcode: Int): Int {
        // Address increment for the const-add-pc / special formula.
        val adjusted = opcode - prog.opcodeBase
        return adjusted / prog.lineRange
    }
}
