package compass.dwarf

import compass.elf.ByteReader

/** Executes one .debug_line program and collects rows + transitions. */
class StateMachine(
    private val version: Int,
    private val addressSize: Int,
    private val segmentSelectorSize: Int,
    private val minimumInstructionLength: Int,
    private val maximumOperationsPerInstruction: Int,
    private val defaultIsStmt: Boolean,
    private val lineBase: Int,
    private val lineRange: Int,
    private val opcodeBase: Int,
    private val standardOpcodeLengths: IntArray,
    private val files: MutableList<LineFile>,
    private val resolveStrx: (Long) -> String?,
    private val resolveLineStrp: (Long) -> String?
) {
    val rows = ArrayList<LineRow>()
    val transitions = ArrayList<LineTransition>()
    val issues = mutableListOf<ParseIssue>()

    // registers
    private var address = 0L
    private var segment = 0
    private var opIndex = 0L
    private var file = 0L
    private var line = 1L
    private var column = 0L
    private var isStmt = defaultIsStmt
    private var basicBlock = false
    private var endSequence = false
    private var prologueEnd = false
    private var epilogueBegin = false
    private var isa = 0L
    private var discriminator = 0L
    private var seqIndex = 0
    private var opcodeCount = 0

    fun run(r: ByteReader) {
        while (!r.atEnd) {
            if (++opcodeCount > Limits.MAX_LINE_OPCODES) {
                issues.add(ParseIssue("error", "line+$seqIndex", "opcode cap reached; program truncated"))
                return
            }
            if (rows.size > Limits.MAX_LINE_ROWS) {
                issues.add(ParseIssue("error", "line+$seqIndex", "row cap reached; program truncated"))
                return
            }
            val op = r.u1()
            when {
                op == 0 -> extended(r)
                op < opcodeBase -> standard(r, op)
                else -> special(op)
            }
        }
    }

    private fun resetRegisters() {
        address = 0L; segment = 0; opIndex = 0L; file = 0L; line = 1L; column = 0L
        isStmt = defaultIsStmt; basicBlock = false; endSequence = false
        prologueEnd = false; epilogueBegin = false; isa = 0L; discriminator = 0L
    }

    private fun appendRow(opcode: String) {
        val row = LineRow(address, segment, file, line, column, isStmt, basicBlock, endSequence,
            prologueEnd, epilogueBegin, isa, discriminator, opIndex, seqIndex)
        rows.add(row)
        transitions.add(LineTransition(seqIndex, address, line, column, file, isStmt, endSequence, opcode))
    }

    private fun advAddr(operationAdvance: Long) {
        val adv = minimumInstructionLength.toLong() *
            ((opIndex + operationAdvance) / maximumOperationsPerInstruction)
        address += adv
        opIndex = (opIndex + operationAdvance) % maximumOperationsPerInstruction
    }

    private fun special(opcode: Int) {
        val adjusted = opcode - opcodeBase
        val operationAdvance = adjusted / lineRange
        advAddr(operationAdvance.toLong())
        line += (lineBase + (adjusted % lineRange)).toLong()
        appendRow("special($opcode)")
        basicBlock = false; prologueEnd = false; epilogueBegin = false
    }

    private fun standard(r: ByteReader, op: Int) {
        val arity = standardOpcodeLengths.getOrElse(op - 1) {
            issues.add(ParseIssue("warning", "line+$seqIndex",
                String.format("unknown standard opcode %d; cannot locate operands, program stopped", op)))
            r.seek(r.size)
            return
        }
        when (op) {
            DW.LNS_copy -> {
                appendRow("copy")
                basicBlock = false; prologueEnd = false; epilogueBegin = false
            }
            DW.LNS_advance_pc -> advAddr(r.uleb())
            DW.LNS_advance_line -> line += r.sleb()
            DW.LNS_set_file -> file = r.uleb()
            DW.LNS_set_column -> column = r.uleb()
            DW.LNS_negate_stmt -> isStmt = !isStmt
            DW.LNS_set_basic_block -> basicBlock = true
            DW.LNS_const_add_pc -> {
                val adjusted = (255 - opcodeBase)
                advAddr((adjusted / lineRange).toLong())
            }
            DW.LNS_fixed_advance_pc -> {
                val v = r.u2()
                address += v.toLong() and 0xffffL
                opIndex = 0
            }
            DW.LNS_set_prologue_end -> prologueEnd = true
            DW.LNS_set_epilogue_begin -> epilogueBegin = true
            DW.LNS_set_isa -> isa = r.uleb()
            else -> repeat(arity) { r.uleb() }
        }
        // consume any unconsumed declared operands for opcodes we partially model
        if (op != DW.LNS_copy && op != DW.LNS_negate_stmt &&
            op != DW.LNS_set_basic_block && op != DW.LNS_const_add_pc &&
            op != DW.LNS_set_prologue_end && op != DW.LNS_set_epilogue_begin &&
            op > DW.LNS_set_isa) {
            // no extra ops beyond isa in DWARF4/5
        }
    }

    private fun extended(r: ByteReader) {
        val len = r.uleb().toInt()
        if (len == 0) {
            issues.add(ParseIssue("warning", "line+$seqIndex", "zero-length extended opcode"))
            return
        }
        val sub = r.subReader(r.save(), len)
        r.skip(len)
        val eop = sub.u1()
        when (eop) {
            DW.LNE_end_sequence -> {
                endSequence = true
                appendRow("end_sequence")
                endSequence = false
                seqIndex++
                resetRegisters()
            }
            DW.LNE_set_address -> {
                if (segmentSelectorSize > 0) segment = sub.uword(segmentSelectorSize).toInt()
                address = sub.uword(addressSize)
                opIndex = 0
            }
            DW.LNE_define_file -> {
                if (version >= 5) {
                    issues.add(ParseIssue("warning", "line+$seqIndex",
                        "DW_LNE_define_file removed in DWARF5; skipped"))
                } else {
                    val name = sub.cString()
                    val dirIndex = sub.uleb(); sub.uleb(); sub.uleb()
                    val idx = (files.maxOfOrNull { it.index } ?: 0L) + 1
                    files.add(LineFile(idx, name, "dir#$dirIndex"))
                }
            }
            DW.LNE_set_discriminator -> discriminator = sub.uleb()
            else -> {
                if (eop in DW.LNE_lo_user..DW.LNE_hi_user) {
                    // vendor opcodes: bytes already consumed
                } else {
                    issues.add(ParseIssue("warning", "line+$seqIndex",
                        String.format("unknown extended opcode 0x%02x; %d bytes skipped", eop, len - 1)))
                }
            }
        }
    }
}
