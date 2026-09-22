package compass.dwarf

import compass.elf.ByteReader

/** One file-name-table entry. */
data class LineFile(val index: Long, val name: String, val directory: String)

/** One emitted matrix row (state machine snapshot). */
data class LineRow(
    val address: Long,
    val segment: Int,
    val fileIndex: Long,
    val line: Long,
    val column: Long,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Long,
    val discriminator: Long,
    val opIndex: Long,
    val sequenceIndex: Int
)

/**
 * One contiguous [start,end) run of addresses produced by a line program.
 * A single program may contain many sequences (each LNE_end_sequence).
 */
data class LineSequence(
    val index: Int,
    val startAddress: Long,
    val endAddress: Long,
    val segment: Int,
    val rows: List<LineRow>
) {
    fun covers(addr: Long): Boolean = addr in startAddress until endAddress
}

/** State transition log entry for the UI's "line program 状态变化" view. */
data class LineTransition(
    val seq: Int,
    val address: Long,
    val line: Long,
    val column: Long,
    val fileIndex: Long,
    val isStmt: Boolean,
    val endSequence: Boolean,
    val opcode: String
)

class LineProgram(
    val sectionOffset: Long,
    val version: Int,
    val files: List<LineFile>,
    val rows: List<LineRow>,
    val sequences: List<LineSequence>,
    val transitions: List<LineTransition>,
    val minimumInstructionLength: Int,
    val maximumOperationsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val issues: List<ParseIssue>
) {
    fun fileOf(index: Long): LineFile? = files.firstOrNull { it.index == index }

    /** Most specific row for [addr] within this program: last row at-or-before it. */
    fun rowFor(addr: Long): LineRow? {
        val seq = sequences.firstOrNull { it.covers(addr) } ?: return null
        var best: LineRow? = null
        for (row in seq.rows) {
            if (!row.endSequence && row.address <= addr) best = row
        }
        return best
    }
}
