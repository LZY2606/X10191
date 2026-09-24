package compass.dwarf

data class LineFile(val id: Int, val name: String, val directoryIndex: Int?, val timestamp: Long?, val size: Long?)

data class LineRow(
    val address: Long,
    val segment: Int,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val isStatement: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
)

data class LineSequence(val rows: List<LineRow>, val segment: Int, val start: Long, val end: Long)

data class LineProgram(
    val sectionOffset: Long,
    val version: Int,
    val files: List<LineFile>,
    val directories: List<String>,
    val sequences: List<LineSequence>,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val defaultIsStatement: Boolean,
) {
    /**
     * All candidate rows for an address. Multiple overlapping sequences each
     * contribute their own match; callers rank by function/inline evidence.
     * A zero-length entry matches its exact start address.
     */
    fun rowsFor(addr: Long, segment: Int = 0): List<LineRow> {
        val out = mutableListOf<LineRow>()
        for (seq in sequences) {
            if (seq.segment != segment) continue
            if (addr !in seq.start until seq.end && addr != seq.start) continue
            var best: LineRow? = null
            for (row in seq.rows) {
                if (row.endSequence) continue
                if (row.address <= addr) {
                    if (best == null || row.address >= best.address) best = row
                }
            }
            // Exact match for zero-length sequences (start row then end at same address).
            if (best == null) {
                for (row in seq.rows) {
                    if (!row.endSequence && row.address == seq.start) { best = row; break }
                }
            }
            best?.let(out::add)
        }
        return out
    }
}
