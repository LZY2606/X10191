package compass.model

data class AddressRange(val begin: Long, val end: Long, val segment: Long = 0L) {
    val width: Long get() = end - begin
    val zeroLength: Boolean get() = begin == end
    fun contains(addr: Long): Boolean = if (zeroLength) addr == begin else addr >= begin && addr < end
}

data class LineRow(
    val cuIndex: Int,
    val sequence: Int,
    val address: Long,
    var endAddress: Long,
    val segment: Long,
    val file: String,
    val line: Long,
    val column: Long,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Long,
    val discriminator: Long,
    val endSequence: Boolean,
)

data class DieNode(
    val cuIndex: Int,
    val offset: Long,
    val depth: Int,
    val tag: Long,
    val name: String?,
    val lowPc: Long?,
    val highPc: Long?,
    val highPcIsAddress: Boolean,
    val ranges: List<AddressRange>,
    val callFile: Long?,
    val callLine: Long?,
    val callColumn: Long?,
    val abstractOrigin: Long?,
    val specification: Long?,
)

data class CompilationUnit(
    val index: Int,
    val offset: Long,
    val version: Int,
    val unitType: Int,
    val addrSize: Int,
    val isDwarf64: Boolean,
    val name: String?,
    val compDir: String?,
    val producer: String?,
    val dwoName: String?,
    val stmtList: Long?,
    val lowPc: Long?,
    val highPc: Long?,
    val highPcIsAddress: Boolean,
    val rangesOffset: Long?,
    val rangesBase: Long,
    val addrBase: Long,
    val strOffsetsBase: Long,
    val status: String, // "ok" | "degraded" | "failed"
)

data class ParseIssue(
    val section: String,
    val offset: Long,
    val severity: String, // "warning" | "error"
    val message: String,
)

data class ParsedDwarf(
    val units: List<CompilationUnit>,
    val dies: List<DieNode>,
    val lineRows: List<LineRow>,
    val issues: List<ParseIssue>,
    val tableVersions: Map<String, String>, // e.g. "line" -> "DWARF5", "ranges" -> "rnglists"
    val cuFiles: Map<Int, List<String>> = emptyMap(),
)
