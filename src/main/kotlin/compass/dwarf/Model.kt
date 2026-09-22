package compass.dwarf

/** 行程序产生的一条矩阵行（end_sequence 行 endSequence=true）。 */
data class LineRow(
    val address: Long,
    val segment: Long,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
    val hseq: Int
)

data class LineFile(val id: Int, val name: String, val dirIndex: Int, val compDir: String?) {
    val displayPath: String get() = if (compDir != null && name.startsWith("/")) name else name
}

/** 一个 line program header + 矩阵；同一 CU 可有多个 sequence。 */
data class LineProgram(
    val cuOffset: Long,
    val headerOffset: Long,
    val table: TableVersion,
    val files: List<LineFile>,
    val directories: List<String>,
    val rows: List<LineRow>,
    /** 每行对应的状态机事件（opcode 名称），与 rows 等长。 */
    val events: List<String>,
    val warnings: List<String>
) {
    fun fileName(idx: Int): String? = files.getOrNull(idx)?.displayPath
}

data class DieRange(val low: Long, val high: Long) {
    val isEmpty: Boolean get() = high <= low
}

data class DieNode(
    val offset: Long,
    val tag: Int,
    val parentOffset: Long?,
    val childrenOffsets: List<Long>,
    val name: String?,
    val lowPc: Long?,
    /** 0 = DW_FORM_addr 常量形式的 high_pc；非 0 = 地址形式 high_pc。 */
    val highPcConst: Long?,
    val highPcAddr: Long?,
    val rangesOffset: Long?,
    val rangesX: Long?,
    val abstractOrigin: Long?,
    val specification: Long?,
    val callFile: Int?,
    val callLine: Int?,
    val ranges: List<DieRange>,
    val isDeclaration: Boolean
) {
    fun covers(addr: Long): Boolean = ranges.any { !it.isEmpty && addr >= it.low && addr < it.high }
}

data class CompilationUnit(
    val offset: Long,
    val length: Long,
    val dwarfVersion: Int,
    val unitType: Int?,
    val is64Bit: Boolean,
    val addressSize: Int,
    val abbrevOffset: Long,
    val name: String?,
    val compDir: String?,
    val dwoName: String?,
    val dwoId: Long?,
    val stmtListOffset: Long?,
    val dies: Map<Long, DieNode>,
    val rootOffset: Long,
    val split: Boolean,
    val warnings: List<String>,
    /** 该 CU 因未知 form 等问题被隔离：DIE 可能不完整，不应与其他结果混淆。 */
    val degraded: Boolean
)

data class SectionInfo(
    val name: String,
    val fileOffset: Long,
    val size: Long,
    val vaddr: Long,
    val present: Boolean,
    val sha256Short: String?
)

data class ParsedDebugInfo(
    val sections: List<SectionInfo>,
    val cus: List<CompilationUnit>,
    val programs: List<LineProgram>,
    val warnings: List<String>,
    val rawSectionDigests: Map<String, String>
)
