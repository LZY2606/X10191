package luopan.model

/** 一个 section 的原始字节摘要（不保存全部明文，只保存指纹与长度；原始 BLOB 在 DB 层另存）。 */
data class SectionSummary(
    val name: String,
    val fileOffset: Long,
    val size: Long,
    val address: Long,
    val sha256: String,
    val entropy: Double,
    val headHex: String
)

data class ElfInfo(
    val elfClass: Int,          // 1 = 32bit, 2 = 64bit
    val endian: String,         // "LSB" / "MSB"
    val machine: Int,
    val machineName: String,
    val type: Int,
    val typeName: String,
    val entry: Long,
    val littleEndian: Boolean
)

/** ELF 程序头（LOAD 段），用于段地址解释。 */
data class ProgramHeader(val type: Int, val offset: Long, val vaddr: Long, val paddr: Long,
                         val filesz: Long, val memsz: Long, val flags: Int, val align: Long)

data class SectionBlob(val name: String, val data: ByteArray, val address: Long = 0L, val fileOffset: Long = 0L) {
    override fun equals(other: Any?): Boolean = other is SectionBlob && other.name == name
    override fun hashCode(): Int = name.hashCode()
}

data class ParsedElf(
    val elf: ElfInfo,
    val sections: List<SectionBlob>,
    val summaries: List<SectionSummary>,
    val programHeaders: List<ProgramHeader>
) {
    fun section(name: String): ByteArray? = sections.firstOrNull { it.name == name }?.data
}

/** range list 解析出的一对 [start, end)（相对地址 + index）。 */
data class AddressRange(val start: Long, val endExclusive: Long, val segment: Long = 0L) {
    val isEmpty: Boolean get() = endExclusive <= start
}

data class LineFile(val id: Int, val name: String, val dirIndex: Int)

/** line program 执行的一步状态变化（含中间步骤，供前端画时间线）。 */
data class LineStep(
    val pc: Long,
    val file: String,
    val line: Int,
    val column: Int,
    val endSequence: Boolean,
    val isa: Int,
    val discriminator: Int,
    val opcode: String
)

data class LineSequence(
    val startPc: Long,
    val endPc: Long,
    val segment: Long,
    val steps: List<LineStep>,
    val version: Int,
    val cuName: String?
)

/** 内联调用栈上的一帧：CU 帧（depth=0）或函数/内联帧。 */
data class InlineFrame(
    val depth: Int,
    val name: String,
    val tag: Int,
    val declFile: String?,
    val declLine: Int?,
    val declColumn: Int?,
    val callFile: String?,
    val callLine: Int?,
    val callColumn: Int?,
    val abstractName: String?
)

data class CompilationUnit(
    val index: Int,
    val name: String?,          // DW_AT_NAME
    val compDir: String?,
    val dwoName: String?,
    val dwoId: Long?,
    val version: Int,
    val unitType: Int,
    val isSkeleton: Boolean,
    val isSplit: Boolean,
    val language: Long?,
    val stmtListOffset: Long,
    val lowPc: Long?,
    val ranges: List<AddressRange>,
    val lineProgramPresent: Boolean,
    val parseError: String?,
    val dwoResolved: Boolean,
    val dwoResolutionNote: String?,
    val dieCount: Int
)

data class FunctionInfo(
    val cuIndex: Int,
    val name: String?,
    val linkName: String?,
    val lowPc: Long?,
    val highPc: Long?,
    val highPcIsSize: Boolean,
    val rangesOffset: Long?,
    val ranges: List<AddressRange>,
    val inlineDepth: Int,
    val dieOffset: Long,
    val explicitPriority: Long?,
    val isArtificial: Boolean
)

/** 一次地址查询命中的一个合法候选（保留全部合法候选，不只返回最优）。 */
data class AddressCandidate(
    val rank: Int,
    val file: String?,
    val line: Int,
    val column: Int,
    val cuName: String?,
    val cuIndex: Int,
    val sequenceStart: Long,
    val sequenceEnd: Long,
    val lineVersion: Int,
    val symbol: String?,
    val inlineChain: List<InlineFrame>,
    val matchedRangeStart: Long,
    val matchedRangeEnd: Long,
    val rangeWidth: Long,
    val maxInlineDepth: Int,
    val explicitPriority: Long?,
    val isZeroLengthHit: Boolean,
    val confidence: String,      // HIGH / MEDIUM / LOW
    val notes: List<String>
)

data class AddressQuery(
    val requestedAddress: Long,
    val relativeAddress: Long?,
    val loadBias: Long?,
    val moduleName: String?,
    val snapshotId: Long?,
    val segmented: Boolean,
    val segment: Long,
    val candidates: List<AddressCandidate>,
    val trustedConclusions: List<String>,
    val untrustedNotes: List<String>,
    val errors: List<String>
)

data class SectionMapEntry(
    val name: String,
    val fileOffset: Long,
    val size: Long,
    val address: Long,
    val sha256: String
)

/** 解析后的完整模块（内存态；DB 里保存的是原始 BLOB + 元数据）。 */
data class ParsedModule(
    val moduleId: Long,
    val fileName: String,
    val elf: ElfInfo,
    val sectionMap: List<SectionMapEntry>,
    val cus: List<CompilationUnit>,
    val functions: List<FunctionInfo>,
    val sequences: List<LineSequence>,
    val parseErrors: List<String>
)

data class LoadSnapshot(
    val id: Long,
    val name: String,
    val moduleVersionId: Long,
    val moduleId: Long,
    val baseAddress: Long?,
    val segments: List<SnapshotSegment>,
    val createdAt: Long
)

data class SnapshotSegment(
    val name: String,
    val fileOffset: Long,
    val vaddr: Long,
    val memsz: Long,
    val baseAdjust: Long
)

data class CrashRecord(
    val id: Long,
    val moduleVersionId: Long,
    val snapshotId: Long?,
    val addresses: List<Long>,
    val note: String,
    val createdAt: Long
)
