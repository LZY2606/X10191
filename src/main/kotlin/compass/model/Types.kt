package compass.model

import kotlinx.serialization.Serializable

/** 越界 / 长度不足：所有读取都必须在声明边界内进行。 */
class BoundsException(message: String) : RuntimeException(message)

/** 遇到未知 DW_FORM，无法安全跳过，必须中止当前作用域，避免游标错位。 */
class UnknownFormException(val form: Int) : RuntimeException("unknown DW_FORM 0x${form.toString(16)}")

enum class Endian { LITTLE, BIG }

enum class TrustLevel {
    /** 全部关键结构可验证（含 split dwo 匹配成功）。 */
    FULL,

    /** 部分结论可信：例如缺 dwo 时行号仍可信，但函数/内联信息不完整。 */
    PARTIAL,

    /** 游标对齐无法保证，该作用域结果不得用于解释地址。 */
    UNTRUSTED
}

@Serializable
data class ParseIssue(
    val severity: String, // warn | error
    val area: String,
    val message: String,
    val offset: Long? = null
)

@Serializable
data class ByteSummary(
    val sha256: String,
    val size: Long,
    val headHex: String,
    val tailHex: String,
    val sectionSummaries: Map<String, SectionSummary> = emptyMap()
)

@Serializable
data class SectionSummary(val sha256: String, val size: Long)

@Serializable
data class ElfSectionInfo(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val fileOffset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val entsize: Long,
    val noBits: Boolean
)

@Serializable
data class ElfSegmentInfo(
    val type: Int,
    val flags: Int,
    val fileOffset: Long,
    val vaddr: Long,
    val filesz: Long,
    val memsz: Long
)

@Serializable
data class SourceFile(val id: Int, val name: String, val directory: String) {
    val displayPath: String get() = if (directory.isBlank() || directory == ".") name else "$directory/$name"
}

@Serializable
data class LineRow(
    val address: Long,
    val segment: Int,
    val opIndex: Int,
    val fileId: Int,
    val line: Int,
    val column: Int,
    val discriminator: Int,
    val isa: Int,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val endSequence: Boolean
)

@Serializable
data class LineSequence(
    val cuIndex: Int,
    val index: Int,
    val version: Int,
    val dwarfFormat: Int,
    val startAddress: Long,
    val endAddress: Long,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val files: List<SourceFile>,
    val rows: List<LineRow>,
    val issues: List<ParseIssue> = emptyList()
)

@Serializable
data class AddrRange(
    val low: Long,
    val high: Long,
    val zeroLength: Boolean = false,
    val source: String = "ranges"
) {
    val width: Long get() = high - low
    fun contains(addr: Long): Boolean =
        if (zeroLength) addr == low else addr in low until high
}

@Serializable
data class RawAttr(val name: String, val form: String, val value: String)

@Serializable
data class DieNode(
    val offset: Long,
    val tag: Int,
    val tagName: String,
    val depth: Int,
    val parentOffset: Long?,
    val childOffsets: List<Long>,
    val name: String?,
    val linkageName: String?,
    val ranges: List<AddrRange>,
    val rangeBasis: String,
    val abstractOriginOffset: Long?,
    val specificationOffset: Long?,
    val declFileId: Int?,
    val declLine: Int?,
    val callFileId: Int?,
    val callLine: Int?,
    val callColumn: Int?,
    val inlineCode: Int?,
    val declaration: Boolean,
    val external: Boolean,
    val unknownForm: Boolean,
    val rawAttrs: List<RawAttr>
)

@Serializable
data class CompilationUnitInfo(
    val index: Int,
    val offset: Long,
    val version: Int,
    val dwarfFormat: Int,
    val unitType: Int,
    val unitTypeName: String,
    val addressSize: Int,
    val dwoId: Long?,
    val abbrevOffset: Long,
    val dieCount: Int,
    val rootName: String?,
    val compDir: String?,
    val primaryFile: String?,
    val language: Int?,
    val trust: TrustLevel,
    val issues: List<ParseIssue>,
    val splitMatched: Boolean,
    val splitNeeded: Boolean
)

@Serializable
data class FunctionFrame(
    val dieOffset: Long,
    val tagName: String,
    val name: String,
    val declFile: String?,
    val declLine: Int?,
    val callFile: String?,
    val callLine: Int?,
    val callColumn: Int?,
    val inline: Boolean,
    val depth: Int,
    val ranges: List<AddrRange>
)

@Serializable
data class AddressCandidate(
    val rank: Int,
    val versionId: String,
    val versionLabel: String,
    val cuIndex: Int,
    val cuName: String?,
    val sequenceIndex: Int,
    val file: String?,
    val line: Int?,
    val column: Int?,
    val discriminator: Int?,
    val address: Long,
    val matchedVaddr: Long,
    val loadBias: Long?,
    val tableVersion: Int,
    val sequenceStart: Long,
    val sequenceEnd: Long,
    val narrowestRangeWidth: Long,
    val inlineDepth: Int,
    val explicitPriority: Int,
    val chain: List<FunctionFrame>,
    val trust: TrustLevel,
    val notes: List<String>
)

@Serializable
data class ResolvedAddress(
    val input: String,
    val runtimeAddress: Long?,
    val candidates: List<AddressCandidate>,
    val generations: List<String>,
    val notes: List<String>
)

@Serializable
data class ParseResultSummary(
    val versionId: String,
    val trust: TrustLevel,
    val issues: List<ParseIssue>,
    val cus: List<CompilationUnitInfo>,
    val sequenceCount: Int,
    val functionCount: Int
)
