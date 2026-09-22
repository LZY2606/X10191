package compass.web

import compass.dwarf.*
import compass.elf.ElfSection
import kotlinx.serialization.Serializable

@Serializable
data class RangeJson(val start: String, val end: String, val segment: Int, val zeroLength: Boolean)

@Serializable
data class LineFileJson(val index: Long, val name: String, val directory: String)

@Serializable
data class TransitionJson(
    val seq: Int, val address: String, val line: Long, val column: Long,
    val fileIndex: Long, val isStmt: Boolean, val endSequence: Boolean, val opcode: String
)

@Serializable
data class SequenceJson(
    val index: Int, val start: String, val end: String, val segment: Int,
    val dwarfVersion: Int, val rows: Int
)

@Serializable
data class InlineFrameJson(
    val depth: Int, val function: String, val dieOffset: String,
    val callFile: String? = null, val line: Long? = null, val column: Long? = null,
    val ranges: List<RangeJson> = emptyList()
)

@Serializable
data class LineHitJson(
    val file: String, val directory: String, val line: Long, val column: Long,
    val sequenceIndex: Int, val sequenceStart: String, val sequenceEnd: String,
    val dwarfVersion: Int, val isStmt: Boolean
)

@Serializable
data class CandidateJson(
    val rank: Int,
    val fileId: Long,
    val fileName: String,
    val fileSha256: String,
    val cuName: String,
    val cuOffset: String,
    val dwarfVersion: Int,
    val matchedRange: RangeJson,
    val rangeWidth: String,
    val inlineDepth: Int,
    val explicitScore: Int,
    val function: String?,
    val line: LineHitJson?,
    val inlineChain: List<InlineFrameJson>,
    val tableVersion: Int?,
    val trusted: Boolean,
    val notes: List<String>
)

@Serializable
data class QueryResponseJson(
    val raw: String,
    val runtimeAddress: String,
    val relativeAddress: String,
    val loadBias: String?,
    val moduleBase: String?,
    val moduleName: String?,
    val summary: String,
    val warnings: List<String>,
    val candidates: List<CandidateJson>
)

@Serializable
data class SectionJson(
    val name: String, val type: Int, val flags: String, val addr: String,
    val fileOffset: String, val size: Long, val sha256: String?
)

@Serializable
data class IssueJson(val severity: String, val location: String, val message: String)

@Serializable
data class UnitJson(
    val unitOffset: String, val version: Int, val unitType: Int,
    val name: String?, val isSkeleton: Boolean, val isSplit: Boolean,
    val dwoId: String?, val stmtList: String?,
    val linked: Boolean, val scopes: Int, val issues: List<IssueJson>
)

@Serializable
data class ScopeJson(
    val dieOffset: String, val tag: Int, val name: String?, val inlineDepth: Int,
    val ranges: List<RangeJson>,
    val callFile: String?, val callLine: Long?, val callColumn: Long?
)

@Serializable
data class FileDetailJson(
    val id: Long, val path: String?, val sha256: String, val size: Long,
    val versionLabel: String,
    val sections: List<SectionJson>,
    val units: List<UnitJson>,
    val scopes: List<ScopeJson>,
    val issues: List<IssueJson>,
    val loadSegments: List<RangeJson>,
    val preferredBase: String?
)

@Serializable
data class ImportResponseJson(
    val id: Long, val deduped: Boolean, val versionLabel: String,
    val sha256: String, val units: Int, val scopes: Int, val issues: List<IssueJson>
)

@Serializable
data class LineProgramJson(
    val stmtList: String, val dwarfVersion: Int,
    val minInsnLength: Int, val defaultIsStmt: Boolean,
    val lineBase: Int, val lineRange: Int, val opcodeBase: Int,
    val files: List<LineFileJson>,
    val sequences: List<SequenceJson>,
    val transitions: List<TransitionJson>,
    val issues: List<IssueJson>
)

@Serializable
data class ModuleSpecJson(val name: String, val fileId: Long, val base: String, val generation: Int = 0)

@Serializable
data class SnapshotRequestJson(val label: String, val modules: List<ModuleSpecJson>)

@Serializable
data class SnapshotJson(
    val id: Long, val label: String, val createdAt: String,
    val modules: List<ModuleSpecJson>
)

@Serializable
data class BatchQueryRequestJson(
    val snapshotId: Long? = null,
    val addresses: List<String>
)

@Serializable
data class BatchQueryResponseJson(val results: List<QueryResponseJson>)

@Serializable
data class ImportErrorJson(val error: String)
