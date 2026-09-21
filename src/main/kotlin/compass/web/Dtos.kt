package compass.web

import compass.dwarf.*
import compass.resolve.*
import compass.store.*

data class ImportRequest(val key: String?, val fileName: String?, val base64: String?)
data class SnapshotLoadDto(
    val moduleKey: String, val moduleVersion: Int? = null,
    val loadBias: Long = 0, val generation: Int = 1, val label: String? = null,
)
data class SnapshotRequest(val name: String, val loads: List<SnapshotLoadDto>)
data class BatchRequest(val snapshotId: Long, val name: String?, val raw: String)
data class RelativeQueryRequest(val moduleKey: String, val moduleVersion: Int? = null, val relative: Long, val loadBias: Long = 0, val generation: Int = 1)

data class RangeDto(val start: Long, val end: Long, val length: Long, val zeroLength: Boolean)
data class ScopeDto(
    val name: String?, val linkageName: String?, val tag: String, val offset: Long,
    val depth: Int, val inline: Boolean, val ranges: List<RangeDto>,
    val callFile: String?, val callLine: Int?,
)
data class SequenceDto(
    val index: Int, val start: Long, val end: Long, val rowCount: Int,
    val cuIndex: Int,
)
data class LineRowDto(
    val address: Long, val file: String?, val line: Int, val column: Int,
    val isStmt: Boolean, val endSequence: Boolean, val basicBlock: Boolean,
    val prologueEnd: Boolean, val epilogueBegin: Boolean, val discriminator: Int,
    val sequenceIndex: Int,
)
data class CuDto(
    val index: Int, val version: Int, val unitType: Int, val offset: Long,
    val name: String?, val compDir: String?, val dwoName: String?,
    val tableVersion: String, val warnings: List<String>,
    val scopeCount: Int, val sequenceCount: Int,
)
data class ModuleDetailDto(
    val id: Long, val key: String, val version: Int, val fileName: String,
    val sha256: String, val importedAt: String, val superseded: Boolean,
    val digests: List<SectionDigest>,
    val warnings: List<String>,
    val cus: List<CuDto>,
    val scopes: Map<Int, List<ScopeDto>>,
    val sequences: Map<Int, List<SequenceDto>>,
    val lineRows: Map<Int, List<LineRowDto>>,
)
data class CandidateDto(
    val moduleKey: String, val moduleVersion: Int, val moduleFileName: String,
    val loadBias: Long, val generation: Int, val inputAddress: Long,
    val relativeAddress: Long, val cuName: String?, val cuCompDir: String?,
    val cuOffset: Long, val cuVersion: Int, val tableVersion: String,
    val scopeName: String?, val filePath: String?, val line: Int?, val column: Int?,
    val sequenceIndex: Int?, val rangeStart: Long?, val rangeEnd: Long?,
    val rangeLength: Long?, val inlineDepth: Int,
    val inlineChain: List<InlineFrame>, val priority: Int, val source: String,
    val dwoMissing: Boolean, val warnings: List<String>,
)
data class QueryResponseDto(
    val resolved: Boolean, val loadBias: Long?, val generation: Int?,
    val moduleKey: String?, val moduleVersion: Int?,
    val candidates: List<CandidateDto>, val warnings: List<String>, val notes: List<String>,
)
