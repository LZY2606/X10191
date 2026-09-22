package compass.web

import compass.dwarf.LineCandidate
import compass.dwarf.QueryResult
import kotlinx.serialization.Serializable

@Serializable
data class ApiResult(
    val ok: Boolean,
    val data: kotlinx.serialization.json.JsonElement? = null,
    val error: String? = null
)

@Serializable
data class FrameDto(
    val depth: Int,
    val name: String,
    val dieOffset: String,
    val tag: String,
    val callFile: String?,
    val callLine: Int?,
    val rangeLow: String?,
    val rangeHigh: String?,
    val width: String
)

@Serializable
data class CandidateDto(
    val cuOffset: String,
    val cuName: String?,
    val cuVersion: Int,
    val tableVersion: Int,
    val sequenceIndex: Int,
    val sequenceStart: String,
    val sequenceEnd: String,
    val matchedAddress: String,
    val file: String?,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val prologueEnd: Boolean,
    val segment: String,
    val rank: Int,
    val source: String,
    val frames: List<FrameDto>,
    val warnings: List<String>
)

@Serializable
data class QueryResultDto(
    val runtimeAddress: String,
    val loadBias: String,
    val relativeAddress: String,
    val snapshotGeneration: Int,
    val resolved: Boolean,
    val degraded: Boolean,
    val warnings: List<String>,
    val candidates: List<CandidateDto>
)

@Serializable
data class BatchItemDto(val input: String, val address: String, val result: QueryResultDto?)

fun QueryResult.toDto(): QueryResultDto = QueryResultDto(
    runtimeAddress = "0x${runtimeAddress.toString(16)}",
    loadBias = "0x${loadBias.toString(16)}",
    relativeAddress = "0x${relativeAddress.toString(16)}",
    snapshotGeneration = snapshotGeneration,
    resolved = resolved,
    degraded = degraded,
    warnings = warnings,
    candidates = candidates.map { it.toDto() }
)

private fun tagName(tag: Int) = when (tag) {
    0x2e -> "DW_TAG_subprogram"
    0x1d -> "DW_TAG_inlined_subroutine"
    else -> "0x${tag.toString(16)}"
}

fun LineCandidate.toDto(): CandidateDto = CandidateDto(
    cuOffset = "0x${cuOffset.toString(16)}",
    cuName = cuName,
    cuVersion = cuVersion,
    tableVersion = tableVersion,
    sequenceIndex = sequenceIndex,
    sequenceStart = "0x${sequenceStart.toString(16)}",
    sequenceEnd = "0x${sequenceEnd.toString(16)}",
    matchedAddress = "0x${address.toString(16)}",
    file = file,
    line = line,
    column = column,
    isStmt = isStmt,
    prologueEnd = prologueEnd,
    segment = "0x${segment.toString(16)}",
    rank = rank,
    source = source,
    frames = frames.map {
        FrameDto(
            depth = it.depth,
            name = it.name,
            dieOffset = "0x${it.dieOffset.toString(16)}",
            tag = tagName(it.tag),
            callFile = it.callFile,
            callLine = it.callLine,
            rangeLow = it.rangeLow?.let { v -> "0x${v.toString(16)}" },
            rangeHigh = it.rangeHigh?.let { v -> "0x${v.toString(16)}" },
            width = "0x${it.width.let { w -> if (w == Long.MAX_VALUE) "n/a" else w.toString(16) }}"
        )
    },
    warnings = warnings
)
