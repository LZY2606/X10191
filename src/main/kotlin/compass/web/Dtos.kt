package compass.web

import compass.dwarf.*
import compass.query.AddressExplanation
import compass.query.FrameCandidate
import compass.query.InlineFrame
import compass.query.ResultSource
import kotlinx.serialization.Serializable

@Serializable
data class VersionDto(
    val id: Long,
    val label: String,
    val fileName: String,
    val sha256: String,
    val createdAt: String,
    val dwarfVersions: String,
)

@Serializable
data class SectionDto(
    val name: String,
    val size: Long,
    val addr: String,
    val allocated: Boolean,
    val sha256: String?,
    val error: String?,
)

@Serializable
data class CuDto(
    val index: Int,
    val offset: String,
    val version: Int,
    val name: String?,
    val compDir: String?,
    val isDwo: Boolean,
    val dwoId: String?,
    val stmtList: String?,
    val ranges: List<RangeDto>,
    val split: String,
)

@Serializable
data class RangeDto(val start: String, val end: String, val length: String)

@Serializable
data class SequenceDto(
    val index: Int,
    val start: String,
    val end: String,
    val rows: List<RowDto>,
)

@Serializable
data class RowDto(
    val address: String,
    val file: String?,
    val line: Int,
    val column: Int,
    val endSequence: Boolean,
)

@Serializable
data class TraceDto(
    val address: String,
    val file: Int,
    val line: Int,
    val column: Int,
    val emitted: Boolean,
    val endSequence: Boolean,
    val opcode: String,
)

@Serializable
data class InlineDto(
    val depth: Int,
    val name: String?,
    val tag: String,
    val file: String?,
    val callLine: Int?,
    val callColumn: Int?,
    val rangeStart: String?,
    val rangeEnd: String?,
    val abstractOriginResolved: Boolean,
)

@Serializable
data class CandidateDto(
    val rank: Int,
    val symbol: String?,
    val cuName: String?,
    val filePath: String?,
    val line: Int?,
    val column: Int?,
    val sequenceIndex: Int?,
    val matchedRangeStart: String,
    val matchedRangeEnd: String,
    val rangeLength: String,
    val inlineDepth: Int,
    val inlineChain: List<InlineDto>,
    val priority: Int,
    val source: String,
    val tableVersion: Int?,
    val exact: Boolean,
    val warnings: List<String>,
)

@Serializable
data class Explanations(
    val runtimeAddress: String,
    val relativeAddress: String,
    val loadBias: String,
    val snapshotId: String?,
    val generation: Int?,
    val module: String?,
    val candidates: List<CandidateDto>,
    val warnings: List<String>,
    val trustworthy: Boolean,
    val confidence: String,
) {
    companion object {
        fun from(e: AddressExplanation): Explanations = Explanations(
            runtimeAddress = "0x${e.runtimeAddress.toString(16)}",
            relativeAddress = "0x${e.relativeAddress.toString(16)}",
            loadBias = "0x${e.loadBias.toString(16)}",
            snapshotId = e.snapshotId,
            generation = e.generation,
            module = e.module,
            candidates = e.candidates.map(::candidate),
            warnings = e.warnings,
            trustworthy = e.trustworthy,
            confidence = e.confidence,
        )

        private fun candidate(c: FrameCandidate): CandidateDto = CandidateDto(
            rank = c.rank,
            symbol = c.symbol,
            cuName = c.cuName,
            filePath = c.filePath,
            line = c.line,
            column = c.column,
            sequenceIndex = c.sequenceIndex,
            matchedRangeStart = "0x${c.matchedRangeStart.toString(16)}",
            matchedRangeEnd = "0x${c.matchedRangeEnd.toString(16)}",
            rangeLength = "0x${c.rangeLength.toString(16)}",
            inlineDepth = c.inlineDepth,
            inlineChain = c.inlineChain.map(::inline),
            priority = c.priority,
            source = c.source.name,
            tableVersion = c.tableVersion,
            exact = c.exact,
            warnings = c.warnings,
        )

        private fun inline(f: InlineFrame): InlineDto = InlineDto(
            f.depth, f.name, f.tag, f.file, f.callLine, f.callColumn,
            f.rangeStart?.let { "0x${it.toString(16)}" },
            f.rangeEnd?.let { "0x${it.toString(16)}" },
            f.abstractOriginResolved,
        )
    }
}

fun AddrRange.toDto() = RangeDto("0x${start.toString(16)}", "0x${end.toString(16)}", "0x${length.toString(16)}")
fun ResultSource.name2() = name
