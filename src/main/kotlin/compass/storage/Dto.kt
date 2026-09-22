package compass.storage

import compass.model.ParseIssue
import compass.resolve.AddressCandidate
import compass.resolve.AddressExplanation
import compass.resolve.InlineFrame
import compass.resolve.ModuleSnapshot
import kotlinx.serialization.Serializable

@Serializable
data class ImportResponse(
    val versionId: Long,
    val sha256: String,
    val buildId: String?,
    val reused: Boolean,
    val issueCount: Int,
)

@Serializable
data class VersionDto(
    val id: Long,
    val filename: String,
    val sha256: String,
    val buildId: String?,
    val elfClass: String,
    val machine: Int,
    val importedAt: String,
    val isSplit: Boolean = false,
    val dwoId: String? = null,
)

@Serializable
data class SectionDto(
    val name: String, val addr: Long, val fileOffset: Long, val size: Long,
    val sha256: String?, val debug: Boolean, val type: Int, val flags: Long,
)

@Serializable
data class SegmentDto(
    val flags: Int, val fileOffset: Long, val vaddr: Long, val filesz: Long, val memsz: Long,
)

@Serializable
data class CuDto(
    val headerOffset: Long,
    val name: String?,
    val compDir: String?,
    val version: Int,
    val unitType: Int,
    val dieCount: Int,
    val dwoId: String?,
    val dwoName: String?,
    val isSkeleton: Boolean,
    val isSplit: Boolean,
    val language: Int?,
)

@Serializable
data class SequenceDto(
    val cuHeaderOffset: Long,
    val index: Int,
    val dwarfVersion: Int,
    val selector: Long,
    val start: Long,
    val end: Long,
    val rows: List<LineRowDto>,
)

@Serializable
data class LineRowDto(
    val address: Long, val file: Int, val line: Int, val column: Int,
    val endSequence: Boolean, val isStmt: Boolean, val basicBlock: Boolean,
    val prologueEnd: Boolean, val epilogueBegin: Boolean, val isa: Int,
    val discriminator: Int, val trigger: String? = null,
)

@Serializable
data class LineEventDto(val seqIndex: Int, val trigger: String, val row: LineRowDto)

@Serializable
data class FileDto(val id: Int, val name: String, val dirIndex: Int, val mtime: Long, val size: Long)

@Serializable
data class ProgramDto(
    val cuHeaderOffset: Long, val version: Int,
    val files: List<FileDto>, val dirs: List<String>,
    val defaultIsStmt: Boolean, val minInstrLen: Int, val maxOpsPerInstr: Int,
    val sequences: List<SequenceDto>,
)

@Serializable
data class SymbolDto(
    val cuHeaderOffset: Long, val dieOffset: Long, val tag: String,
    val name: String?, val linkageName: String?,
    val ranges: List<RangeDto>, val depth: Int, val inline: Boolean,
    val callFile: String? = null, val callLine: Int? = null, val callColumn: Int? = null,
    val explicitPriority: Long? = null,
)

@Serializable
data class RangeDto(val selector: Long, val start: Long, val end: Long, val zeroLength: Boolean)

@Serializable
data class IssueDto(val severity: String, val code: String, val message: String, val section: String?, val offset: Long?)

@Serializable
data class VersionDetail(
    val version: VersionDto,
    val sections: List<SectionDto>,
    val segments: List<SegmentDto>,
    val cus: List<CuDto>,
    val programs: List<ProgramDto>,
    val symbols: List<SymbolDto>,
    val issues: List<IssueDto>,
    val events: List<LineEventDto>,
    val hasSplitRefs: Boolean,
    val dwoAvailable: List<String>,
    val dwoMissing: List<String>,
)

@Serializable
data class SnapshotDto(
    val id: Long, val versionId: Long, val label: String,
    val loadBase: Long, val firstSegmentVaddr: Long, val bias: Long,
    val generation: Int, val frozenAt: String,
) {
    companion object {
        fun from(s: ModuleSnapshot) = SnapshotDto(
            s.id, s.versionId, s.label, s.loadBase, s.firstSegmentVaddr, s.bias, s.generation, s.frozenAt,
        )
    }
}

@Serializable
data class ResolveRequest(
    val versionId: Long,
    val addresses: List<String>,
    val snapshotIds: List<Long>? = null,
    val saveAs: String? = null,
    val selector: Long = 0,
)

@Serializable
data class PositionDto(val file: String, val line: Int, val column: Int, val fileIndex: Int)

@Serializable
data class InlineFrameDto(
    val symbol: String, val dieTag: String, val depth: Int,
    val callFile: String?, val callLine: Int?, val callColumn: Int?,
    val rangeStart: Long, val rangeEnd: Long, val rangeLength: Long,
) {
    companion object {
        fun from(f: InlineFrame) = InlineFrameDto(
            f.symbol, f.dieTag, f.depth, f.callFile, f.callLine, f.callColumn,
            f.rangeStart, f.rangeEnd, f.rangeLength,
        )
    }
}

@Serializable
data class CandidateDto(
    val kind: String,
    val cuName: String?,
    val cuHeaderOffset: Long,
    val dwarfVersion: Int,
    val sequenceIndex: Int,
    val sequenceStart: Long,
    val sequenceEnd: Long,
    val position: PositionDto?,
    val symbolName: String?,
    val rangeStart: Long,
    val rangeEnd: Long,
    val rangeLength: Long,
    val inlineDepth: Int,
    val explicitPriority: Long?,
    val selector: Long,
    val inlineChain: List<InlineFrameDto>,
    val zeroLength: Boolean,
)

@Serializable
data class ExplanationDto(
    val inputRuntime: Long,
    val inputSelector: Long,
    val relativeAddress: Long,
    val snapshotLabel: String?,
    val bias: Long?,
    val trustLevel: String,
    val lineTableVersions: List<String>,
    val notes: List<String>,
    val best: CandidateDto?,
    val candidates: List<CandidateDto>,
) {
    companion object {
        fun cand(c: AddressCandidate): CandidateDto = CandidateDto(
            c.kind, c.cuName, c.cuHeaderOffset, c.dwarfVersion, c.sequenceIndex,
            c.sequenceStart, c.sequenceEnd,
            c.position?.let { PositionDto(it.file, it.line, it.column, it.fileIndex) },
            c.symbolName, c.rangeStart, c.rangeEnd, c.rangeLength,
            c.inlineDepth, c.explicitPriority, c.selector,
            c.inlineChain.map { InlineFrameDto.from(it) }, c.zeroLength,
        )

        fun from(e: AddressExplanation): ExplanationDto = ExplanationDto(
            e.inputRuntime, e.inputSelector, e.relativeAddress, e.snapshotLabel, e.bias,
            e.trustLevel, e.lineTableVersions, e.notes,
            e.best?.let { cand(it) }, e.candidates.map { cand(it) },
        )
    }
}

@Serializable
data class BatchExplanationDto(
    val explanations: List<ExplanationDto>,
    val orderStable: Boolean,
    val crashId: Long?,
)

@Serializable
data class CrashDto(
    val id: Long, val label: String, val createdAt: String,
    val snapshotId: Long, val addressesJson: String, val resultJson: String,
    val versionFingerprint: String,
)

fun ParseIssue.toDto() = IssueDto(severity, code, message, section, offset)
