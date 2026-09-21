package compass.resolve

import compass.dwarf.*

/** A single scoped DIE with its resolved (possibly zero-length) ranges. */
data class ScopeEntry(
    val die: Die,
    val name: String?,
    val linkageName: String?,
    val ranges: List<AddrRange>,
    val depth: Int,
    val isInline: Boolean,
    val callFile: String?,
    val callLine: Int?,
    val cuIndex: Int,
)

data class LineHit(
    val cuIndex: Int,
    val sequenceIndex: Int,
    val row: LineRow,
    val filePath: String?,
)

data class InlineFrame(
    val name: String,
    val linkageName: String?,
    val depth: Int,
    val callFile: String?,
    val callLine: Int?,
    val dieOffset: Long,
)

data class AddressCandidate(
    val moduleKey: String,
    val moduleVersion: Int,
    val moduleFileName: String,
    val loadBias: Long,
    val generation: Int,
    val inputAddress: Long,
    val relativeAddress: Long,
    val cuName: String?,
    val cuCompDir: String?,
    val cuOffset: Long,
    val cuVersion: Int,
    val tableVersion: String,
    val scopeName: String?,
    val filePath: String?,
    val line: Int?,
    val column: Int?,
    val sequenceIndex: Int?,
    val matchedRangeStart: Long?,
    val matchedRangeEnd: Long?,
    val matchedRangeLength: Long?,
    val inlineDepth: Int,
    val inlineChain: List<InlineFrame>,
    val priority: Int,
    /** stable tiebreak components, ascending preferred */
    val rangeLength: Long,
    val cuIndex: Int,
    val dieOffset: Long,
    val dwoMissing: Boolean,
    val warnings: List<String>,
    val source: String, // "dwarf" | "line-only"
)

data class QueryExplanation(
    val inputAddress: Long,
    val resolved: Boolean,
    val loadBias: Long?,
    val generation: Int?,
    val moduleKey: String?,
    val moduleVersion: Int?,
    val candidates: List<AddressCandidate>,
    val warnings: List<String>,
    val notes: List<String>,
)
