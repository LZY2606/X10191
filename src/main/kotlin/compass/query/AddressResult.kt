package compass.query

/**
 * A single legal interpretation of a runtime address. Resolvers must keep *all*
 * valid candidates and order them with a total, deterministic key:
 *   1. narrower containing range first (smaller length, then earlier start);
 *   2. deeper inline chain first;
 *   3. explicit [priority] (skeleton vs split dwo etc.);
 *   4. stable structural offsets as the final tie break.
 */
data class FrameCandidate(
    val rank: Int,
    val symbol: String?,
    val cuName: String?,
    val filePath: String?,
    val line: Int?,
    val column: Int?,
    val sequenceIndex: Int?,
    val matchedRangeStart: ULong,
    val matchedRangeEnd: ULong,
    val rangeLength: ULong,
    val inlineDepth: Int,
    val inlineChain: List<InlineFrame>,
    val priority: Int,
    val source: ResultSource,
    val tableVersion: Int?,
    val exact: Boolean,
    val warnings: List<String>,
)

data class InlineFrame(
    val depth: Int,
    val name: String?,
    val tag: String,
    val file: String?,
    val callLine: Int?,
    val callColumn: Int?,
    val rangeStart: ULong?,
    val rangeEnd: ULong?,
    val abstractOriginResolved: Boolean,
)

enum class ResultSource { LINE_PROGRAM, DIE_RANGE_ONLY, SPLIT_DWO, FALLBACK }

data class AddressExplanation(
    val runtimeAddress: ULong,
    val relativeAddress: ULong,
    val loadBias: ULong,
    val snapshotId: String?,
    val generation: Int?,
    val module: String?,
    val candidates: List<FrameCandidate>,
    val warnings: List<String>,
    val trustworthy: Boolean,
    val confidence: String,
)
