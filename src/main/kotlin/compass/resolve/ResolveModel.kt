package compass.resolve

import compass.dwarf.AddrRange
import compass.util.U64
import kotlinx.serialization.Serializable

@Serializable
data class InlineFrame(
    val depth: Int,
    val dieOffset: U64,
    val tag: String,
    val name: String,
    val linkageName: String?,
    val inline: String,
    val declarationFile: String?,
    val declarationLine: Int?,
    val callFile: String?,
    val callLine: Int?,
    val ranges: List<AddrRange>,
    val width: U64
)

@Serializable
data class LineHit(
    val file: String,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val endSequence: Boolean,
    val trigger: String,
    val sequenceStart: U64,
    val sequenceEnd: U64,
    val dwarfVersion: Int,
    val cuOffset: U64,
    val cuName: String?,
    val lineSource: String // "split" | "skeleton" | "cu" | "none"
)

@Serializable
data class FunctionCandidate(
    val selected: Boolean,
    val moduleId: Long,
    val name: String,
    val linkageName: String?,
    val kind: String, // die | symbol
    val source: String, // dwarf | symtab | dynsym | unknown
    val priority: Int,
    val cuOffset: U64?,
    val cuName: String?,
    val range: AddrRange?,
    val width: U64,
    val inlineDepth: Int,
    val scoreExplanation: String,
    val inlineChain: List<InlineFrame>,
    val trust: String
)

@Serializable
data class ResolveResult(
    val runtimeAddress: U64,
    val relativeAddress: U64?,
    val segment: Int,
    val moduleId: Long?,
    val moduleName: String,
    val loadBias: U64?,
    val snapshotId: Long?,
    val snapshotGeneration: Int,
    val cuOffset: U64?,
    val cuName: String?,
    val cuDwarfVersion: Int?,
    val cuKind: String?,
    val line: LineHit?,
    val functionName: String?,
    val candidates: List<FunctionCandidate>,
    val issues: List<String>,
    val trust: String
)
