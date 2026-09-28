package com.linecompass.compass

import com.linecompass.dwarf.AddressRange
import com.linecompass.dwarf.CompilationUnit
import com.linecompass.dwarf.DieNode
import com.linecompass.dwarf.LineSequence

data class ParsedModule(
    val moduleId: Long,
    val debugFileVersionId: Long,
    val parsed: com.linecompass.dwarf.ParsedDebugFile,
    val pathHint: String?
)

/** One legal containment explanation for a runtime address. */
data class AddressCandidate(
    val range: AddressRange,
    val cu: CompilationUnit?,
    val sequence: LineSequence?,
    val die: DieNode?,
    val inlineDepth: Int,
    val rangeWidth: Long,
    val explicitPriority: Int,
    val score: Long,
    val isWinner: Boolean,
    val lineHit: LineHit?
)

data class LineHit(
    val file: String,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val sequenceStart: Long,
    val sequenceEnd: Long,
    val tableVersion: Int,
    val rowOrder: Int
)

data class InlineFrame(
    val depth: Int,
    val name: String,
    val declaredFile: String?,
    val declaredLine: Int?,
    val callFile: String?,
    val callLine: Int?,
    val dieOffset: Long
)

data class ModuleMatch(
    val moduleId: Long,
    val debugFileVersionId: Long,
    val moduleName: String,
    val loadGeneration: Int,
    val loadBias: Long,
    /** relative = runtime - loadBias (segment-aware input keeps seg separately). */
    val relativeAddress: Long,
    val segment: Int,
    val candidateCount: Int,
    val winner: AddressCandidate?,
    val candidates: List<AddressCandidate>,
    val inlineChain: List<InlineFrame>,
    val reliability: List<ReliabilityNote>
)

data class ReliabilityNote(
    val level: String, // INFO | WARNING | ERROR
    val code: String,
    val message: String
)

data class AddressResolution(
    val inputToken: String,
    val runtimeAddress: Long,
    val segment: Int,
    val matches: List<ModuleMatch>,
    val unmatchedGenerations: List<Int>
) {
    val resolved: Boolean get() = matches.any { it.winner != null }
}

/**
 * Snapshot semantics: a fixed set of module loads (possibly multiple
 * generations of the same relative address) bound to debug-file versions.
 */
data class SnapshotModule(
    val moduleId: Long,
    val name: String,
    val debugFileVersionId: Long,
    val baseAddress: Long,
    val generation: Int
)

data class QuerySnapshot(
    val id: Long,
    val name: String,
    val modules: List<SnapshotModule>
)
