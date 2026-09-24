package com.compass.dwarf

import kotlinx.serialization.Serializable

@Serializable
data class QueryAddress(val segment: Long = 0, val relative: Long, val runtime: Long? = null)

@Serializable
data class FrameCandidate(
    val name: String?,
    val dieOffset: Long?,
    val tag: Int?,
    val start: Long,
    val end: Long,
    val zeroLength: Boolean,
    val inlineDepth: Int,
    val priority: Int,
    val source: String,
    val callFile: String?,
    val callLine: Int?,
    val callColumn: Int?
)

@Serializable
data class AddressExplanation(
    val input: String,
    val segment: Long,
    val relativeAddress: Long,
    val runtimeAddress: Long?,
    val loadBias: Long?,
    val moduleName: String?,
    val matched: Boolean,
    val file: String? = null,
    val line: Int? = null,
    val column: Int? = null,
    val lineTableVersion: Int? = null,
    val cuName: String? = null,
    val cuOffset: Long? = null,
    val dwarfVersion: Int? = null,
    val sequenceStart: Long? = null,
    val sequenceEnd: Long? = null,
    val sequenceIndex: Int? = null,
    val inlineChain: List<FrameCandidate> = emptyList(),
    val allCandidates: List<FrameCandidate> = emptyList(),
    val confidence: String = "none",
    val trusted: List<String> = emptyList(),
    val warnings: List<String> = emptyList()
)

object AddressResolver {
    private const val maxNameHops = 8

    fun explain(document: DebugDocument, query: QueryAddress, loadBias: Long?, moduleName: String? = null): AddressExplanation {
        val target = query.relative
        val segment = query.segment
        val matchingUnits = document.compilationUnits.filter { cu ->
            cu.lineProgram?.sequences?.any { it.segment == segment && covers(it.startAddress, it.endAddress, target) } == true ||
                cu.ranges.any { it.segment == segment && covers(it.start, it.end, target) }
        }
        val unit = matchingUnits.firstOrNull()
        val lineMatch = unit?.lineProgram?.allRows?.filter { row ->
            !row.endSequence && row.segment == segment && row.address <= target &&
                nextAddress(unit, row)?.let { target < it } ?: false
        }?.minWithOrNull(compareBy<LineRow>({ it.address }, { -it.line }, { -it.column }, { it.index }))
        val sequence = unit?.lineProgram?.sequences?.firstOrNull { seq ->
            seq.segment == segment && covers(seq.startAddress, seq.endAddress, target)
        }
        val rangeCandidates = document.compilationUnits.flatMap { cu ->
            cu.ranges.filter { it.segment == segment && covers(it.start, it.end, target) }.map { range ->
                frame(range, cu, document)
            }
        }.sortedWith(
            compareByDescending<FrameCandidate> { it.priority }
                .thenBy { it.end - it.start }
                .thenByDescending { it.inlineDepth }
                .thenBy { it.start }
                .thenBy { it.dieOffset ?: 0L }
        )
        val chain = buildInlineChain(rangeCandidates, document)
        val file = lineMatch?.let { resolveFile(unit, it.fileIndex) }
        val splitWarnings = (unit?.warnings ?: emptyList()) + document.warnings.filter { it.contains("Split", ignoreCase = true) }
        val matched = lineMatch != null || rangeCandidates.isNotEmpty()
        val confidence = when {
            !matched -> "none"
            splitWarnings.isNotEmpty() && rangeCandidates.any { it.inlineDepth > 0 } -> "partial"
            lineMatch != null && rangeCandidates.isNotEmpty() -> "high"
            lineMatch != null || rangeCandidates.isNotEmpty() -> "partial"
            else -> "none"
        }
        val trusted = buildList {
            if (lineMatch != null) add("Line table row decoded directly from imported bytes")
            if (sequence != null) add("Address belongs to a complete line sequence")
            if (rangeCandidates.isNotEmpty()) add("DIE ranges match without external symbolization")
            if (splitWarnings.isNotEmpty()) add("Skeleton CU and executable-owned line data remain usable; split-only inline or type details may be absent")
        }
        return AddressExplanation(
            input = queryToString(query), segment, target, query.runtime, loadBias, moduleName, matched,
            file, lineMatch?.line, lineMatch?.column, unit?.lineProgram?.version,
            unit?.name, unit?.offset, unit?.version, sequence?.startAddress, sequence?.endAddress, sequence?.index,
            chain, rangeCandidates, confidence, trusted, splitWarnings.distinct()
        )
    }

    private fun covers(start: Long, end: Long, target: Long): Boolean = if (start == end) start == target else target in start until end
    private fun FrameCandidate.width() = end - start

    private fun nextAddress(cu: CompilationUnit, row: LineRow): Long? {
        val rows = cu.lineProgram?.allRows ?: return null
        return rows.drop(row.index + 1).firstOrNull { it.segment == row.segment && !it.endSequence }?.address
            ?: rows.drop(row.index + 1).firstOrNull { it.segment == row.segment && it.endSequence }?.address
    }

    private fun frame(range: DwarfRange, cu: CompilationUnit, document: DebugDocument): FrameCandidate {
        val die = cu.dies.firstOrNull { it.offset == range.dieOffset }
        val callFile = die?.number(DwarfConst.DW_AT_CALL_FILE)?.let { resolveFile(cu, it.toInt()) }
        val callLine = die?.number(DwarfConst.DW_AT_CALL_LINE)?.toInt()
        val callColumn = die?.number(DwarfConst.DW_AT_CALL_COLUMN)?.toInt()
        val priority = when {
            range.tag == DwarfConst.DW_TAG_INLINED_SUBROUTINE -> 30
            range.zeroLength -> 10
            range.source.startsWith("rnglists") || range.source == "debug_ranges" -> 25
            else -> 20
        }
        return FrameCandidate(range.name, range.dieOffset, range.tag, range.start, range.end, range.zeroLength,
            range.inlineDepth, priority, range.source, callFile, callLine, callColumn)
    }

    private fun buildInlineChain(candidates: List<FrameCandidate>, document: DebugDocument): List<FrameCandidate> {
        if (candidates.isEmpty()) return emptyList()
        val deepest = candidates.maxByOrNull { it.inlineDepth } ?: return candidates.take(1)
        val chain = mutableListOf<FrameCandidate>()
        var currentDie = deepest.dieOffset
        repeat(maxNameHops) {
            val located = locateDie(currentDie ?: return@repeat, document) ?: return@repeat
            val cuRange = located.cu.ranges.firstOrNull { it.dieOffset == located.die.offset }
            if (cuRange != null) chain += frame(cuRange, located.cu, document)
            currentDie = located.die.parentOffset
        }
        return chain.distinctBy { it.dieOffset }.sortedByDescending { it.inlineDepth }.ifEmpty { candidates.take(1) }
    }

    private data class LocatedDie(val cu: CompilationUnit, val die: DieNode)
    private fun locateDie(offset: Long, document: DebugDocument): LocatedDie? {
        document.compilationUnits.forEach { cu ->
            cu.dies.firstOrNull { it.offset == offset }?.let { return LocatedDie(cu, it) }
        }
        return null
    }

    private fun resolveFile(cu: CompilationUnit?, index: Int): String? {
        val program = cu?.lineProgram ?: return null
        val lineFile = program.files.firstOrNull { it.index == index } ?: return null
        val dir = lineFile.directoryIndex?.let { idx -> program.directories.getOrNull((idx - 1).coerceAtLeast(0)) }
            ?: cu.compilationDirectory
        return when {
            lineFile.name.startsWith('/') -> lineFile.name
            dir.isNullOrBlank() -> lineFile.name
            dir.endsWith('/') -> dir + lineFile.name
            else -> "$dir/${lineFile.name}"
        }
    }

    private fun queryToString(query: QueryAddress): String =
        if (query.segment == 0L) "0x${query.relative.toString(16)}" else "${query.segment}:0x${query.relative.toString(16)}"
}
