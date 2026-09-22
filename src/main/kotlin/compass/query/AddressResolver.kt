package compass.query

import compass.dwarf.*

/** A pinned runtime view of one loaded module (a "load generation"). */
data class ModuleLoad(
    val moduleName: String,
    val runtimeBase: Long?,   // explicit runtime base; null => derive lowest PT_LOAD vaddr
    val fileBase: Long?,      // explicit file-side base; null => lowest PT_LOAD vaddr
    val note: String? = null,
)

data class LineHit(
    val file: String?,
    val directory: String?,
    val line: Int,
    val column: Int,
    val sequenceOffset: Long,
    val cuVersion: Int,
    val sequenceIndex: Int,
    val rowIndex: Int,
    val statement: Boolean,
    val endSequence: Boolean,
)

data class FunctionCandidate(
    val name: String?,
    val tag: Int,
    val cuName: String?,
    val start: Long,
    val end: Long,
    val width: Long,
    val inlineDepth: Int,
    val explicitPriority: Int,
    val inlineChain: List<InlineChainLink>,
    val dieOffset: Long,
    val trustNotes: List<String>,
)

data class InlineChainLink(
    val name: String?,
    val tag: Int,
    val start: Long,
    val end: Long,
    val callFile: String?,
    val callLine: Int,
    val callColumn: Int,
)

data class AddressExplanation(
    val inputAddress: String,
    val runtimeAddress: Long,
    val relativeAddress: Long,
    val loadBias: Long,
    val module: String,
    val loadGenerationIndex: Int,
    val tableVersion: Int?,
    val cuName: String?,
    val cuOffset: Long?,
    val line: LineHit?,
    val functionCandidates: List<FunctionCandidate>,
    val sequenceCount: Int,
    val notes: List<String>,
    val confidence: String, // HIGH / MEDIUM / LOW
)

class AddressResolver(private val model: DwarfModel) {

    private val lineSequences = model.allSequences
    private val subprograms = model.subprograms()

    /**
     * Resolve one runtime address against every pinned module load. When the same
     * relative address appears in multiple load generations, each generation is
     * reported separately so history is not collapsed.
     */
    fun resolve(runtimeAddressHex: String, loads: List<ModuleLoad>): List<AddressExplanation> {
        val runtime = parseAddress(runtimeAddressHex)
        if (loads.isEmpty()) {
            return listOf(resolveWithBase(runtimeAddressHex, runtime, 0L, model.fileName, 0, null, null))
        }
        return loads.mapIndexed { i, load ->
            val fileBase = load.fileBase ?: model.main.elf.defaultLoadBase()
            val runtimeBase = load.runtimeBase ?: runtime // bias 0 fallback
            val bias = runtimeBase - fileBase
            resolveWithBase(runtimeAddressHex, runtime, bias, load.moduleName, i, fileBase, runtimeBase)
        }
    }

    private fun resolveWithBase(
        input: String, runtime: Long, bias: Long, module: String, generation: Int,
        fileBase: Long?, runtimeBase: Long?,
    ): AddressExplanation {
        val relative = runtime - bias
        val notes = mutableListOf<String>()
        val seqHits = lineSequences.mapIndexedNotNull { si, seq ->
            if (!seq.contains(relative)) return@mapIndexedNotNull null
            val ri = findRow(seq, relative)
            if (ri >= 0) Triple(si, seq, ri) else null
        }
        // Keep all sequences that cover the address; the "primary" is chosen stably.
        val primary = seqHits
            .sortedWith(compareByDescending<Triple<Int, LineSequence, Int>> { it.third }
                .thenBy { it.first })
            .firstOrNull()
        val lineHit = primary?.let { (si, seq, ri) -> toLineHit(seq, ri, si) }
        if (seqHits.size > 1) notes.add("address is covered by ${seqHits.size} line sequences; primary is the most specific row")
        if (lineHit == null) notes.add("no line table row covers relative address 0x${relative.toString(16)}")

        // Function / inline candidates: retain *all* legal candidates (overlapping functions).
        val candidates = subprograms.mapNotNull { info ->
            val match = info.ranges.firstOrNull { it.contains(relative) } ?: return@mapNotNull null
            val chain = buildInlineChain(info.die, relative)
            FunctionCandidate(
                name = model.nameOf(info.die),
                tag = info.die.tag,
                cuName = model.stringOf(info.cu.root?.at(Dw.AT_name), info.cu),
                start = match.start, end = match.end, width = match.width.coerceAtLeast(0L),
                inlineDepth = chain.size - 1,
                explicitPriority = priorityOf(info.die),
                inlineChain = chain.map { linkOf(it, relative) },
                dieOffset = info.die.offset,
                trustNotes = info.trust,
            )
        }
        val sorted = stableSortCandidates(candidates)
        val cu = primary?.let { findCuForSeq(it.second) }
        val cuName = cu?.let { model.stringOf(it.root?.at(Dw.AT_name), it) }
        cu?.warnings?.takeIf { it.isNotEmpty() }?.let { notes.addAll(it.map { w -> "CU: $w" }) }
        if (model.allWarnings.isNotEmpty()) notes.addAll(model.allWarnings)

        val confidence = when {
            lineHit != null && sorted.isNotEmpty() && notes.isEmpty() -> "HIGH"
            lineHit != null || sorted.isNotEmpty() -> "MEDIUM"
            else -> "LOW"
        }
        return AddressExplanation(
            inputAddress = input, runtimeAddress = runtime, relativeAddress = relative,
            loadBias = bias, module = module, loadGenerationIndex = generation,
            tableVersion = lineHit?.cuVersion, cuName = cuName ?: sorted.firstOrNull()?.cuName,
            cuOffset = cu?.headerOffset ?: model.allUnits.firstOrNull()?.headerOffset,
            line = lineHit, functionCandidates = sorted,
            sequenceCount = seqHits.size, notes = notes.distinct(), confidence = confidence,
        )
    }

    /** Stable ordering: narrowest range, then deepest inline chain, then explicit priority. */
    fun stableSortCandidates(c: List<FunctionCandidate>): List<FunctionCandidate> =
        c.sortedWith(
            compareBy<FunctionCandidate> { it.width }
                .thenByDescending { it.inlineDepth }
                .thenByDescending { it.explicitPriority }
                .thenBy { it.cuName ?: "" }
                .thenBy { it.dieOffset }
        )

    private fun priorityOf(die: DIE): Int = when (die.tag) {
        Dw.TAG_inlined_subroutine -> 3
        Dw.TAG_subprogram -> 2
        Dw.TAG_GNU_call_site -> 1
        else -> 0
    }

    private fun findRow(seq: LineSequence, addr: Long): Int {
        // Last non-end row with address <= addr within the active sequence.
        var best = -1
        for (i in seq.rows.indices) {
            val r = seq.rows[i]
            if (r.endSequence) continue
            if (r.address <= addr) best = i else break
        }
        return best
    }

    private fun toLineHit(seq: LineSequence, rowIndex: Int, seqIndex: Int): LineHit {
        val row = seq.rows[rowIndex]
        val file = seq.files.getOrNull(row.fileIndex - 1)?.name
        val dir = seq.directories.getOrNull(seq.files.getOrNull(row.fileIndex - 1)?.directoryIndex ?: 0)
        return LineHit(file, dir, row.line, row.column, seq.headerOffset, seq.cuVersion, seqIndex, rowIndex,
            row.isStatement, row.endSequence)
    }

    private fun findCuForSeq(seq: LineSequence): CompUnit? =
        model.allUnits.firstOrNull { cu ->
            val stmt = cu.root?.at(Dw.AT_stmt_list)?.asLong()
            stmt == seq.unitOffset
        } ?: model.allUnits.minByOrNull { kotlin.math.abs(it.headerOffset - seq.headerOffset) }

    /**
     * Walk from the containing (possibly inlined) subprogram up to the outermost
     * concrete function, then present outer->inner. Hop-limited against cycles.
     */
    private fun buildInlineChain(inner: DIE, addr: Long): List<DIE> {
        val chain = ArrayDeque<DIE>()
        var d: DIE? = inner
        var hops = 0
        while (d != null && hops < 128) {
            chain.addFirst(d)
            if (d.tag == Dw.TAG_subprogram && d.parent?.tag != Dw.TAG_inlined_subroutine) break
            d = d.parent
            // stop at CU root
            if (d != null && d.tag == Dw.TAG_compile_unit) break
            hops++
        }
        return chain.toList()
    }

    private fun linkOf(die: DIE, addr: Long): InlineChainLink {
        val info = model.dieInfos.firstOrNull { it.die === die }
        val range = info?.ranges?.firstOrNull { it.contains(addr) }
        val callFileAttr = die.at(Dw.AT_call_file)?.asLong()?.toInt()
        val cu = model.cuOf(die)
        val callFileName = if (callFileAttr != null && cu != null) {
            val seq = model.allSequences.firstOrNull { s ->
                cu.root?.at(Dw.AT_stmt_list)?.asLong() == s.unitOffset
            }
            seq?.files?.getOrNull(callFileAttr - 1)?.name
        } else null
        return InlineChainLink(
            name = model.nameOf(die),
            tag = die.tag,
            start = range?.start ?: info?.ranges?.minOfOrNull { it.start } ?: 0L,
            end = range?.end ?: info?.ranges?.maxOfOrNull { it.end } ?: 0L,
            callFile = callFileName,
            callLine = die.at(Dw.AT_call_line)?.asLong()?.toInt() ?: 0,
            callColumn = die.at(Dw.AT_call_column)?.asLong()?.toInt() ?: 0,
        )
    }

    companion object {
        fun parseAddress(s: String): Long {
            val t = s.trim().removePrefix("0x").removePrefix("0X")
            return t.toLong(16)
        }
    }
}
