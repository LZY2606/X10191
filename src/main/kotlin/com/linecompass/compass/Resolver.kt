package com.linecompass.compass

import com.linecompass.dwarf.AddressRange
import com.linecompass.dwarf.AttrValue
import com.linecompass.dwarf.CompilationUnit
import com.linecompass.dwarf.CuKind
import com.linecompass.dwarf.DW
import com.linecompass.dwarf.DieNode
import com.linecompass.dwarf.LineRow
import com.linecompass.dwarf.Limits
import com.linecompass.dwarf.LineSequence
import com.linecompass.dwarf.ParsedDebugFile
import com.linecompass.dwarf.RangeKind
import java.util.IdentityHashMap

/**
 * The "address compass": turns a runtime address into every legal source
 * explanation, deterministically ordered. Ordering never depends on import
 * order — only on (priority, width, inline depth, stable offsets).
 */
class CompassResolver(
    private val modulesById: Map<Long, ParsedModule>,
    private val snapshots: Map<Long, QuerySnapshot>
) {
    private val nameCache = IdentityHashMap<DieNode, String>()

    fun resolve(token: String, snapshotId: Long?): AddressResolution {
        val parsed = parseToken(token)
        val snapshot = snapshotId?.let { snapshots[it] }
        val matches = mutableListOf<ModuleMatch>()
        val unmatchedGens = mutableListOf<Int>()

        if (snapshot != null) {
            // Group by (module, generation) so reloads of the same module create
            // distinct explanations of the same relative address.
            val groups = snapshot.modules.groupBy { it.moduleId }
            for ((moduleId, loads) in groups) {
                for (load in loads) {
                    val module = modulesById[moduleId]
                    if (module == null || module.debugFileVersionId != load.debugFileVersionId) {
                        unmatchedGens += load.generation
                        continue
                    }
                    val relative = parsed.address - load.baseAddress
                    val mm = matchModule(module, parsed.segment, relative, load.baseAddress,
                        load.generation, load.name)
                    if (mm.winner != null || mm.candidates.isNotEmpty()) matches += mm
                    else unmatchedGens += load.generation
                }
            }
        } else {
            // No fixed snapshot: every imported module is tried with bias = 0
            // (input treated as a relative/link address).
            for (module in modulesById.values.sortedBy { it.moduleId }) {
                val mm = matchModule(module, parsed.segment, parsed.address, 0L, 0,
                    "module#${module.moduleId}")
                if (mm.winner != null || mm.candidates.isNotEmpty()) matches += mm
            }
        }
        return AddressResolution(token, parsed.address, parsed.segment, matches, unmatchedGens)
    }

    private data class ParsedToken(val segment: Int, val address: Long)

    private fun parseToken(token: String): ParsedToken {
        val t = token.trim().removePrefix("0x").removePrefix("0X")
        return if (t.contains(':')) {
            val (seg, addr) = t.split(":", limit = 2)
            ParsedToken(seg.toLong(16).toInt(), addr.toLong(16))
        } else {
            ParsedToken(0, java.lang.Long.parseUnsignedLong(t, 16))
        }
    }

    private fun matchModule(
        module: ParsedModule, segment: Int, relative: Long, bias: Long,
        generation: Int, moduleName: String
    ): ModuleMatch {
        val parsed = module.parsed
        val cands = mutableListOf<AddressCandidate>()
        for (range in parsed.rangeIndex) {
            if (!range.zeroLength && range.contains(segment, relative)) {
                cands += buildCandidate(range, relative, segment)
            }
        }
        // Deterministic ordering independent of import order.
        val ordered = cands.sortedWith(
            compareBy<AddressCandidate> { it.explicitPriority }
                .thenByUnsigned { it.rangeWidth }
                .thenByDescending { it.inlineDepth }
                .thenBy { it.cu?.offset ?: Long.MAX_VALUE }
                .thenBy { it.die?.offset ?: Long.MAX_VALUE }
                .thenBy { it.range.kind.ordinal }
        )
        val winner = ordered.firstOrNull()?.copy(isWinner = true)
        val winnerList = ordered.mapIndexed { i, c -> if (i == 0) c.copy(isWinner = true) else c }

        val chain = winner?.let { buildInlineChain(it) } ?: emptyList()
        val notes = buildNotes(parsed, winner?.cu, winner, winnerList.size)
        return ModuleMatch(
            moduleId = module.moduleId,
            debugFileVersionId = module.debugFileVersionId,
            moduleName = moduleName,
            loadGeneration = generation,
            loadBias = bias,
            relativeAddress = relative,
            segment = segment,
            candidateCount = winnerList.size,
            winner = winner,
            candidates = winnerList,
            inlineChain = chain,
            reliability = notes
        )
    }

    private fun buildCandidate(range: AddressRange, relative: Long, segment: Int): AddressCandidate {
        val cu = range.cu
        val depth = range.die?.let { inlineDepth(it) } ?: 0
        val sequence = cu?.lineProgram?.sequences
            ?.filter { it.contains(segment, relative) }
            ?.minByOrNull { unsignedWidth(it.startAddress, it.endAddress) }
        val lineHit = sequence?.let { findLineRow(it, relative, segment, cu) }
        val width = unsignedWidth(range.start, range.end)
        val score = scoreCandidate(range, width, depth)
        return AddressCandidate(range, cu, sequence, range.die, depth, width,
            range.explicitPriority, score, false, lineHit)
    }

    private fun scoreCandidate(range: AddressRange, width: Long, depth: Int): Long {
        // Smaller is better; composed only of intrinsic properties.
        val p = range.explicitPriority * SCORE_PRIORITY
        val w = width.coerceAtMost(SCORE_WIDTH_MASK)
        val d = (Limits.MAX_RECURSION - depth.coerceAtMost(Limits.MAX_RECURSION))
        return p + w + d * SCORE_DEPTH
    }

    private fun unsignedWidth(a: Long, b: Long): Long {
        val w = b - a
        return if (w < 0) Long.MAX_VALUE else w
    }

    private fun inlineDepth(die: DieNode): Int {
        var d = 0
        var n: DieNode? = die
        while (n != null) {
            if (n.isInline) d++
            n = n.parent
        }
        return d
    }

    private fun findLineRow(seq: LineSequence, relative: Long, segment: Int, cu: CompilationUnit): LineHit? {
        // Last row whose address <= target in this sequence; end_sequence row address
        // is exclusive (one-past), so only non-end rows before the target count.
        var chosen: LineRow? = null
        for (row in seq.rows) {
            if (row.endSequence) continue
            if (java.lang.Long.compareUnsigned(row.address, relative) <= 0) chosen = row
            else break
        }
        val row = chosen ?: return null
        val version = cu.lineProgram?.version ?: 0
        return LineHit(
            file = row.file.fullPath.ifEmpty { row.file.name },
            line = row.line, column = row.column, isStmt = row.isStmt,
            sequenceStart = seq.startAddress, sequenceEnd = seq.endAddress,
            tableVersion = version, rowOrder = row.order
        )
    }

    private fun buildInlineChain(cand: AddressCandidate): List<InlineFrame> {
        val leaf = cand.die ?: return emptyList()
        val frames = mutableListOf<InlineFrame>()
        var node: DieNode? = leaf
        while (node != null) {
            if (node.isSubprogram || node.isInline) {
                frames += InlineFrame(
                    depth = inlineDepth(node),
                    name = resolveName(node),
                    declaredFile = declaredFile(node),
                    declaredLine = node.num(DW.AT_decl_line)?.toInt(),
                    callFile = callFile(node),
                    callLine = node.num(DW.AT_call_line)?.toInt(),
                    dieOffset = node.offset
                )
            }
            node = node.parent
        }
        // Leaf/innermost first, outermost last.
        return frames.sortedByDescending { it.depth }
    }

    private fun resolveName(die: DieNode): String {
        nameCache[die]?.let { return it }
        die.nameOrNull()?.let { nameCache[die] = it; return it }
        // Follow abstract_origin / specification with a hop limit.
        var hops = 0
        var current: DieNode? = die
        while (current != null && hops < Limits.MAX_REF_HOPS) {
            val refAttr = current.attr(DW.AT_abstract_origin)?.value
                ?: current.attr(DW.AT_specification)?.value
            val ref = (refAttr as? AttrValue.Ref) ?: break
            val cu = current.cu
            val target = cu?.dieByOffset?.get(ref.targetOffset)
                ?: cu?.splitCu?.dieByOffset?.get(ref.targetOffset)
            current = target
            hops++
            current?.nameOrNull()?.let { nameCache[die] = it; return it }
        }
        val fallback = if (die.isInline) "<inlined>" else "<subprogram>"
        nameCache[die] = fallback
        return fallback
    }

    private fun declaredFile(die: DieNode): String? {
        val cu = die.cu ?: return null
        return die.num(DW.AT_decl_file)?.toInt()?.let { idx -> cu.lineProgram?.files?.getOrNull(idx)?.fullPath }
    }

    private fun callFile(die: DieNode): String? {
        val cu = die.cu ?: return null
        return die.num(DW.AT_call_file)?.toInt()?.let { idx -> cu.lineProgram?.files?.getOrNull(idx)?.fullPath }
    }

    private fun buildNotes(
        parsed: ParsedDebugFile, cu: CompilationUnit?, winner: AddressCandidate?, candidateCount: Int
    ): List<ReliabilityNote> {
        val notes = mutableListOf<ReliabilityNote>()
        parsed.issues.filter { it.severity == "ERROR" }.forEach {
            notes += ReliabilityNote("ERROR", it.code, "${it.section}: ${it.message}")
        }
        parsed.issues.filter { it.severity == "WARNING" }.forEach {
            notes += ReliabilityNote("WARNING", it.code, "${it.section}: ${it.message}")
        }
        if (cu?.kind == CuKind.SKELETON && cu.splitMissing) {
            notes += ReliabilityNote("WARNING", "INLINE_PARTIAL",
                "split .dwo unavailable: skeleton CU line/address ranges are trusted, " +
                    "but inline frames inside this CU may be missing")
        }
        if (winner != null && candidateCount > 1) {
            notes += ReliabilityNote("INFO", "OVERLAPPING_RANGES",
                "address is covered by $candidateCount legal ranges; winner selected by " +
                    "explicit priority → narrowest range → deepest inline → stable offset")
        }
        return notes
    }

    companion object {
        private const val SCORE_PRIORITY = 1_000_000_000_000L
        private const val SCORE_WIDTH_MASK = 0x7fffffffffffffffL
        private const val SCORE_DEPTH = 1L
    }
}

private inline fun <T> Comparator<T>.thenByUnsigned(crossinline selector: (T) -> Long): Comparator<T> =
    this.thenComparator { a, b ->
        java.lang.Long.compareUnsigned(selector(a), selector(b))
    }

private inline fun <T> Comparator<T>.thenComparator(crossinline comparison: (a: T, b: T) -> Int): Comparator<T> =
    Comparator { a, b ->
        val r = compare(a, b)
        if (r != 0) r else comparison(a, b)
    }
