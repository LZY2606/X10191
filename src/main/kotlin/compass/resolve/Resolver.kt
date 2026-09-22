package compass.resolve

import compass.dwarf.*
import kotlinx.serialization.Serializable

@Serializable
data class InlineFrame(
    val function: String,
    val depth: Int,
    val callFile: String?,
    val callLine: Int?,
    val dieOffset: Long
)

@Serializable
data class AddressCandidate(
    val rank: Int,
    val file: String?,
    val line: Int?,
    val column: Int,
    val function: String?,
    val cu: String?,
    val cuVersion: Int,
    val cuOffset: Long,
    val sequenceStart: Long,
    val sequenceEnd: Long,
    val rangeStart: Long,
    val rangeEnd: Long,
    val rangeWidth: Long,
    val inlineDepth: Int,
    val inlineChain: List<InlineFrame>,
    val isZeroLengthMatch: Boolean,
    val tableVersion: Int,
    val confidence: String
)

@Serializable
data class AddressResolution(
    val runtimeAddress: Long,
    val fileRelativeAddress: Long,
    val moduleName: String,
    val moduleBuildId: String?,
    val loadBias: Long,
    val loadGeneration: Int,
    val segment: Int,
    val candidates: List<AddressCandidate>,
    val primary: AddressCandidate?,
    val notes: List<String>,
    val trusted: Boolean
)

data class ModuleSnapshot(
    val name: String,
    val buildId: String?,
    val loadBias: Long,
    val generation: Int,
    val segment: Int,
    val index: DwarfIndex
)

object AddressResolver {

    fun resolve(
        runtime: Long,
        modules: List<ModuleSnapshot>,
        tableVersionOverride: Int? = null
    ): List<Pair<ModuleSnapshot, AddressResolution>> {
        return modules.mapNotNull { mod ->
            // runtime address minus load bias = file-relative VMA
            val rel = runtime - mod.loadBias
            val notes = ArrayList<String>()
            val inImage = mod.index.elf.segments.any { it.contains(rel) } ||
                mod.index.cus.flatMap { it.ranges }.any { it.contains(rel) || it.start == rel } ||
                mod.index.allSequences.any { it.covers(rel) } ||
                mod.index.scopes.any { sc -> sc.ranges.any { r ->
                    if (r.end > r.start) rel in r.start until r.end else rel == r.start } }
            if (!inImage) return@mapNotNull null
            resolveInModule(runtime, rel, mod, notes)?.let { mod to it }
        }.let { pairs ->
            // stable order across import sequences: by module name, buildId, generation
            pairs.sortedWith(compareBy({ it.first.name }, { it.first.buildId ?: "" }, { it.first.generation }))
        }
    }

    private fun resolveInModule(
        runtime: Long,
        rel: Long,
        mod: ModuleSnapshot,
        notes: MutableList<String>
    ): AddressResolution? {
        val idx = mod.index
        val candidates = ArrayList<AddressCandidate>()

        for (cu in idx.cus) {
            // 1) Line rows — find best sequence/row.
            for (seq in cu.sequences) {
                if (!seq.covers(rel)) continue
                val row = seq.rowFor(rel) ?: continue
                val seqEnd = seq.rows.lastOrNull()?.address ?: continue
                // 2) enclosing scopes, narrowest first.
                val enclosing = idx.scopes
                    .filter { it.cuOffset == cu.offset && it.ranges.any { r -> matchRange(r, rel) } }
                    .sortedWith(scopeCandidateOrder(rel))

                val outer = enclosing.lastOrNull { it.tag == DW.TAG_SUBPROGRAM }
                val inlineChain = buildInlineChain(enclosing)
                val narrowest = enclosing.firstOrNull()
                val range = narrowest?.ranges?.filter { matchRange(it, rel) }?.minByOrNull { it.width(rel) }

                candidates.add(AddressCandidate(
                    rank = 0,
                    file = row.file?.fullPath,
                    line = if (row.endSequence) null else row.line,
                    column = row.column,
                    function = (narrowest ?: outer)?.name,
                    cu = cu.name,
                    cuVersion = cu.version,
                    cuOffset = cu.offset.toLong(),
                    sequenceStart = seq.startAddress,
                    sequenceEnd = seqEnd,
                    rangeStart = range?.start ?: row.address,
                    rangeEnd = range?.end ?: row.address,
                    rangeWidth = range?.let { it.end - it.start } ?: 0L,
                    inlineDepth = narrowest?.inlineDepth ?: 0,
                    inlineChain = inlineChain,
                    isZeroLengthMatch = range != null && range.end == range.start,
                    tableVersion = cu.version,
                    confidence = when {
                        range == null -> "line-only (no enclosing function range)"
                        range.end == range.start -> "zero-length exact-PC match"
                        else -> "exact range + line row"
                    }
                ))
            }
            // 2b) range-only match with no line row (e.g. missing .dwo line section).
            if (cu.sequences.none { it.covers(rel) }) {
                val enclosing = idx.scopes
                    .filter { it.cuOffset == cu.offset && it.ranges.any { r -> matchRange(r, rel) } }
                    .sortedWith(scopeCandidateOrder(rel))
                val best = enclosing.firstOrNull() ?: continue
                val range = best.ranges.filter { matchRange(it, rel) }.minByOrNull { it.width(rel) }!!
                notes.add("CU '${cu.name}': PC 0x${rel.toString(16)} matched function range but no line sequence " +
                    "(line table absent or incomplete)")
                candidates.add(AddressCandidate(
                    rank = 0, file = null, line = null, column = 0,
                    function = best.name, cu = cu.name, cuVersion = cu.version,
                    cuOffset = cu.offset.toLong(),
                    sequenceStart = 0, sequenceEnd = 0,
                    rangeStart = range.start, rangeEnd = range.end,
                    rangeWidth = range.end - range.start,
                    inlineDepth = best.inlineDepth,
                    inlineChain = buildInlineChain(enclosing),
                    isZeroLengthMatch = range.end == range.start,
                    tableVersion = cu.version,
                    confidence = "range-only (no line row)"
                ))
            }
        }

        if (candidates.isEmpty()) {
            notes.add("PC 0x${rel.toString(16)} lies within the image but no DWARF coverage found")
            return AddressResolution(
                runtime, rel, mod.name, mod.buildId, mod.loadBias, mod.generation, mod.segment,
                emptyList(), null, notes, trusted = false
            )
        }

        val ranked = candidates.sortedWith(
            compareBy<AddressCandidate> { it.isZeroLengthMatch && it.rangeWidth > 0 } // non-zero first
                .thenBy { it.rangeWidth.takeIf { w -> w > 0 } ?: Long.MAX_VALUE }   // narrowest
                .thenByDescending { it.inlineDepth }                                  // deepest inline
                .thenBy { it.cuOffset }
                .thenBy { it.sequenceStart }
                .thenBy { it.rangeStart }
        ).mapIndexed { i, c -> c.copy(rank = i) }

        val primary = ranked.first()
        if (ranked.size > 1) notes.add("${ranked.size} legal candidates retained; ties broken by narrowest range, " +
            "then inline depth, then stable offsets")

        val trusted = primary.line != null
        return AddressResolution(
            runtime, rel, mod.name, mod.buildId, mod.loadBias, mod.generation, mod.segment,
            ranked, primary, notes, trusted
        )
    }

    private fun matchRange(r: RangeEntry, vma: Long): Boolean {
        if (r.end > r.start) return vma in r.start until r.end
        return r.start == vma // zero-length range: exact PC only
    }

    private fun RangeEntry.width(vma: Long): Long = when {
        end > start -> end - start
        else -> 0L
    }

    private fun scopeCandidateOrder(vma: Long): Comparator<Scope> =
        compareBy<Scope> { sc ->
            sc.ranges.filter { matchRange(it, vma) }.minOfOrNull { if (it.end > it.start) it.end - it.start else Long.MAX_VALUE }
                ?: Long.MAX_VALUE
        }.thenByDescending { it.inlineDepth }
            .thenBy { it.dieOffset }

    private fun buildInlineChain(enclosing: List<Scope>): List<InlineFrame> =
        enclosing.filter { it.tag == DW.TAG_SUBPROGRAM || it.tag == DW.TAG_INLINED_SUBROUTINE }
            .sortedBy { it.inlineDepth }
            .map {
                InlineFrame(
                    function = it.name,
                    depth = it.inlineDepth,
                    callFile = it.callFile,
                    callLine = it.callLine,
                    dieOffset = it.dieOffset.toLong()
                )
            }
}
