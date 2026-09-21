package compass.resolve

import compass.dwarf.AddrRange
import compass.dwarf.CompilationUnit
import compass.dwarf.Die
import compass.dwarf.DwAt
import compass.dwarf.DwTag
import compass.dwarf.LineProgram
import compass.dwarf.LineRow
import compass.dwarf.LineSequence
import compass.dwarf.tagName
import compass.elf.SymbolInfo
import compass.util.U64

/**
 * One entry in a pinned load snapshot: a module loaded at a concrete load bias,
 * belonging to a generation (each re-load of the same relative address gets a new one).
 */
data class LoadEntry(
    val module: LoadedModule,
    val loadBias: U64,
    val baseAddress: U64, // preferred load base used to compute relative addresses
    val generation: Int
)

data class Snapshot(val id: Long, val name: String, val entries: List<LoadEntry>)

data class BatchAddress(val raw: String, val address: U64?, val parseError: String? = null)

class ResolvedAddress(
    val result: compass.resolve.ResolveResult,
    val entry: LoadEntry?
)

/**
 * Pure in-memory address -> source compass.
 *
 * Determinism: ties are broken by (width asc, depth desc, priority asc, moduleId asc,
 * CU offset asc, DIE offset asc), so the result is independent of file import order.
 */
class AddressResolver {

    fun resolveBatch(snapshot: Snapshot, rawList: List<String>, segment: Int = 0): List<ResolveResult> =
        rawList.map { resolveOne(snapshot, it, segment) }

    fun resolveOne(snapshot: Snapshot, raw: String, segment: Int): ResolveResult {
        val addr = try { U64.parse(raw) } catch (e: Exception) {
            return ResolveResult(
                runtimeAddress = U64.ZERO, relativeAddress = null, segment = segment,
                moduleId = null, moduleName = "?", loadBias = null, snapshotId = snapshot.id,
                snapshotGeneration = 0, cuOffset = null, cuName = null, cuDwarfVersion = null,
                cuKind = null, line = null, functionName = null, candidates = emptyList(),
                issues = listOf("address '$raw' is not a valid hex/decimal 64-bit value"),
                trust = "none"
            )
        }
        return resolveParsed(snapshot, addr, segment)
    }

    fun resolveParsed(snapshot: Snapshot, runtime: U64, segment: Int): ResolveResult {
        // Find every entry whose module image could contain the runtime address.
        val matches = snapshot.entries.mapNotNull { e ->
            // relative = runtime - loadBias; for a standard ELF this is already the linked vaddr
            val relative = U64(runtime.v - e.loadBias.v)
            if (imageContains(e.module, segment, relative)) e to relative else null
        }

        if (matches.isEmpty()) {
            return ResolveResult(
                runtimeAddress = runtime, relativeAddress = null, segment = segment,
                moduleId = null, moduleName = "(no loaded module covers address)",
                loadBias = null, snapshotId = snapshot.id, snapshotGeneration = 0,
                cuOffset = null, cuName = null, cuDwarfVersion = null, cuKind = null,
                line = null, functionName = null, candidates = emptyList(),
                issues = listOf("runtime address not covered by any module in snapshot '${snapshot.name}'"),
                trust = "none"
            )
        }

        val allCandidates = ArrayList<Candidate>()
        var best: Candidate? = null
        var bestEntry: LoadEntry? = null
        for ((entry, relative) in matches) {
            val virtual = relative
            val cands = candidatesFor(entry.module, segment, virtual)
            for (c in cands) {
                allCandidates += c
                if (best == null || compare(c, best!!) < 0) {
                    best = c; bestEntry = entry
                }
            }
        }

        val chosenEntry = bestEntry ?: matches.first().first
        val chosenRel = U64(runtime.v - chosenEntry.loadBias.v)
        val chosenVirtual = chosenRel
        val selected = best
        val lineHit = selected?.let { lineFor(it, chosenEntry, segment, chosenVirtual) }

        val functionCandidates = allCandidates.map { c ->
            val frames = inlineChain(c)
            FunctionCandidate(
                selected = c === selected,
                moduleId = c.module.id,
                name = c.displayName(),
                linkageName = c.linkageName(),
                kind = if (c is DieCandidate) "die" else "symbol",
                source = c.sourceName(),
                priority = c.priority(),
                cuOffset = c.cu?.offset,
                cuName = c.cu?.name,
                range = c.rangeFor(segment),
                width = c.width(segment),
                inlineDepth = frames.size - 1,
                scoreExplanation = c.explain(),
                inlineChain = frames,
                trust = c.trustLevel()
            )
        }.sortedWith(compareBy(
            { !it.selected }, { it.width }, { -it.inlineDepth }, { it.priority },
            { it.moduleId ?: Long.MAX_VALUE }, { it.cuOffset ?: U64.MAX }, { it.range?.start ?: U64.MAX }
        ))

        val issues = collectIssues(chosenEntry, selected, lineHit)
        val trust = overallTrust(chosenEntry, selected, lineHit)

        return ResolveResult(
            runtimeAddress = runtime,
            relativeAddress = chosenRel,
            segment = segment,
            moduleId = chosenEntry.module.id,
            moduleName = chosenEntry.module.name,
            loadBias = chosenEntry.loadBias,
            snapshotId = snapshot.id,
            snapshotGeneration = chosenEntry.generation,
            cuOffset = selected?.cu?.offset ?: firstDieCu(allCandidates),
            cuName = selected?.cu?.name,
            cuDwarfVersion = selected?.cu?.dwarfVersion,
            cuKind = selected?.cu?.kind,
            line = lineHit,
            functionName = selected?.displayName(),
            candidates = functionCandidates,
            issues = issues,
            trust = trust
        )
    }

    private fun firstDieCu(cands: List<Candidate>): U64? =
        cands.filterIsInstance<DieCandidate>().minByOrNull { it.cu.offset }?.cu?.offset

    private fun imageContains(module: LoadedModule, segment: Int, virtual: U64): Boolean {
        val segs = module.bundle.elf.segments
        if (segs.isNotEmpty()) return segs.any { it.contains(virtual) }
        val secs = module.bundle.elf.sections.filter { it.size.v != 0L }
        if (secs.isNotEmpty()) return secs.any {
            virtual >= it.addr && virtual < U64(it.addr.v + it.size.v)
        }
        // no allocation metadata: accept and let ranges decide
        return true
    }

    // -------- candidate collection --------

    private sealed interface Candidate {
        val module: LoadedModule
        val cu: CompilationUnit?
        fun rangeFor(segment: Int): AddrRange?
        fun width(segment: Int): U64
        fun displayName(): String
        fun linkageName(): String?
        fun priority(): Int
        fun sourceName(): String
        fun explain(): String
        fun trustLevel(): String
        fun stableKey(): Long
    }

    private class DieCandidate(
        override val module: LoadedModule,
        override val cu: CompilationUnit,
        val die: Die,
        val matched: AddrRange,
        val depth: Int
    ) : Candidate {
        override fun rangeFor(segment: Int) = matched
        override fun width(segment: Int) = U64(matched.end.v - matched.start.v)
        override fun displayName(): String = die.linkageName ?: die.name ?: ("${die.tagName()}@${die.offset}")
        override fun linkageName() = die.linkageName
        override fun priority() = when (die.tag) {
            DwTag.INLINED_SUBROUTINE -> 0
            DwTag.SUBPROGRAM -> 1
            DwTag.LEXICAL_BLOCK -> 2
            else -> 3
        }
        override fun sourceName() = "dwarf"
        override fun explain(): String =
            "DWARF ${die.tagName()} range ${matched.start}..${matched.end} (${matched.source}), " +
                "width=${width(matched.segment)}, inlineDepth=$depth, tagPriority=${priority()}"
        override fun trustLevel(): String =
            if (cu.issues.any { it.severity == "error" }) "partial" else "high"
        override fun stableKey() = die.offset.v
    }

    private class SymbolCandidate(
        override val module: LoadedModule,
        val symbol: SymbolInfo,
        val priority: Int,
        val source: String
    ) : Candidate {
        override val cu: CompilationUnit? = null
        override fun rangeFor(segment: Int) =
            if (symbol.size.v == 0L) AddrRange(symbol.value, symbol.value, source = "symbol(zero-size)")
            else AddrRange(symbol.value, U64(symbol.value.v + symbol.size.v), source = "symbol")
        override fun width(segment: Int) = U64(symbol.size.v)
        override fun displayName() = symbol.name
        override fun linkageName(): String? = null
        override fun priority() = priority
        override fun sourceName() = source
        override fun explain() =
            "ELF symbol '${symbol.name}' @ ${symbol.value} size=${symbol.size.v}, source=$source priority=$priority"
        override fun trustLevel() = "medium"
        override fun stableKey() = symbol.value.v xor symbol.name.hashCode().toLong()
    }

    private fun candidatesFor(entry: LoadedModule, segment: Int, virtual: U64): List<Candidate> {
        val out = ArrayList<Candidate>()
        for (eff in CuView.effective(entry.bundle)) {
            val effective = eff.cu
            val dies = scopeDies(effective, segment, virtual)
            for (die in dies) {
                val matched = die.ranges.first { it.contains(segment, virtual) || (it.zeroLength && it.start == virtual) }
                val depth = inlineDepthAt(effective, die)
                out += DieCandidate(entry, effective, die, matched, depth)
            }
        }
        // symbol fallback: STT_FUNC (2) from .symtab (priority 2) / .dynsym (3)
        for (sym in entry.symbols()) {
            if (sym.type != 2) continue
            val end = if (sym.size.v == 0L) U64(sym.value.v + 1) else U64(sym.value.v + sym.size.v)
            if (virtual >= sym.value && virtual < end) {
                val priority = if (sym.source == "symtab") 2 else 3
                out += SymbolCandidate(entry, sym, priority, sym.source)
            }
        }
        return out
    }

    private fun scopeDies(cu: CompilationUnit, segment: Int, addr: U64): List<Die> {
        val out = ArrayList<Die>()
        for (die in cu.dies) {
            if (die.tag != DwTag.SUBPROGRAM && die.tag != DwTag.INLINED_SUBROUTINE && die.tag != DwTag.LEXICAL_BLOCK) continue
            if (die.ranges.isEmpty()) continue
            for (rg in die.ranges) {
                if (rg.contains(segment, addr) || (rg.zeroLength && rg.start == addr)) { out += die; break }
            }
        }
        return out
    }

    private fun inlineDepthAt(cu: CompilationUnit, die: Die): Int {
        if (die.tag != DwTag.INLINED_SUBROUTINE) return 0
        var d = 0
        var cur: Die? = die
        val byOff = HashMap<U64, Die>().apply { cu.dies.forEach { put(it.offset, it) } }
        while (cur != null) {
            val p = cur.parentOffset ?: break
            cur = byOff[p]
            if (cur != null && cur.tag == DwTag.INLINED_SUBROUTINE) d++
        }
        return d + 1
    }

    private fun compare(a: Candidate, b: Candidate): Int {
        // 1) narrowest range (zero-width is most specific)
        var c = a.width(0).compareTo(b.width(0))
        if (c != 0) return c
        // 2) inline depth (deeper wins) — only for DIE candidates
        val da = (a as? DieCandidate)?.depth ?: 0
        val db = (b as? DieCandidate)?.depth ?: 0
        c = db.compareTo(da)
        if (c != 0) return c
        // 3) explicit priority (inline=0, subprogram=1, block=2, symtab=2, dynsym=3...)
        c = a.priority().compareTo(b.priority())
        if (c != 0) return c
        // 4) stable tiebreak: module id, CU offset, DIE/symbol key
        c = a.module.id.compareTo(b.module.id)
        if (c != 0) return c
        val coa = a.cu?.offset ?: U64.MAX
        val cob = b.cu?.offset ?: U64.MAX
        c = coa.compareTo(cob)
        if (c != 0) return c
        return a.stableKey().compareTo(b.stableKey())
    }

    // -------- inline call chain --------

    private fun inlineChain(c: Candidate): List<InlineFrame> {
        if (c !is DieCandidate) return emptyList()
        val cu = c.cu
        val byOff = HashMap<U64, Die>().apply { cu.dies.forEach { put(it.offset, it) } }
        val chain = ArrayList<Die>()
        var cur: Die? = c.die
        var guard = 0
        while (cur != null && guard++ < 256) {
            if (cur.tag == DwTag.SUBPROGRAM || cur.tag == DwTag.INLINED_SUBROUTINE || cur.tag == DwTag.LEXICAL_BLOCK) {
                chain.add(0, cur)
            }
            cur = cur.parentOffset?.let { byOff[it] }
        }
        return chain.mapIndexed { i, d ->
            val w = d.ranges.minOfOrNull { U64(it.end.v - it.start.v) } ?: U64.ZERO
            InlineFrame(
                depth = i,
                dieOffset = d.offset,
                tag = d.tagName(),
                name = d.linkageName ?: d.name ?: d.tagName(),
                linkageName = d.linkageName,
                inline = when {
                    d.tag == DwTag.INLINED_SUBROUTINE -> "inlined"
                    (d.inlineCode ?: 0) != 0 -> "declared_inline(${d.inlineCode})"
                    else -> "concrete"
                },
                declarationFile = d.declarationFile,
                declarationLine = d.declarationLine,
                callFile = d.callFile,
                callLine = d.callLine,
                ranges = d.ranges,
                width = w
            )
        }
    }

    // -------- line program lookup --------

    private fun lineFor(c: Candidate, entry: LoadEntry, segment: Int, virtual: U64): LineHit? {
        val dieCu = c.cu
        // DWARF 5: skeleton holds ranges, split CU holds the line program.
        val skeletonCu = entry.module.bundle.cus.firstOrNull { cu ->
            cu.kind == "skeleton" && entry.module.bundle.splitLinks[cu.offset] == dieCu?.offset
        }
        val lineCu = dieCu ?: return null
        val lp = entry.module.lineProgramFor(lineCu)
            ?: skeletonCu?.let { entry.module.lineProgramFor(it) }
            ?: return null
        val hit = findLineRow(lp, segment, virtual) ?: return null
        val row = hit.row
        val seq = lp.sequences.firstOrNull { hit.index in it.startRow..it.endRow }
        val file = lp.files.getOrNull(row.fileIndex)?.path ?: "<file index ${row.fileIndex}>"
        val lineSource = when {
            lineCu.kind == "split" -> "split"
            lineCu.kind == "skeleton" -> "skeleton"
            else -> "cu"
        }
        return LineHit(
            file = file,
            line = row.line,
            column = row.column,
            isStmt = row.isStmt,
            endSequence = row.endSequence,
            trigger = row.trigger,
            sequenceStart = seq?.startAddress ?: row.address,
            sequenceEnd = seq?.endAddress ?: row.address,
            dwarfVersion = lp.dwarfVersion,
            cuOffset = lineCu.offset,
            cuName = lineCu.name,
            lineSource = lineSource
        )
    }

    private data class IndexedRow(val index: Int, val row: LineRow)

    /**
     * Returns the row describing the address. Standard row semantics: the last row whose
     * address <= target within the same sequence; an end_sequence row only matches when the
     * address equals its (exclusive) end exactly. Multiple sequences are searched and the
     * closest preceding row wins, with non-end rows preferred at equal addresses.
     */
    private fun findLineRow(lp: LineProgram, segment: Int, target: U64): IndexedRow? {
        var bestRow: IndexedRow? = null
        for (seq in lp.sequences) {
            if (seq.segment != segment) continue
            for (i in seq.startRow..seq.endRow) {
                val row = lp.rows[i]
                if (row.segment != segment) continue
                if (row.endSequence) {
                    if (row.address == target) {
                        if (bestRow == null || row.address > bestRow!!.row.address) bestRow = IndexedRow(i, row)
                    }
                    continue
                }
                if (row.address <= target) {
                    if (bestRow == null || row.address > bestRow!!.row.address ||
                        (row.address == bestRow!!.row.address && !bestRow!!.row.endSequence)
                    ) {
                        bestRow = IndexedRow(i, row)
                    }
                }
            }
        }
        return bestRow
    }

    // -------- issues / trust --------

    private fun collectIssues(entry: LoadEntry, selected: Candidate?, line: LineHit?): List<String> {
        val out = ArrayList<String>()
        val bundle = entry.module.bundle
        for (cu in bundle.cus) {
            if (selected is DieCandidate && selected.cu.offset != cu.offset) continue
            for (iss in cu.issues) {
                if (iss.severity == "error") out += "[${iss.code}] ${iss.message}"
            }
        }
        if (bundle.issues.any { it.code == "MISSING_DWO" }) {
            val relevant = bundle.issues.filter { it.code == "MISSING_DWO" }
            out += relevant.joinToString("; ") { "[${it.code}] ${it.message}" }
        }
        if (selected != null && line == null) {
            out += "[NO_LINE_ROW] address mapped into ${selected.displayName()} but no line-program row covers it"
        }
        return out.distinct()
    }

    private fun overallTrust(entry: LoadEntry, selected: Candidate?, line: LineHit?): String {
        if (selected == null) return "low"
        if (selected is SymbolCandidate) return "medium"
        val cu = selected.cu ?: return "medium"
        val cuError = cu.issues.any { it.severity == "error" }
        val missingDwo = cu.kind == "skeleton" && entry.module.bundle.splitLinks[cu.offset] == null
        return when {
            cuError -> "partial"
            missingDwo -> "partial"
            line == null -> "medium"
            else -> "high"
        }
    }
}
