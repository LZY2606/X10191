package compass.resolve

import compass.dwarf.CodeSymbol
import compass.dwarf.DebugSections
import compass.dwarf.DwarfFileParser
import compass.dwarf.DwarfNames
import compass.dwarf.DW
import compass.dwarf.RangeResolver
import compass.model.AddrRange
import compass.model.AttrValue
import compass.model.CompilationUnit
import compass.model.Die
import compass.model.LineProgram
import compass.model.LineRow
import compass.model.LineSequence
import compass.model.ParsedDebugFile
import compass.model.unsignedCompare

data class ModuleSnapshot(
    val id: Long = 0,
    val versionId: Long,
    val label: String,
    val loadBase: Long,
    val firstSegmentVaddr: Long,
    val frozenAt: String,
    val generation: Int,
) {
    val bias: Long get() = loadBase - firstSegmentVaddr
}

data class SourcePosition(
    val file: String,
    val line: Int,
    val column: Int,
    val fileIndex: Int,
)

data class InlineFrame(
    val symbol: String,
    val dieTag: String,
    val depth: Int,
    val callFile: String?,
    val callLine: Int?,
    val callColumn: Int?,
    val rangeStart: Long,
    val rangeEnd: Long,
    val rangeLength: Long,
)

data class AddressCandidate(
    val kind: String, // LINE | FUNCTION
    val cuName: String?,
    val cuHeaderOffset: Long,
    val dwarfVersion: Int,
    val sequenceIndex: Int,
    val sequenceStart: Long,
    val sequenceEnd: Long,
    val position: SourcePosition?,
    val symbolName: String?,
    val rangeStart: Long,
    val rangeEnd: Long,
    val rangeLength: Long,
    val inlineDepth: Int,
    val explicitPriority: Long?,
    val selector: Long,
    val inlineChain: List<InlineFrame>,
    val zeroLength: Boolean,
)

data class AddressExplanation(
    val inputRuntime: Long,
    val inputSelector: Long,
    val relativeAddress: Long,
    val matchedSnapshot: ModuleSnapshot?,
    val snapshotLabel: String?,
    val bias: Long?,
    val candidates: List<AddressCandidate>,
    val best: AddressCandidate?,
    val lineTableVersions: List<String>,
    val notes: List<String>,
    val trustLevel: String, // EXACT | LIMITED | UNRESOLVED
)

class AddressResolver(
    private val parsed: ParsedDebugFile,
    private val symbols: List<CodeSymbol>,
    private val rangeResolver: RangeResolver,
) {
    private val lineByStmtOffset: Map<Long, LineProgram> =
        parsed.linePrograms.associateBy { it.cuHeaderOffset }
    private val cuByHeader: Map<Long, CompilationUnit> =
        parsed.units.associateBy { it.headerOffset }

    /**
     * @param runtimeAddr address as observed in the crashing process
     * @param snapshots fixed module load generations to consider; all matches kept
     */
    fun resolve(runtimeAddr: Long, selector: Long, snapshots: List<ModuleSnapshot>): AddressExplanation {
        val notes = ArrayList<String>()
        val candidates = ArrayList<AddressCandidate>()
        var matchedSnapshot: ModuleSnapshot? = null
        var relative = runtimeAddr
        var bias: Long? = null

        if (snapshots.isNotEmpty()) {
            val viable = snapshots.filter { snap ->
                parsed.elf.segments.any { seg ->
                    val start = seg.vaddr + snap.bias
                    val end = start + seg.memsz
                    unsignedCompare(runtimeAddr, start) >= 0 && unsignedCompare(runtimeAddr, end) < 0
                }
            }
            if (viable.size > 1) {
                notes += "address is valid in ${viable.size} frozen load generations; all are reported, ordered by generation"
            }
            matchedSnapshot = viable.minByOrNull { it.generation }
            if (matchedSnapshot != null) {
                relative = runtimeAddr - matchedSnapshot.bias
                bias = matchedSnapshot.bias
            } else {
                notes += "runtime address does not fall inside any frozen load segment; treated as a relative address"
                relative = runtimeAddr
            }
        }

        for (cu in parsed.units) {
            collectLineCandidates(cu, relative, selector, candidates)
            collectFunctionCandidates(cu, relative, selector, candidates)
        }

        // zero-length ranges: include point-equality via inclusive match helper inside collectors
        val ordered = candidates.sortedWith(compareBy<AddressCandidate>(
            { it.relativeRank() },                         // line rows before bare function ranges
            { it.rangeLength },                            // narrowest range wins
            { -it.inlineDepth },                           // deeper inline site wins
            { -(it.explicitPriority ?: 0L) },              // explicit vendor priority
            { it.cuHeaderOffset },                         // stable across import order
            { it.sequenceIndex },
            { it.rangeStart },
            { it.dieOffsetStable() },
        ))

        val versions = parsed.linePrograms
            .filter { lp -> ordered.any { it.cuHeaderOffset == lp.cuHeaderOffset } }
            .map { "DWARF${it.version}" }
            .distinct()
            .sorted()

        val trust = when {
            ordered.isNotEmpty() && parsed.issues.none { it.severity == "ERROR" } -> "EXACT"
            ordered.isNotEmpty() -> "LIMITED"
            else -> "UNRESOLVED"
        }
        if (parsed.hasSplitRefs) notes += splitNote()
        parsed.issues.filter { it.severity == "ERROR" }.forEach {
            notes += "parse ${it.code}: ${it.message}"
        }

        return AddressExplanation(
            inputRuntime = runtimeAddr, inputSelector = selector,
            relativeAddress = relative,
            matchedSnapshot = matchedSnapshot, snapshotLabel = matchedSnapshot?.label,
            bias = bias, candidates = ordered, best = ordered.firstOrNull(),
            lineTableVersions = versions, notes = notes, trustLevel = trust,
        )
    }

    private fun AddressCandidate.relativeRank(): Int = when (kind) {
        "LINE" -> 0
        else -> 1
    }

    private fun AddressCandidate.dieOffsetStable(): Long = rangeStart xor rangeEnd

    private fun collectLineCandidates(cu: CompilationUnit, relAddr: Long, selector: Long, out: MutableList<AddressCandidate>) {
        val stmtOff = cu.root?.num(DW.AT_stmt_list) ?: return
        val prog = lineByStmtOffset[stmtOff] ?: return
        for (seq in prog.sequences) {
            if (seq.rows.isEmpty()) continue
            val sel = seq.selector
            if (sel != selector) continue
            // last row is end_sequence address: range [start, end)
            val start = seq.start
            val end = seq.end
            if (seq.rows.size == 1) {
                if (relAddr != start) continue
            } else {
                if (unsignedCompare(relAddr, start) < 0 || unsignedCompare(relAddr, end) > 0) continue
            }
            val row = pickRow(seq.rows, relAddr) ?: continue
            val file = resolveFile(prog, row.file)
            val pos = SourcePosition(file, row.line, row.column, row.file)
            out += AddressCandidate(
                kind = "LINE",
                cuName = cu.name, cuHeaderOffset = cu.headerOffset,
                dwarfVersion = prog.version,
                sequenceIndex = seq.index, sequenceStart = start, sequenceEnd = end,
                position = pos, symbolName = enclosingSymbolName(cu, relAddr, selector),
                rangeStart = row.address, rangeEnd = seq.rows.let { rows ->
                    val next = rows.indexOf(row).let { i -> rows.getOrNull(i + 1)?.address }
                    next ?: end
                },
                rangeLength = (seq.rows.let { rows ->
                    val i = rows.indexOf(row); (rows.getOrNull(i + 1)?.address ?: end) - row.address
                }),
                inlineDepth = 0, explicitPriority = null, selector = sel,
                inlineChain = inlineChain(cu, relAddr, selector),
                zeroLength = seq.rows.size == 1,
            )
        }
    }

    private fun pickRow(rows: List<LineRow>, addr: Long): LineRow? {
        var best: LineRow? = null
        for (row in rows) {
            if (unsignedCompare(row.address, addr) <= 0) {
                best = row
            } else break
        }
        // do not anchor on the end_sequence row itself for a half-open sequence
        if (best != null && best.endSequence && best.address != addr) {
            val idx = rows.indexOf(best)
            best = rows.getOrNull(idx - 1)
        }
        return best
    }

    private fun enclosingSymbolName(cu: CompilationUnit, addr: Long, selector: Long): String? {
        return symbols.filter { it.cuHeaderOffset == cu.headerOffset }
            .filter { s -> s.ranges.any { it.containsInclusive(selector, addr) || (it.start == addr && it.end == addr) } }
            .minByOrNull { s -> s.ranges.minOf { r -> if (r.contains(selector, addr)) r.length else Long.MAX_VALUE } }
            ?.let { it.name ?: it.linkageName }
    }

    private fun collectFunctionCandidates(cu: CompilationUnit, relAddr: Long, selector: Long, out: MutableList<AddressCandidate>) {
        for (s in symbols) {
            if (s.cuHeaderOffset != cu.headerOffset) continue
            val hit = s.ranges.firstOrNull { r ->
                r.contains(selector, relAddr) || (r.start == relAddr && r.end == relAddr)
            } ?: continue
            out += AddressCandidate(
                kind = "FUNCTION",
                cuName = cu.name, cuHeaderOffset = cu.headerOffset,
                dwarfVersion = cu.version,
                sequenceIndex = -1, sequenceStart = 0, sequenceEnd = 0,
                position = null,
                symbolName = s.name ?: s.linkageName ?: DwarfNames.tag(s.tag),
                rangeStart = hit.start, rangeEnd = hit.end, rangeLength = hit.length,
                inlineDepth = s.depth, explicitPriority = s.explicitPriority,
                selector = hit.selector,
                inlineChain = inlineChain(cu, relAddr, selector),
                zeroLength = hit.end == hit.start,
            )
        }
    }

    /**
     * Walks from the deepest inlined_subroutine containing the address up to
     * its outer subprogram, following abstract_origin / specification refs for
     * names and call sites.  Hop count is clamped to prevent cycles.
     */
    fun inlineChain(cu: CompilationUnit, addr: Long, selector: Long): List<InlineFrame> {
        val containing = symbols
            .filter { it.cuHeaderOffset == cu.headerOffset }
            .filter { s ->
                s.ranges.any { r -> r.contains(selector, addr) || (r.start == addr && r.end == addr) }
            }
            .sortedByDescending { it.depth }
        val frames = ArrayList<InlineFrame>()
        val seen = HashSet<Long>()
        for (s in containing) {
            val die = cu.dies[s.dieOffset] ?: continue
            if (!seen.add(die.offset)) continue
            val nameDie = followOriginChain(cu, die)
            val name = nameDie?.str(DW.AT_name) ?: nameDie?.num(DW.AT_linkage_name)?.let { null } ?: s.name
            val range = s.ranges.first { it.contains(selector, addr) || (it.start == addr && it.end == addr) }
            val callFileIdx = die.num(DW.AT_call_file)?.toInt()
            val prog = lineByStmtOffset[cu.root?.num(DW.AT_stmt_list) ?: -1]
            val callFile = callFileIdx?.let { idx -> prog?.let { resolveFile(it, idx) } }
            frames += InlineFrame(
                symbol = name ?: DwarfNames.tag(die.tag),
                dieTag = DwarfNames.tag(die.tag),
                depth = die.depth,
                callFile = callFile,
                callLine = die.num(DW.AT_call_line)?.toInt(),
                callColumn = die.num(DW.AT_call_column)?.toInt(),
                rangeStart = range.start, rangeEnd = range.end, rangeLength = range.length,
            )
        }
        return frames
    }

    private fun followOriginChain(cu: CompilationUnit, start: Die): Die? {
        var die: Die = start
        var hops = 0
        val seen = HashSet<Long>()
        while (true) {
            if (!seen.add(die.offset) || hops++ > 64) return die
            val refAttr = die.attr(DW.AT_abstract_origin) ?: die.attr(DW.AT_specification) ?: return die
            val ref = (refAttr.value as? AttrValue.InfoRef)?.offset ?: return die
            die = cu.dies[ref] ?: return die
        }
    }

    private fun resolveFile(prog: LineProgram, idx: Int): String {
        val entry = prog.files.firstOrNull { it.id == idx } ?: return "<file $idx>"
        val dir = entry.dirIndex.takeIf { it in prog.dirs.indices }?.let { prog.dirs[it] }.orEmpty()
        return if (dir.isEmpty()) entry.name else "$dir/${entry.name}"
    }

    private fun splitNote(): String {
        val missing = parsed.units.filter { it.isSkeleton }.mapNotNull { skeleton ->
            val dwo = parsed.dwoUnits[skeleton.dwoId]
            if (dwo == null) skeleton.dwoName ?: "dwo_id=${skeleton.dwoId?.toString(16)}" else null
        }
        return if (missing.isEmpty()) "split DWARF references present; all dwo files were available"
        else "split DWARF: skeleton line tables are trustworthy, but inlined bodies/types from missing dwo [${missing.joinToString()}] are unavailable"
    }
}
