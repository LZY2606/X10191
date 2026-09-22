package compass.dwarf

/** How the queried address was expressed. */
data class AddressInput(
    val raw: String,
    val moduleKey: String?,
    val segment: Int?,
    val address: Long,
    val relative: Boolean
)

data class InlineFrame(
    val depth: Int,
    val function: String,
    val dieOffset: Long,
    val callFile: String?,
    val line: Long?,
    val column: Long?,
    val ranges: List<AddressRange>
)

data class LineHit(
    val file: String,
    val directory: String,
    val line: Long,
    val column: Long,
    val sequenceIndex: Int,
    val sequenceStart: Long,
    val sequenceEnd: Long,
    val dwarfVersion: Int,
    val isStmt: Boolean
)

data class CandidateExplanation(
    val rank: Int,
    val fileId: Long,
    val fileName: String,
    val fileSha256: String,
    val cuName: String,
    val cuOffset: Long,
    val dwarfVersion: Int,
    val matchedRange: AddressRange,
    val rangeWidth: Long,
    val inlineDepth: Int,
    val explicitScore: Int,
    val function: String?,
    val line: LineHit?,
    val inlineChain: List<InlineFrame>,
    val tableVersion: Int?,
    val trusted: Boolean,
    val notes: List<String>
)

data class QueryResult(
    val input: AddressInput,
    val runtimeAddress: Long,
    val relativeAddress: Long,
    val loadBias: Long?,
    val moduleBase: Long?,
    val moduleName: String?,
    val candidates: List<CandidateExplanation>,
    val summary: String,
    val warnings: List<String>
)

class QueryEngine(private val registry: Registry) {

    fun parseInput(raw: String): AddressInput {
        var s = raw.trim()
        var module: String? = null
        var seg: Int? = null
        var relative = false
        if (s.contains(":")) {
            val head = s.substringBeforeLast(":")
            val tail = s.substringAfterLast(":")
            // module:0xADDR or SEG:OFFSET
            if (tail.startsWith("0x") || tail.toLongOrNull(16) != null) {
                val h = head
                if (h.startsWith("0x") || h.toLongOrNull(16) != null) {
                    seg = h.removePrefix("0x").toLong(16).toInt()
                } else {
                    module = h
                }
                s = tail
            }
        }
        if (s.startsWith("+")) { relative = true; s = s.substring(1) }
        val addr = parseHexOrDec(s)
        return AddressInput(raw, module, seg, addr, relative)
    }

    private fun parseHexOrDec(s: String): Long {
        val t = s.removePrefix("0x")
        return if (s.startsWith("0x")) t.toLong(16) else t.toLongOrNull() ?: t.toLong(16)
    }

    /**
     * Resolve an address. With a snapshot, module bases give a load bias and
     * restrict which debug files participate. Without one, the value is
     * treated as a linker vaddr and all imports are searched.
     */
    fun query(input: AddressInput, snapshot: SnapshotView? = null): QueryResult {
        val warnings = mutableListOf<String>()
        val modules: List<SnapshotModule> = snapshot?.modulesMatching(input) ?: emptyList()
        var loadBias: Long? = null
        var runtimeAddr = input.address
        var relativeAddr = input.address
        var moduleName: String? = null
        var moduleBase: Long? = null

        val participants = ArrayList<Pair<ParsedFile, Long>>() // file -> bias
        when {
            modules.isNotEmpty() -> {
                for (m in modules) {
                    val f = registry.file(m.fileId) ?: continue
                    val fileBase = f.elf.preferredBase() ?: 0L
                    val bias = m.base - fileBase
                    // Relative inputs are file vaddrs; absolute inputs are runtime addrs.
                    val target = if (input.relative) input.address else input.address - bias
                    if (participants.isEmpty()) {
                        loadBias = bias
                        runtimeAddr = if (input.relative) input.address + bias else input.address
                        relativeAddr = target
                        moduleName = m.name
                        moduleBase = m.base
                    }
                    participants.add(f to bias)
                }
            }
            else -> {
                for (f in registry.all()) participants.add(f to 0L)
                runtimeAddr = input.address
                relativeAddr = input.address
            }
        }
        if (snapshot != null && modules.isEmpty())
            warnings.add("no loaded module in the pinned snapshot covers this address")

        val raw = ArrayList<CandidateExplanation>()
        for ((file, bias) in participants) {
            val vaddr = runtimeAddr - bias
            raw.addAll(candidatesInFile(file, vaddr, bias, input.segment, warnings))
        }
        val sorted = raw.sortedWith(compareBy(
            { -it.explicitScore },
            { it.rangeWidth },
            { -it.inlineDepth },
            { it.fileSha256 },
            { it.cuOffset },
            { it.matchedRange.start }
        ))
        val ranked = sorted.mapIndexed { idx, c -> c.copy(rank = idx + 1) }
        val summary = when {
            ranked.isEmpty() -> "no debug information maps this address"
            else -> {
                val top = ranked.first()
                val loc = top.line?.let { "${it.file}:${it.line}:${it.column}" } ?: "no line row"
                "${top.function ?: "?"} ($loc) [CU ${top.cuName}, DWARF${top.dwarfVersion}]"
            }
        }
        return QueryResult(input, runtimeAddr, relativeAddr, loadBias, moduleBase, moduleName,
            ranked, summary, warnings)
    }

    private fun candidatesInFile(
        file: ParsedFile, vaddr: Long, bias: Long, segment: Int?,
        warnings: MutableList<String>
    ): List<CandidateExplanation> {
        val out = ArrayList<CandidateExplanation>()
        val nameResolver = DwarfNames { _, off -> file.dieAtGlobalOffset(off)?.second }
        // scope candidates
        for (scope in file.scopes) {
            val range = scope.ranges.firstOrNull {
                (segment == null || it.segment == segment) && it.matches(vaddr)
            } ?: continue
            val notes = mutableListOf<String>()
            val lineHit = findLine(scope.unit, file, vaddr)
            val chain = inlineChain(scope, file, nameResolver)
            val score = when {
                lineHit != null && scope.die.tag == DW.TAG_subprogram -> 3
                lineHit != null && scope.die.tag == DW.TAG_inlined_subroutine -> 3
                scope.ranges.isNotEmpty() -> 2
                else -> 1
            }
            if (range.zeroLength) notes.add("matched a zero-length range at ${hex(range.start)}")
            val unit = scope.unit
            val dwoMissing = unit.isSkeleton && unit.linkedDwoFileId == null
            if (dwoMissing) notes.add("skeleton only: .dwo not imported, inline split DIEs absent")
            out.add(CandidateExplanation(
                rank = 0,
                fileId = file.id,
                fileName = file.elf.path?.substringAfterLast('/') ?: "file#${file.id}",
                fileSha256 = file.sha256,
                cuName = unit.name() ?: ("cu@${hex(unit.unitOffset)}"),
                cuOffset = unit.unitOffset,
                dwarfVersion = unit.version,
                matchedRange = range,
                rangeWidth = range.length,
                inlineDepth = scope.inlineDepth,
                explicitScore = score,
                function = nameResolver.name(scope.die, scope.unit),
                line = lineHit,
                inlineChain = chain,
                tableVersion = lineHit?.dwarfVersion,
                trusted = !dwoMissing && unit.issues.none { it.severity == "error" },
                notes = notes
            ))
        }
        // line-only candidates: CUs whose line program covers vaddr but no scope
        for (unit in file.units) {
            if (out.any { it.cuOffset == unit.unitOffset }) continue
            val lineHit = findLine(unit, file, vaddr) ?: continue
            out.add(CandidateExplanation(
                rank = 0, fileId = file.id,
                fileName = file.elf.path?.substringAfterLast('/') ?: "file#${file.id}",
                fileSha256 = file.sha256,
                cuName = unit.name() ?: ("cu@${hex(unit.unitOffset)}"),
                cuOffset = unit.unitOffset, dwarfVersion = unit.version,
                matchedRange = AddressRange(lineHit.sequenceStart, lineHit.sequenceEnd),
                rangeWidth = lineHit.sequenceEnd - lineHit.sequenceStart,
                inlineDepth = 0, explicitScore = 1,
                function = null, line = lineHit, inlineChain = emptyList(),
                tableVersion = lineHit.dwarfVersion,
                trusted = unit.issues.none { it.severity == "error" },
                notes = listOf("line program only: no function DIE covers this address")
            ))
        }
        return out
    }

    private fun findLine(unit: CompUnit, file: ParsedFile, vaddr: Long): LineHit? {
        val prog = try {
            file.lineProgramFor(unit)
        } catch (e: Exception) {
            unit.issues.add(ParseIssue("warning", "line", e.message ?: "line parse failed"))
            return null
        } ?: return null
        val row = prog.rowFor(vaddr) ?: return null
        val seq = prog.sequences.firstOrNull { it.index == row.sequenceIndex } ?: return null
        val lf = prog.fileOf(row.fileIndex)
        return LineHit(
            file = lf?.name ?: "file#${row.fileIndex}",
            directory = lf?.directory ?: "",
            line = row.line, column = row.column,
            sequenceIndex = seq.index, sequenceStart = seq.startAddress,
            sequenceEnd = seq.endAddress, dwarfVersion = prog.version, isStmt = row.isStmt
        )
    }

    private fun inlineChain(
        scope: ScopeDie, file: ParsedFile, names: DwarfNames
    ): List<InlineFrame> {
        if (scope.die.tag != DW.TAG_inlined_subroutine) {
            return listOf(frameFor(scope, names))
        }
        val chain = ArrayList<InlineFrame>()
        var node: DieNode? = scope.die
        var depth = scope.inlineDepth
        while (node != null) {
            if (node.isScopeWithCode) {
                val sc = file.scopes.firstOrNull { it.die === node }
                chain.add(
                    InlineFrame(
                        depth = if (node.tag == DW.TAG_inlined_subroutine) depth else 0,
                        function = names.name(node, scope.unit) ?: "?",
                        dieOffset = node.offset,
                        callFile = (node.attr(DW.AT_call_file)?.value as? FormValue.Number)
                            ?.let { idx -> file.lineProgramFor(scope.unit)?.fileOf(idx.value)?.name },
                        line = node.num(DW.AT_call_line),
                        column = node.num(DW.AT_call_column),
                        ranges = sc?.ranges ?: emptyList()
                    )
                )
                if (node.tag == DW.TAG_inlined_subroutine) depth--
            }
            node = node.parent
        }
        return chain.reversed()
    }

    private fun frameFor(scope: ScopeDie, names: DwarfNames): InlineFrame = InlineFrame(
        depth = 0,
        function = names.name(scope.die, scope.unit) ?: "?",
        dieOffset = scope.die.offset,
        callFile = null, line = null, column = null,
        ranges = scope.ranges
    )

    companion object {
        fun hex(v: Long): String = "0x${v.toString(16)}"
    }
}
