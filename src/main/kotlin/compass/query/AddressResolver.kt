package compass.query

import compass.dwarf.*

/**
 * Explains one runtime address. Unlike a one-shot `addr2line` call it:
 *  - keeps every legal candidate (overlapping functions, multiple sequences,
 *    zero-length ranges);
 *  - returns the full inline call chain with call-site file/line/column;
 *  - records load bias, CU, sequence index and the *line table version* used;
 *  - says explicitly which conclusions remain trustworthy when the dwo is absent
 *    or a section is corrupted.
 */
class AddressResolver(private val module: compass.dwarf.DebugModule) {

    private val lineCache = HashMap<String, LineProgram?>()
    private val localWarnings = ArrayList<String>()

    private fun lineProgram(cu: CompilationUnit, useDwo: Boolean): LineProgram? {
        val key = "${cu.sectionOffset}:$useDwo"
        if (lineCache.containsKey(key)) return lineCache[key]
        val offset = cu.stmtList ?: return null
        val prog = module.lineParser.parse(offset, cu.version, isDwo = useDwo)
        lineCache[key] = prog
        return prog
    }

    fun resolve(runtimeAddress: ULong, loadBias: ULong, snapshotId: String? = null, generation: Int? = null, moduleName: String? = null): AddressExplanation {
        localWarnings.clear()
        val relative = if (runtimeAddress >= loadBias) runtimeAddress - loadBias else runtimeAddress
        val candidates = ArrayList<RawCandidate>()
        val examinedUnits = module.units + module.dwoUnits

        for (cu in examinedUnits) {
            examineCu(cu, relative, candidates)
        }

        // Deterministic ordering independent of import/parse iteration: sort all raw
        // candidates by the total key, then assign visible ranks.
        val ordered = candidates.sortedWith(
            compareBy<RawCandidate>(
                { it.rangeLength },                 // narrowest first
                { -it.inlineDepth },                // deepest inline first
                { -it.priority },                   // explicit priority
                { it.cuOffset },                    // stable structural tie-breaks
                { it.rangeStart },
                { it.sequence ?: -1 },
                { it.dieOffset },
            )
        )

        val framed = ordered.mapIndexed { idx, rc -> buildFrame(idx, rc) }
        val trustworthy = framed.isNotEmpty()
        val confidence = when {
            framed.isEmpty() -> "none"
            framed.size == 1 && framed[0].source == ResultSource.LINE_PROGRAM -> "high"
            framed.any { it.source == ResultSource.DIE_RANGE_ONLY } -> "partial"
            framed.size > 1 -> "ambiguous"
            else -> "high"
        }
        return AddressExplanation(
            runtimeAddress = runtimeAddress,
            relativeAddress = relative,
            loadBias = loadBias,
            snapshotId = snapshotId,
            generation = generation,
            module = moduleName,
            candidates = framed,
            warnings = (module.warnings + localWarnings).distinct(),
            trustworthy = trustworthy,
            confidence = confidence,
        )
    }

    private fun examineCu(cu: CompilationUnit, address: ULong, out: MutableList<RawCandidate>) {
        val cuRanges = module.rangeResolver.dieRanges(cu.root, cu)
        val cuCovers = cuRanges.any { it.contains(address) || it.start == address && it.length == 0UL }
        if (cuRanges.isNotEmpty() && !cuCovers) return

        val isSplitResident = module.dwoFor(cu) != null
        if (cuRanges.isEmpty() && module.units.size + module.dwoUnits.size > 1) {
            // A CU without any own ranges (skeleton with ranges in dwo) is still
            // considered when its dwo provides the ranges.
        }

        val program = if (cu.isDwo) lineProgram(cu, useDwo = true) else lineProgram(cu, useDwo = false)

        // Line program matches: exact row containing the address within its sequence.
        if (program != null) {
            for (seq in program.sequences) {
                if (address !in seq.startAddress..seq.endAddress &&
                    !(address == seq.startAddress && seq.startAddress == seq.endAddress)) continue
                val row = pickRow(seq, address)
                val containingDie = findContainingDie(cu, address)
                out.add(RawCandidate(
                    cuOffset = cu.sectionOffset,
                    dieOffset = containingDie?.offset ?: -1,
                    sequence = seq.index,
                    rangeStart = containingDie?.let { narrowestRange(it, cu)?.start } ?: row?.address ?: seq.startAddress,
                    rangeEnd = containingDie?.let { narrowestRange(it, cu)?.end } ?: row?.address ?: seq.endAddress,
                    rangeLength = containingDie?.let { narrowestRange(it, cu)?.length }
                        ?: (if (row != null) 0UL else seq.endAddress - seq.startAddress),
                    line = row?.line,
                    column = row?.column,
                    fileIndex = row?.fileIndex,
                    program = program,
                    cu = cu,
                    die = containingDie,
                    priority = if (isSplitResident) 2 else if (cu.isDwo) 1 else 0,
                    exact = row != null && row.address == address,
                    splitResident = isSplitResident,
                ))
            }
        }

        // DIE-only matches (functions/ranges with no usable line row).
        if (program == null || program.sequences.none { address in it.startAddress..it.endAddress }) {
            findContainingDies(cu, address).forEach { die ->
                if (out.none { it.cuOffset == cu.sectionOffset && it.dieOffset == die.offset }) {
                    val nr = narrowestRange(die, cu)
                    out.add(RawCandidate(
                        cuOffset = cu.sectionOffset,
                        dieOffset = die.offset,
                        sequence = null,
                        rangeStart = nr?.start ?: address,
                        rangeEnd = nr?.end ?: address,
                        rangeLength = nr?.length ?: 0UL,
                        line = die.attr(Attr.CALL_LINE)?.value?.asLong?.toInt(),
                        column = null,
                        fileIndex = null,
                        program = null,
                        cu = cu,
                        die = die,
                        priority = if (isSplitResident) 2 else 0,
                        exact = nr != null && nr.start == address,
                        splitResident = isSplitResident,
                    ))
                }
            }
        }

        // Split DWARF: skeleton covered but no resident dwo -> still report, flagged.
        val dwoRequested = cu.root.attr(Attr.DW_AT_dwo_name) != null || cu.root.attr(Attr.DW_AT_GNU_dwo_name) != null
        if (dwoRequested && !isSplitResident && cuCovers) {
            localWarnings += "skeleton CU ${cu.name ?: cu.sectionOffset} references a .dwo that is not imported; " +
                "frame names/inline chains from the split unit are unavailable"
        }
    }

    private fun pickRow(seq: LineSequence, address: ULong): LineRow? {
        var best: LineRow? = null
        for (row in seq.rows) {
            if (row.endSequence) continue
            if (row.address <= address) best = row else break
        }
        // End-sequence rows describe an exclusive end address; never match a row to
        // an address equal to the end unless it is the only hint.
        if (best == null) best = seq.rows.lastOrNull { !it.endSequence }
        return best
    }

    private fun findContainingDies(cu: CompilationUnit, address: ULong): List<Die> {
        val hits = ArrayList<Die>()
        fun walk(die: Die) {
            val ranges = module.rangeResolver.dieRanges(die, cu)
            if (ranges.any { it.contains(address) || (it.start == address && it.length == 0UL) }) {
                hits.add(die)
            }
            die.children.forEach(::walk)
        }
        walk(cu.root)
        return hits
    }

    private fun findContainingDie(cu: CompilationUnit, address: ULong): Die? {
        var best: Die? = null
        var bestLen = ULong.MAX_VALUE
        fun walk(die: Die) {
            for (r in module.rangeResolver.dieRanges(die, cu)) {
                if (r.contains(address) || (r.start == address && r.length == 0UL)) {
                    val len = if (r.length == 0UL) ULong.MAX_VALUE else r.length
                    if (len < bestLen || (len == bestLen && best == null)) {
                        best = die; bestLen = len
                    }
                }
            }
            die.children.forEach(::walk)
        }
        walk(cu.root)
        return best
    }

    private fun narrowestRange(die: Die, cu: CompilationUnit): AddrRange? {
        val ranges = module.rangeResolver.dieRanges(die, cu)
        return ranges.minWithOrNull(compareBy({ it.length }, { it.start }))
    }

    private fun buildFrame(rank: Int, rc: RawCandidate): FrameCandidate {
        val chain = buildInlineChain(rc.cu, rc.die, rc.program)
        val filePath = resolveFile(rc.program, rc.fileIndex, rc.cu)
        val source = when {
            rc.program != null && rc.line != null -> ResultSource.LINE_PROGRAM
            rc.cu.isDwo || rc.splitResident -> ResultSource.SPLIT_DWO
            rc.die != null -> ResultSource.DIE_RANGE_ONLY
            else -> ResultSource.FALLBACK
        }
        val warnings = ArrayList<String>()
        if (rc.program == null && rc.die != null) {
            warnings += "no line table row: only function range is known for this address"
        }
        if (!rc.splitResident && rc.cu.root.let {
                it.attr(Attr.DW_AT_dwo_name) != null || it.attr(Attr.DW_AT_GNU_dwo_name) != null
            }) {
            warnings += ".dwo companion missing; split-debug names may be incomplete"
        }
        return FrameCandidate(
            rank = rank,
            symbol = rc.die?.name ?: chain.firstOrNull { it.name != null }?.name,
            cuName = rc.cu.name,
            filePath = filePath,
            line = rc.line,
            column = rc.column,
            sequenceIndex = rc.sequence,
            matchedRangeStart = rc.rangeStart,
            matchedRangeEnd = rc.rangeEnd,
            rangeLength = rc.rangeLength,
            inlineDepth = chain.size,
            inlineChain = chain,
            priority = rc.priority,
            source = source,
            tableVersion = rc.program?.tableVersion,
            exact = rc.exact,
            warnings = warnings,
        )
    }

    private fun buildInlineChain(cu: CompilationUnit, leaf: Die?, program: LineProgram?): List<InlineFrame> {
        if (leaf == null) return emptyList()
        val path = ArrayList<Die>()
        var d: Die? = leaf
        // Rebuild ancestor path via depth scan from root (parent links intentionally
        // not stored; the tree is small per query and traversal is bounded).
        val ancestors = ArrayDeque<Die>()
        fun find(node: Die): Boolean {
            ancestors.addLast(node)
            if (node === leaf) return true
            for (ch in node.children) if (find(ch)) return true
            ancestors.removeLast()
            return false
        }
        find(cu.root)
        path.addAll(ancestors)

        val abstractOrigin = HashMap<Int, Die>()
        fun indexOrigins(node: Die) {
            node.attr(Attr.NAME)?.let { /* presence marker */ }
            node.children.forEach(::indexOrigins)
        }
        indexOrigins(cu.root)

        return path.mapIndexedNotNull { depth, die ->
            val tag = when (die.tag) {
                Tag.SUBPROGRAM -> if (depth == 0) "subprogram" else "subprogram"
                Tag.INLINED_SUBROUTINE -> "inlined_subroutine"
                Tag.LEXICAL_BLOCK -> "lexical_block"
                Tag.COMPILE_UNIT, Tag.SKELETON_UNIT -> return@mapIndexedNotNull null
                else -> "tag_0x${die.tag.toString(16)}"
            }
            val ranges = module.rangeResolver.dieRanges(die, cu)
            val nr = ranges.minWithOrNull(compareBy({ it.length }, { it.start }))
            val callFileIndex = die.attr(Attr.CALL_FILE)?.value?.asLong?.toInt()
            InlineFrame(
                depth = depth,
                name = die.name ?: resolveAbstractName(cu, die),
                tag = tag,
                file = program?.let { resolveFile(it, callFileIndex, cu) },
                callLine = die.attr(Attr.CALL_LINE)?.value?.asLong?.toInt(),
                callColumn = die.attr(Attr.CALL_COLUMN)?.value?.asLong?.toInt(),
                rangeStart = nr?.start,
                rangeEnd = nr?.end,
                abstractOriginResolved = die.attr(Attr.ABSTRACT_ORIGIN) == null ||
                    resolveAbstractName(cu, die) != null,
            )
        }
    }

    private val abstractOriginCache = HashMap<Pair<CompilationUnit, Int>, String?>()

    private fun resolveAbstractName(cu: CompilationUnit, die: Die): String? {
        val originAttr = die.attr(Attr.ABSTRACT_ORIGIN) ?: return null
        val target = originAttr.value.asLong?.toInt() ?: return null
        return abstractOriginCache.getOrPut(cu to target) {
            val flat = cu.root.flatten()
            // REF addresses are section-relative; our Die offsets are DIE-area-relative.
            val dieAreaBase = cu.dieAreaStart
            flat.firstOrNull { it.offset + dieAreaBase == target }?.name
                ?: flat.firstOrNull { it.offset == target }?.name
        }
    }

    private fun resolveFile(program: LineProgram?, index: Int?, cu: CompilationUnit): String? {
        if (program == null || index == null) return null
        // DWARF5 file indexes are 0-based into the entry list; DWARF <=4 uses 1-based
        // where file 0 means the CU primary source file.
        val file = when {
            program.tableVersion >= 5 -> program.files.getOrNull(index)
            index == 0 -> program.files.getOrNull(0) ?: LineFile(cu.name ?: "", 0, 0, 0, null)
            else -> program.files.getOrNull(index - 1)
        } ?: return null
        val dir = program.directories.getOrNull((file.dirIndex - 1).coerceAtLeast(0))
            ?: cu.compDir
        return when {
            file.name.startsWith('/') -> file.name
            dir != null -> "$dir/${file.name}"
            else -> file.name
        }
    }

    private data class RawCandidate(
        val cuOffset: Int,
        val dieOffset: Int,
        val sequence: Int?,
        val rangeStart: ULong,
        val rangeEnd: ULong,
        val rangeLength: ULong,
        val line: Int?,
        val column: Int?,
        val fileIndex: Int?,
        val program: LineProgram?,
        val cu: CompilationUnit,
        val die: Die?,
        val priority: Int,
        val exact: Boolean,
        val splitResident: Boolean,
    ) {
        val inlineDepth: Int get() = die?.depth ?: 0
    }
}
