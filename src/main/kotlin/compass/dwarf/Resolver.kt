package compass.dwarf

/** A relocated module context: runtime addresses are biased by [loadBias]. */
data class ModuleLoad(
    val moduleName: String,
    val preferredBase: Long,   // ELF vaddr of first PT_LOAD (p_vaddr), typically 0
    val loadBase: Long,        // runtime address where it was mapped
    val generation: Int        // loading generation (same relative addr can recur)
) {
    val loadBias: Long get() = loadBase - preferredBase
    fun toRelative(runtimePc: Long): Long = runtimePc - loadBias
    fun toRuntime(rel: Long): Long = rel + loadBias
}

/** One line row hit within a sequence. */
data class LineHit(
    val file: String,
    val line: Int,
    val column: Int,
    val sequenceIndex: Int,
    val rowAddress: Long,
    val tableVersion: String,
    val isStmt: Boolean,
    val endSequence: Boolean
)

/** One frame in the inline call chain. */
data class InlineFrame(
    val function: String,
    val depth: Int,
    val callFile: String?,
    val callLine: Int,
    val rangeLow: Long,
    val rangeHigh: Long,
    val abstractName: String?,
    val dieOffset: Long
)

/** A single legal interpretation (kept; ties are all returned). */
data class AddressCandidate(
    val rank: Int,
    val cuName: String?,
    val compDir: String?,
    val line: LineHit?,
    val sequenceIndex: Int,
    val inlineChain: List<InlineFrame>,
    val coveringFunction: String?,
    val confidence: String,
    val tieKey: String
)

data class AddressQueryResult(
    val runtimePc: Long,
    val relativePc: Long,
    val loadBias: Long,
    val module: ModuleLoad?,
    val candidates: List<AddressCandidate>,
    val trusted: List<String>,   // conclusions still trustworthy when data is degraded
    val warnings: List<String>,
    val tableVersions: List<String>
)

/**
 * Address attribution engine. Collects *every* legal candidate across CUs and
 * line sequences, then orders by: narrowest enclosing range, greatest inline
 * depth, explicit tie-break priority (concrete>abstract, earlier CU+offset).
 * Ordering never depends on import/iteration accident: tie keys are absolute
 * offsets, so reordering imports cannot reorder equal candidates.
 */
class Resolver(private val info: DebugInfo) {

    fun query(runtimePc: Long, load: ModuleLoad?): AddressQueryResult {
        val rel = load?.toRelative(runtimePc) ?: runtimePc
        val warnings = ArrayList<String>()
        val trusted = ArrayList<String>()
        val raw = ArrayList<RawCandidate>()

        for (cu in info.units) {
            if (cu.isSplit) continue // split units contribute ranges via skeleton linkage
            queryCu(cu, rel, raw, warnings)
        }
        // Split units (standalone .dwo import without skeleton): still searchable.
        for (cu in info.units) {
            if (!cu.isSplit) continue
            queryCu(cu, rel, raw, warnings)
        }

        if (info.splitStatus == SplitStatus.MISSING_DWO) {
            warnings.add("DW_AT_dwo_name 指向的 .dwo 缺失: split unit 的行号/类型可能不完整")
            trusted.add("skeleton 主文件中的函数地址范围与非 split CU 的行号仍可信")
        }
        for (iss in info.issues) warnings.add("[${iss.section}] ${iss.message}")
        if (raw.isEmpty()) trusted.add("地址未落入任何已知 range / line sequence（结论: 无匹配, 可信）")

        // Sort key order: narrowest enclosing range, then greatest inline depth,
        // then fully deterministic absolute offsets (import-order independent).
        val ordered = raw.sortedWith(compareBy(
            { widthKey(it.sortWidth) }, { -it.inlineDepth },
            { it.cuOffset }, { it.dieOffset }, { it.sequenceIndex }, { it.rowAddress }
        ))

        val candidates = ordered.mapIndexed { idx, c -> buildCandidate(idx + 1, c) }
        val versions = ordered.mapNotNull { it.lineVersion }.distinct().ifEmpty {
            info.units.map { it.tableVersion }.distinct()
        }
        return AddressQueryResult(
            runtimePc = runtimePc, relativePc = rel,
            loadBias = load?.loadBias ?: 0L, module = load,
            candidates = candidates, trusted = trusted.distinct(),
            warnings = warnings.distinct(), tableVersions = versions
        )
    }

    // Zero-length ranges are exact-point matches: narrowest possible.
    private fun widthKey(w: Long): Long = when (w) {
        0L -> -1L
        Long.MAX_VALUE -> Long.MAX_VALUE
        else -> w
    }

    private class RawCandidate(
        val cu: CompilationUnit,
        val line: LineHit?,
        val sequenceIndex: Int,
        val rowAddress: Long,
        val chain: List<InlineFrame>,
        val function: String?,
        val inlineDepth: Int,
        val narrowestRange: Long,
        val sortWidth: Long,
        val cuOffset: Long,
        val dieOffset: Long,
        val lineVersion: String?
    )

    private fun queryCu(
        cu: CompilationUnit, rel: Long, out: MutableList<RawCandidate>, warnings: MutableList<String>
    ) {
        // Line table: pick last row whose address <= rel within each sequence.
        val lineHits = ArrayList<LineHit>()
        cu.lineProgram?.let { lp ->
            lp.sequences.forEachIndexed { si, seq ->
                if (seq.rows.size < 2 || rel !in seq.start until seq.end) return@forEachIndexed
                var best: LineRow? = null
                for (row in seq.rows) {
                    if (row.endSequence) continue
                    if (row.address <= rel) best = row else break
                }
                val row = best ?: return@forEachIndexed
                val file = lp.files.getOrNull(row.file - 1)?.name
                    ?: lp.files.getOrNull(row.file)?.name ?: "?"
                lineHits.add(LineHit(file, row.line, row.column, si, row.address,
                    "DWARF${lp.version}", row.isStmt, row.endSequence))
            }
        }
        cu.issues.forEach { warnings.add("CU@${cu.offset}: $it") }

        // DIE coverage + inline chains.
        val chains = ArrayList<Pair<List<InlineFrame>, Die>>()
        cu.root?.let { findChains(it, rel, emptyList(), chains) }

        if (lineHits.isEmpty() && chains.isEmpty()) return

        if (chains.isEmpty()) {
            for (lh in lineHits) {
                out.add(RawCandidate(cu, lh, lh.sequenceIndex, lh.rowAddress, emptyList(),
                    null, 0, Long.MAX_VALUE, Long.MAX_VALUE, cu.offset, cu.offset, lh.tableVersion))
            }
            return
        }
        for ((chain, leaf) in chains) {
            val width = DieRanges.of(leaf).minByOrNull { it.width }?.width ?: Long.MAX_VALUE
            val lh = lineHits.firstOrNull() // one line program per CU; rows already address-precise
            out.add(RawCandidate(cu, lh, lh?.sequenceIndex ?: -1, lh?.rowAddress ?: 0L,
                chain, functionName(leaf), chain.size - 1, width,
                if (width == 0L || width == Long.MAX_VALUE) width else width,
                cu.offset, leaf.globalOffset, lh?.tableVersion ?: cu.tableVersion))
        }
    }

    /** Walk DIE tree; every time a subprogram/inlined DIE covers rel, push its frame. */
    private fun findChains(
        die: Die, rel: Long, path: List<Die>, out: ArrayList<Pair<List<InlineFrame>, Die>>
    ) {
        val relevant = die.isSubprogram || die.isInlinedSubroutine
        val covers = DieRanges.of(die).any { it.contains(rel) }
        val nextPath = if (relevant && covers) path + die else path
        if (relevant && covers) out.add(buildFrames(nextPath) to die)
        for (c in die.children) findChains(c, rel, nextPath, out)
    }

    private fun buildFrames(stack: List<Die>): List<InlineFrame> =
        stack.mapIndexed { depth, die ->
            val origin = resolveOrigin(die)
            val name = functionName(die) ?: functionName(origin) ?: "??"
            val range = DieRanges.of(die).minByOrNull { it.width }
            InlineFrame(
                function = name,
                depth = depth,
                callFile = die.num(DW_AT_call_file)?.let { "file#$it" },
                callLine = die.num(DW_AT_call_line)?.toInt() ?: 0,
                rangeLow = range?.low ?: 0L,
                rangeHigh = range?.high ?: 0L,
                abstractName = functionName(origin),
                dieOffset = die.globalOffset
            )
        }

    private fun resolveOrigin(die: Die, hops: Int = 0): Die? {
        if (hops > Limits.MAX_REF_HOPS) return null
        val ref = die.ref(DW_AT_abstract_origin) ?: die.ref(DW_AT_specification) ?: return null
        val target = cuLocalDie(die.cu, ref) ?: return null
        return if (target.ref(DW_AT_abstract_origin) != null) resolveOrigin(target, hops + 1) else target
    }

    private fun cuLocalDie(cu: CompilationUnit, cuRelative: Long): Die? {
        val root = cu.root ?: return null
        return findByOffset(root, cuRelative - cu.dieHeaderLength())
    }

    private fun findByOffset(die: Die, off: Long): Die? {
        if (die.globalOffset == off) return die
        for (c in die.children) findByOffset(c, off)?.let { return it }
        return null
    }

    private fun functionName(die: Die?): String? {
        if (die == null) return null
        return die.str(DW_AT_linkage_name) ?: die.str(DW_AT_MIPS_linkage_name)
            ?: die.str(DW_AT_name)
    }

    private fun buildCandidate(rank: Int, c: RawCandidate): AddressCandidate {
        val confidence = when {
            c.line != null && c.chain.isNotEmpty() -> "高: 行表与内联链一致"
            c.line != null -> "中: 仅行表命中, 无函数 DIE 覆盖"
            c.chain.isNotEmpty() -> "中: 仅函数范围命中, 无行号"
            else -> "低"
        }
        return AddressCandidate(
            rank = rank,
            cuName = c.cu.name, compDir = c.cu.compDir,
            line = c.line, sequenceIndex = c.sequenceIndex,
            inlineChain = c.chain, coveringFunction = c.function,
            confidence = confidence,
            tieKey = "cu=${c.cuOffset} die=${c.dieOffset} seq=${c.sequenceIndex} row=${c.rowAddress}"
        )
    }
}
