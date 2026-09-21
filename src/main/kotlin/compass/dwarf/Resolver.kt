package compass.dwarf

import kotlinx.serialization.Serializable

import compass.dwarf.DW_AT as A
import compass.dwarf.DW_TAG as T
import compass.elf.ElfFile

interface DebugVersion {
    val versionId: Long
    val label: String
    val priority: Int
    val image: DwarfImage
    val dwarfTableVersion: String get() = image.tableVersionSummary()
}

fun DwarfImage.tableVersionSummary(): String =
    (cus.map { it.version }.toSortedSet() + splitCus.map { it.version }.toSortedSet())
        .joinToString(",") { "DWARF$it" }.ifEmpty { "无 CU" }

data class ModuleLoad(
    val moduleId: Long,
    val versionId: Long,
    val generation: Long,
    val baseAddress: Long,
    val bias: Long,
    val loadedAt: Long,
    val label: String
)

@Serializable
data class InlineFrame(
    val dieOffset: Long,
    val name: String,
    val tag: Int,
    val depth: Int,
    val callFile: String?,
    val callLine: Int?,
    val callColumn: Int?,
    val declFile: String?,
    val declLine: Int?
)

@Serializable
data class LineCandidate(
    val versionId: Long,
    val versionLabel: String,
    val priority: Int,
    val cuOffset: Long,
    val cuName: String,
    val sequenceId: Int,
    val seqStart: Long,
    val seqEnd: Long,
    val relativeAddress: Long,
    val loadBias: Long,
    val file: String?,
    val line: Int,
    val column: Int,
    val dwarfVersion: Int,
    val segmented: Boolean,
    val inlineChain: List<InlineFrame>,
    val functionDieOffset: Long?,
    val rangeWidth: Long,
    val rangeZeroLength: Boolean,
    val generation: Long,
    val moduleLabel: String,
    val candidateKind: String
)

@Serializable
data class AddressAnswer(
    val queryAddress: Long,
    val moduleLabel: String?,
    val resolvedRelative: Long?,
    val loadBias: Long?,
    val generation: Long?,
    val candidates: List<LineCandidate>,
    val notes: List<String>
) {
    val primary: LineCandidate? get() = candidates.firstOrNull()
}

class AddressResolver(private val versions: List<DebugVersion>, private val loads: List<ModuleLoad>) {

    fun resolve(runtimeAddress: Long, atGeneration: Long? = null): AddressAnswer {
        val notes = mutableListOf<String>()
        val applicableLoads = loads
            .filter { atGeneration == null || it.generation == atGeneration }
            .sortedWith(compareByDescending<ModuleLoad> { it.generation }.thenBy { it.moduleId })
        if (applicableLoads.isEmpty())
            return AddressAnswer(runtimeAddress, null, null, null, null, emptyList(),
                listOf("没有匹配的模块加载快照：地址无法换算为相对地址。"))

        val candidates = mutableListOf<LineCandidate>()
        var matchedLoad: ModuleLoad? = null
        val candidateKeys = sortedSetOf<String>()

        for (load in applicableLoads) {
            val version = versions.firstOrNull { it.versionId == load.versionId } ?: continue
            val rel = runtimeAddress - load.bias
            if (rel < 0) continue
            val img = version.image
            val inLoad = img.elf.segments.any { seg ->
                seg.type == ElfFile.PT_LOAD && rel in seg.vaddr until seg.vaddr + seg.filesz
            } || img.elf.sections.any { it.size > 0 && rel in it.addr until it.addr + it.size }
            if (!inLoad) continue
            matchedLoad = load
            resolveInVersion(version, load, rel, candidates, candidateKeys)
        }

        val sorted = candidates.sortedWith(
            compareByDescending<LineCandidate> { it.priority }
                .thenBy { it.rangeWidth }
                .thenByDescending { it.inlineChain.size }
                .thenBy { it.versionId }
                .thenBy { it.cuOffset }
                .thenBy { it.sequenceId }
                .thenBy { it.functionDieOffset ?: -1L }
                .thenBy { it.relativeAddress }
        )

        if (sorted.isEmpty()) {
            notes.add("相对地址落在已加载模块内，但没有任何 line sequence 或函数范围覆盖它。")
        }
        if (applicableLoads.size > 1) {
            notes.add("同一相对地址命中了多个加载代次，已全部保留，按优先级/范围宽度排序。")
        }
        return AddressAnswer(runtimeAddress, matchedLoad?.label,
            sorted.firstOrNull()?.relativeAddress, sorted.firstOrNull()?.loadBias,
            matchedLoad?.generation, sorted, notes)
    }

    private data class FuncHit(val cu: CompUnit, val die: DieNode, val range: AddressRange)
    private data class LineHit(val cu: CompUnit, val seq: LineSequence, val row: LineRow)

    private fun resolveInVersion(
        version: DebugVersion, load: ModuleLoad, rel: Long,
        out: MutableList<LineCandidate>, keys: MutableSet<String>
    ) {
        val img = version.image
        val effectiveCus = linkedMapOf<Long, CompUnit>()
        for (cu in img.cus) {
            effectiveCus[cu.offset] = cu
            cu.splitCu?.let { effectiveCus[it.offset] = it }
        }
        for (cu in img.splitCus) effectiveCus.putIfAbsent(cu.offset, cu)

        val hits = mutableListOf<FuncHit>()
        for (cu in effectiveCus.values) collectFuncHits(cu, rel, hits)

        val lineHits = mutableListOf<LineHit>()
        for (seq in img.sequences) {
            if (rel < seq.startAddress || rel > seq.endAddress) continue
            if (seq.rows.none { !it.endSequence && it.address <= rel }) continue
            val cu = effectiveCus[seq.cuOffset]
                ?: img.cus.firstOrNull { it.offset == seq.cuOffset }
                ?: continue
            var best: LineRow? = null
            for (row in seq.rows) {
                if (row.endSequence) continue
                if (row.address <= rel) best = row else break
            }
            if (best != null) lineHits.add(LineHit(cu, seq, best))
        }

        if (lineHits.isEmpty()) {
            for (h in hits.sortedWith(compareBy<FuncHit> { it.range.width }.thenByDescending { it.die.depth })) {
                emit(version, load, rel, h.cu, null, h, out, keys)
            }
            return
        }

        for (lh in lineHits) {
            val skeletonOffset = lh.cu.skeletonCu?.offset
            val covering = hits.filter {
                it.cu.offset == lh.cu.offset || it.cu.offset == skeletonOffset ||
                    it.cu.skeletonCu?.offset == lh.cu.offset
            }
            val innermost = covering
                .sortedWith(compareBy<FuncHit> { it.range.width }.thenByDescending { it.die.depth })
                .firstOrNull()
            emit(version, load, rel, lh.cu, lh, innermost, out, keys)
        }
    }

    private fun collectFuncHits(cu: CompUnit, rel: Long, out: MutableList<FuncHit>) {
        val root = cu.root ?: return
        val stack = ArrayDeque<DieNode>().apply { add(root) }
        while (stack.isNotEmpty()) {
            val d = stack.removeFirst()
            for (rg in d.ranges) if (rg.contains(rel)) out.add(FuncHit(cu, d, rg))
            stack.addAll(d.children)
        }
    }

    private fun emit(
        version: DebugVersion, load: ModuleLoad, rel: Long,
        cu: CompUnit, lineHit: LineHit?, funcHit: FuncHit?,
        out: MutableList<LineCandidate>, keys: MutableSet<String>
    ) {
        val seq = lineHit?.seq
        val row = lineHit?.row
        val file = if (seq != null && row != null) seq.fileOf(row.fileId) else null
        val chain = if (funcHit != null) buildInlineChain(funcHit.die, cu) else emptyList()
        val key = "${version.versionId}:${cu.offset}:${seq?.id ?: -1}:${funcHit?.die?.offset ?: -1}:${rel}"
        if (!keys.add(key)) return
        out.add(LineCandidate(
            versionId = version.versionId,
            versionLabel = version.label,
            priority = version.priority,
            cuOffset = cu.offset,
            cuName = cu.root?.str(A.NAME)?.let { if (it.isEmpty()) "<anon>@0x${cu.offset.toString(16)}" else it }
                ?: "<anon>@0x${cu.offset.toString(16)}",
            sequenceId = seq?.id ?: -1,
            seqStart = seq?.startAddress ?: funcHit?.range?.start ?: rel,
            seqEnd = seq?.endAddress ?: funcHit?.range?.end ?: rel,
            relativeAddress = rel,
            loadBias = load.bias,
            file = file,
            line = row?.line ?: funcHit?.die?.num(A.DECL_LINE)?.toInt() ?: 0,
            column = row?.column ?: 0,
            dwarfVersion = cu.version,
            segmented = seq?.segmented ?: false,
            inlineChain = chain,
            functionDieOffset = funcHit?.die?.offset,
            rangeWidth = funcHit?.range?.width ?: (if (row != null) (rel - row.address).coerceAtLeast(0) else 0L),
            rangeZeroLength = funcHit?.range?.zeroLength ?: false,
            generation = load.generation,
            moduleLabel = load.label,
            candidateKind = when {
                funcHit == null -> "仅行号"
                funcHit.range.zeroLength -> "零长度符号"
                chain.size > 1 || funcHit.die.tag == T.INLINED_SUBROUTINE -> "函数+行号（含内联）"
                else -> "函数+行号"
            }
        ))
    }

    private fun resolveRef(d: DieNode, target: Long): DieNode? {
        val cu = d.cu ?: return null
        cu.dieByOffset[target]?.let { return it }
        cu.splitCu?.dieByOffset?.values?.firstOrNull { it.offset == target }?.let { return it }
        // DW_FORM_ref1..4 inside split CU are CU-relative; try that too.
        cu.splitCu?.let { sp -> sp.dieByOffset[sp.offset + (target - cu.offset)] }?.let { return it }
        return null
    }

    private fun dieName(d: DieNode): String {
        d.str(A.NAME)?.let { return it }
        d.str(A.LINKAGE_NAME)?.let { return it }
        var cur: DieNode? = d
        var hops = 0
        while (cur != null && hops < MAX_REF_HOPS) {
            hops++
            val c = cur!!
            val origin = c.num(A.ABSTRACT_ORIGIN) ?: c.num(A.SPECIFICATION) ?: break
            if (origin == 0L) break
            val r = resolveRef(c, origin) ?: break
            r.str(A.NAME)?.let { return it }
            r.str(A.LINKAGE_NAME)?.let { return it }
            cur = r
        }
        return "<anon>@0x${d.offset.toString(16)}"
    }

    private fun buildInlineChain(leaf: DieNode, cu: CompUnit): List<InlineFrame> {
        val frames = mutableListOf<InlineFrame>()
        var d: DieNode? = leaf
        var guard = 0
        while (d != null && guard++ < InfoParser.MAX_DIE_DEPTH) {
            val tag = d.tag
            if (tag == T.SUBPROGRAM || tag == T.INLINED_SUBROUTINE || tag == T.LEXICAL_BLOCK) {
                frames.add(InlineFrame(
                    dieOffset = d.offset,
                    name = dieName(d),
                    tag = tag,
                    depth = d.depth,
                    callFile = resolveFileRef(d.num(A.CALL_FILE), cu),
                    callLine = d.num(A.CALL_LINE)?.toInt(),
                    callColumn = d.num(A.CALL_COLUMN)?.toInt(),
                    declFile = resolveFileRef(d.num(A.DECL_FILE), cu),
                    declLine = d.num(A.DECL_LINE)?.toInt()
                ))
            }
            d = d.parent
        }
        return frames.reversed()
    }

    private fun resolveFileRef(id: Long?, cu: CompUnit): String? {
        if (id == null) return null
        val seqs = versions.flatMap { it.image.sequences }.filter {
            it.cuOffset == cu.offset || cu.skeletonCu != null && it.cuOffset == cu.skeletonCu!!.offset
        }
        for (seq in seqs) {
            val idx = if (cu.version >= 5) id.toInt() else id.toInt() - 1
            val f = seq.files.getOrNull(idx) ?: continue
            val dir = seq.dirs.getOrNull(f.dirIndex)
            return if (dir.isNullOrEmpty() || dir == ".") f.name else "$dir/${f.name}"
        }
        return null
    }

    companion object { const val MAX_REF_HOPS = 32 }
}
