package compass.core

import compass.dwarf.*

data class LoadSnapshot(
    val id: Long,
    val label: String,
    val fileId: Long,
    val generation: Int,
    val loadBias: Long,           // 运行时加载基址；rel = runtime - bias
    val moduleBaseVaddr: Long,    // ELF 镜像中最低 PT_LOAD 的 vaddr（通常 0）
    val note: String = ""
)

class LoadedFile(val fileId: Long, val parsed: ParsedDebugFile)

class QueryService {
    private val files = LinkedHashMap<Long, LoadedFile>()
    private val snapshots = LinkedHashMap<Long, LoadSnapshot>()

    @Synchronized
    fun registerFile(fileId: Long, parsed: ParsedDebugFile) { files[fileId] = LoadedFile(fileId, parsed) }

    @Synchronized
    fun registerSnapshot(s: LoadSnapshot) { snapshots[s.id] = s }
    @Synchronized
    fun snapshot(id: Long): LoadSnapshot? = snapshots[id]
    @Synchronized
    fun allSnapshots(): List<LoadSnapshot> = snapshots.values.toList()
    @Synchronized
    fun file(id: Long): LoadedFile? = files[id]

    private fun resolverFor(lf: LoadedFile): Resolver {
        val r = Resolver()
        val p = lf.parsed
        r.v4Provider = { off, addrSize ->
            // 直接用 RangeListParser 的惰性解析
            val sec = DebugSections(p.elf)
            RangeListParser(sec).parseV4At(off, addrSize)
        }
        r.addrIndexProvider = { index, unit -> readDebugAddr(p, unit, index) }
        r.rngListAtProvider = { off, unit -> resolveV5List(p, off, unit) }
        return r
    }

    private fun readDebugAddr(p: ParsedDebugFile, unit: CompUnit, index: Long): Long? {
        val bytes = p.elf.section(".debug_addr") ?: return null
        val base = unit.addrBase ?: 0L
        val pos = (base + index * unit.addressSize).toInt()
        if (pos < 0 || pos + unit.addressSize > bytes.size) return null
        var v = 0L
        for (i in 0 until unit.addressSize) v = v or ((bytes[pos + i].toLong() and 0xff) shl (8 * i))
        return v
    }

    private fun resolveV5List(p: ParsedDebugFile, sectionOffset: Long, unit: CompUnit): List<AddrRange>? {
        val list = p.rangeLists.v5Lists[sectionOffset] ?: return null
        val out = ArrayList<AddrRange>()
        var base = 0L
        var segBase = 0L
        for (item in list.items) when (item) {
            is RngV5Item.EndList -> break
            is RngV5Item.BaseAddress -> { base = item.address; segBase = 0 }
            is RngV5Item.BaseAddressX -> { base = readDebugAddr(p, unit, item.index) ?: return out; segBase = 0 }
            is RngV5Item.StartxEndx -> {
                val b = readDebugAddr(p, unit, item.startIndex) ?: return out
                val e = readDebugAddr(p, unit, item.endIndex) ?: return out
                out += AddrRange(SegAddr(0, b), SegAddr(0, e))
            }
            is RngV5Item.StartxLength -> {
                val b = readDebugAddr(p, unit, item.startIndex) ?: return out
                out += AddrRange(SegAddr(0, b), SegAddr(0, b + item.length))
            }
            is RngV5Item.OffsetPair -> {
                out += AddrRange(SegAddr(item.segment, base + item.startOffset), SegAddr(item.segment, base + item.endOffset))
                if (item.segment != 0L) segBase = item.segment
            }
            is RngV5Item.StartEnd ->
                out += AddrRange(SegAddr(item.segment, item.start), SegAddr(item.segment, item.end))
            is RngV5Item.StartLength ->
                out += AddrRange(SegAddr(item.segment, item.start), SegAddr(item.segment, item.start + item.length))
        }
        return out
    }

    @Synchronized
    fun query(runtime: SegAddr, snapshotId: Long?): List<AddressResult> {
        val targetSnapshots = snapshotId?.let { listOfNotNull(snapshots[it]) } ?: snapshots.values.toList()
        return targetSnapshots.map { snap -> resolveOne(runtime, snap) }
    }

    @Synchronized
    fun queryBatch(items: List<SegAddr>, snapshotId: Long?): List<AddressResult> =
        items.flatMap { query(it, snapshotId) }

    private fun resolveOne(runtime: SegAddr, snap: LoadSnapshot): AddressResult {
        val lf = files[snap.fileId]
            ?: return emptyResult(runtime, snap, listOf("快照引用的调试文件版本不存在（可能已被新版本替换，旧记录仍保留）"))
        val rel = SegAddr(runtime.segment, runtime.offset - snap.loadBias + snap.moduleBaseVaddr)
        val resolver = resolverFor(lf)
        val units = lf.parsed.units

        val lineHits = resolver.matchLine(units, rel)
        val scopeHits = resolver.scopesAt(units, rel)

        val notes = ArrayList<String>()
        // ---- 行候选：与 scope 关联形成完整解释；行命中独立也保留 ----
        data class Full(
            val line: LineMatch, val scope: Scope?, val width: Long,
            val inlineDepth: Int, val priority: Int, val unitStable: Long, val lineStable: Long
        )
        val fulls = ArrayList<Full>()
        for (lm in lineHits) {
            // 为该 CU 找包含地址的最深 scope
            val bestScope = scopeHits.filter { it.first.unit === lm.unit }.minWithOrNull(
                compareBy<Pair<Scope, Long>> { it.second }.thenByDescending { it.first.inlineDepth }
            )
            val scope = bestScope?.first
            val width = bestScope?.second ?: Long.MAX_VALUE
            val depth = scope?.inlineDepth ?: 0
            val priority = scopePriority(scope)
            fulls += Full(lm, scope, width, depth, priority, stableUnit(lm.unit), lm.row.address.offset)
        }
        // scope 命中但没有任何行命中（例如 dwo 缺失场景）也作为候选补充
        for ((scope, width) in scopeHits) {
            if (lineHits.any { it.unit === scope.unit }) continue
            val synthetic = LineMatch(scope.unit,
                LineSequence(-1, SegAddr(0, 0), SegAddr(0, 0)),
                LineRow(-1, rel, 0, scope.declLine ?: 0, 0, false, false, false, false, 0, 0, false),
                scope.declFile ?: "?", 0, false)
            fulls += Full(synthetic, scope, width, scope.inlineDepth, scopePriority(scope),
                stableUnit(scope.unit), rel.offset)
            notes += "CU ${scope.unit.name.ifEmpty { "0x${scope.unit.sectionOffset.toString(16)}" }} 没有可用行表，仅给出函数级结论"
        }

        // ---- 稳定排序：最窄范围 → 内联深度 → 显式优先级 → 与行点距离 → 稳定标识 ----
        val sorted = fulls.sortedWith(
            compareBy<Full>
                { it.width }
                .thenByDescending { it.inlineDepth }
                .thenBy { it.priority }
                .thenBy { it.line.distance }
                .thenBy { it.unitStable }
                .thenBy { it.lineStable }
                .thenBy { it.line.row.line }
        )

        val candidates = sorted.mapIndexed { i, f ->
            CandidateView(
                rank = i + 1,
                filePath = f.line.filePath,
                line = f.line.row.line,
                column = f.line.row.column,
                unit = f.line.unit.name.ifEmpty { "0x${f.line.unit.sectionOffset.toString(16)}" },
                unitOffset = f.line.unit.sectionOffset,
                sequence = f.line.sequence.index,
                rangeWidth = if (f.width == Long.MAX_VALUE) -1L else f.width,
                inlineDepth = f.inlineDepth,
                equalPoint = f.line.equalPoint,
                tableVersion = f.line.unit.lineProgram?.version ?: f.line.unit.version,
                selectionReason = reason(f, sorted.firstOrNull() === f)
            )
        }

        val top = sorted.firstOrNull()
        val chain = top?.scope?.let { buildChain(it) } ?: emptyList()
        val trust = computeTrust(lf.parsed, top, notes)
        val topRow = top?.line?.row

        return AddressResult(
            runtimeAddress = runtime,
            relativeAddress = rel,
            loadBias = snap.loadBias,
            snapshotId = snap.id,
            snapshotLabel = snap.label,
            filePath = top?.line?.filePath,
            fileId = topRow?.fileId,
            line = topRow?.line,
            column = topRow?.column,
            tableVersion = top?.line?.unit?.lineProgram?.version,
            unitName = top?.line?.unit?.name?.ifEmpty { null },
            unitOffset = top?.line?.unit?.sectionOffset,
            sequenceIndex = top?.line?.sequence?.index?.takeIf { it >= 0 },
            sequenceStart = top?.line?.sequence?.start?.takeIf { top.line.sequence.index >= 0 },
            sequenceEnd = top?.line?.sequence?.end?.takeIf { top.line.sequence.index >= 0 },
            inlineChain = chain,
            candidates = candidates,
            trust = trust,
            notes = notes.distinct()
        )
    }

    private fun reason(f: Full, isTop: Boolean): String {
        if (!isTop) return "合法候选：范围/深度/优先级排序后非首选"
        return "最窄包含范围，优先采用"
    }

    private fun scopePriority(s: Scope?): Int = when (s?.tag) {
        Tag.INLINED_SUBROUTINE -> 0
        Tag.SUBPROGRAM -> 1
        Tag.LEXICAL_BLOCK -> 2
        null -> 9
        else -> 5
    }

    private fun buildChain(deepest: Scope): List<InlineFrame> {
        val up = ArrayList<Scope>()
        var s: Scope? = deepest
        while (s != null) { up += s; s = s.parent }
        up.reverse()
        return up.mapIndexed { depth, sc ->
            InlineFrame(
                depth = depth,
                name = sc.name,
                tag = when (sc.tag) { Tag.INLINED_SUBROUTINE -> "inlined_subroutine"; Tag.SUBPROGRAM -> "subprogram"; else -> "lexical_block" },
                declFile = sc.declFile,
                declLine = sc.declLine,
                callFile = sc.callFile,
                callLine = sc.callLine,
                callColumn = sc.callColumn,
                rangeWidth = sc.ranges.minOfOrNull { if (it.zeroLength) 0L else it.length } ?: -1L,
                dieOffset = sc.dieOffset
            )
        }
    }

    /** 与导入次序无关的稳定 CU 排序键：内容 hash + section offset。 */
    private fun stableUnit(u: CompUnit): Long {
        // 用偏移作为稳定键的一部分（同一文件内唯一）；跨文件则由 snapshot 隔离
        return u.sectionOffset
    }

    private fun computeTrust(parsed: ParsedDebugFile, top: Full?, notes: MutableList<String>): TrustInfo {
        val reasons = ArrayList<String>()
        var level = TrustInfo.HIGH
        parsed.issues.filter { it.severity == ParseIssue.Severity.ERROR }.let { errs ->
            if (errs.isNotEmpty()) { level = TrustInfo.LOW; reasons += "文件存在 ${errs.size} 个解析错误，部分结论可能缺失" }
        }
        parsed.issues.filter { it.code == "dwo.missing" }.let { miss ->
            if (miss.isNotEmpty()) {
                if (level == TrustInfo.HIGH) level = TrustInfo.MEDIUM
                reasons += "缺少 dwo 拆分调试信息：skeleton 行号可信，但内联/类型细节可能不完整"
            }
        }
        if (top == null) {
            level = TrustInfo.LOW
            reasons += "没有任何范围或行表覆盖该地址"
        }
        if (reasons.isEmpty()) reasons += "行表与 DIE 范围完整匹配，结论可信"
        return TrustInfo(level, reasons)
    }

    private fun emptyResult(runtime: SegAddr, snap: LoadSnapshot, notes: List<String>): AddressResult =
        AddressResult(runtime, SegAddr(runtime.segment, runtime.offset - snap.loadBias), snap.loadBias,
            snap.id, snap.label, null, null, null, null, null, null, null, null, null, null,
            emptyList(), emptyList(), TrustInfo(TrustInfo.LOW, notes), notes)
}
