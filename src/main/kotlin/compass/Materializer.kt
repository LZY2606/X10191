package compass

/**
 * Turns raw parsed CUs into query-ready [CompilationUnit]s:
 * pairs skeleton/split by dwo_id, resolves references, computes ranges and attaches line programs.
 */
class Materializer(private val files: List<RawFile>, private val warnings: MutableList<ParseWarning>) {

    private data class Key(val file: Int, val unit: Long, val local: Long)
    private class Asm(val skel: RawUnit?, val split: RawUnit?)
    private inner class UCtx(val raw: RawUnit, val file: RawFile, val split: Boolean)

    private fun isSplit(u: RawUnit) = u.unitType == Dw.UT_SPLIT_COMPILE || u.unitType == Dw.UT_SPLIT_TYPE
    private fun asLong(v: Any?): Long? = if (v is Long) v else (v as? TargetAddress)?.offset
    private fun asAddr(v: Any?): TargetAddress? = v as? TargetAddress
    private fun asStr(v: Any?): String? = v as? String

    fun build(): List<ParsedFile> {
        val byDwo = LinkedHashMap<Long, Asm>()
        val solo = mutableListOf<Asm>()
        files.forEach { f ->
            f.units.forEach { u ->
                val id = u.dwoId
                if (id == null) solo.add(Asm(if (isSplit(u)) null else u, if (isSplit(u)) u else null))
                else {
                    val a = byDwo.getOrPut(id) { Asm(null, null) }
                    if (isSplit(u)) byDwo[id] = Asm(a.skel, u) else byDwo[id] = Asm(u, a.split)
                }
            }
        }
        val ordered = (solo + byDwo.values).sortedWith(
            compareBy({ (it.skel ?: it.split)!!.fileIndex }, { (it.skel ?: it.split)!!.headerStart })
        )
        val byFile = HashMap<Int, MutableList<CompilationUnit>>()
        for (a in ordered) {
            val r = materialize(a)
            byFile.getOrPut(r.second) { mutableListOf() }.add(r.first)
        }
        return files.mapIndexed { idx, f ->
            f.parsedFile.copy(cus = byFile[idx].orEmpty().sortedBy { it.globalOffset })
        }
    }

    private fun ctxOf(u: RawUnit) = UCtx(u, files[u.fileIndex], isSplit(u))

    private fun dieByKey(k: Key?): Pair<UCtx, RawDie>? {
        if (k == null) return null
        val f = files.getOrNull(k.file) ?: return null
        val u = f.units.firstOrNull { it.headerStart == k.unit } ?: return null
        val d = u.dies[k.local] ?: return null
        return UCtx(u, f, isSplit(u)) to d
    }

    private fun pairCtxs(c: UCtx): List<UCtx> {
        val id = c.raw.dwoId ?: return listOf(c)
        return files.flatMap { f -> f.units.filter { it.dwoId == id }.map { UCtx(it, f, isSplit(it)) } }
    }

    private fun resolveRef(from: UCtx, v: Any?): Key? {
        if (v !is UnresolvedRef) return null
        return when (v.kind) {
            "ref_cu" -> {
                val local = v.target
                if (from.raw.dies.containsKey(local)) return Key(from.raw.fileIndex, from.raw.headerStart, local)
                pairCtxs(from).firstOrNull { it.raw.dies.containsKey(local) }
                    ?.let { Key(it.raw.fileIndex, it.raw.headerStart, local) }
            }
            "ref_addr" -> {
                files.forEachIndexed { fi, f ->
                    f.units.forEach { u ->
                        val local = v.target - u.headerStart
                        if (local >= 0 && u.dies.containsKey(local)) return Key(fi, u.headerStart, local)
                    }
                }
                null
            }
            else -> null
        }
    }

    /** Follow abstract_origin/specification chain to find a name or declaration coord. */
    private fun <T> followChain(start: UCtx, die: RawDie, extract: (RawDie) -> T?): T? {
        extract(die)?.let { return it }
        var cur = die
        var ctx = start
        var hops = 0
        val seen = HashSet<Long>()
        while (hops++ < Limits.MAX_REF_HOPS) {
            val refVal = cur.at(Dw.AT_ABSTRACT_ORIGIN)?.value ?: cur.at(Dw.AT_SPECIFICATION)?.value ?: return null
            val key = resolveRef(ctx, refVal)
            val found = dieByKey(key) ?: return null
            ctx = found.first; cur = found.second
            if (!seen.add(cur.globalOffsetRaw())) return null
            extract(cur)?.let { return it }
        }
        return null
    }

    private fun RawDie.globalOffsetRaw(): Long = globalOffset

    private fun findRnglistsHeader(section: ByteArray, base: Long?): Int {
        // DW_AT_rnglists_base (v5) points at the offset array; header begins 8 bytes earlier
        // (4 initial_length + 2 version + 1 address_size + 1 segment_selector_size).
        if (base != null) {
            val candidate = (base - 8).toInt()
            if (candidate >= 0 && candidate < section.size) return candidate
        }
        return 0
    }

    private fun computeRanges(c: UCtx, die: RawDie, cuLowPc: Long, outWarn: MutableList<String>): Pair<List<RangeWithOrigin>, Boolean> {
        val rangesAttr = die.at(Dw.AT_RANGES)
        val lowPcV = die.at(Dw.AT_LOW_PC)?.value
        val highPcAttr = die.at(Dw.AT_HIGH_PC)
        val out = mutableListOf<RangeWithOrigin>()
        try {
            if (rangesAttr != null) {
                if (c.raw.dwarf5) {
                    val rl = c.file.ctx.store.bytes(".debug_rnglists")
                        ?: c.file.ctx.store.bytes(".debug_rnglists.dwo")
                        ?: throw CursorException(".debug_rnglists missing")
                    val rr = RangeReader(c.file.ctx)
                    val baseAttr = c.raw.rnglistsBase
                    val headerOff = findRnglistsHeader(rl, baseAttr)
                    val isIndex = rangesAttr.formCode == Dw.FORM_RNGLISTX
                    val listOff = rangesAttr.value as Long
                    val resolved = if (isIndex) rr.resolveRnglistxOffset(rl, headerOff, listOff) else listOff
                    val asz = c.raw.addressSize
                    val addrLookup: (Long) -> TargetAddress = { idx ->
                        val tableBase = c.raw.addrBase
                            ?: pairCtxs(c).firstNotNullOfOrNull { it.raw.addrBase }
                            ?: throw CursorException("addrx without addr_base")
                        val addrSec = listOfNotNull(
                            c.file.ctx.store.bytes(".debug_addr"), c.file.ctx.store.bytes(".debug_addr.dwo")
                        ).firstOrNull()
                            ?: files.flatMap { ff ->
                                listOfNotNull(ff.ctx.store.bytes(".debug_addr"), ff.ctx.store.bytes(".debug_addr.dwo"))
                            }.firstOrNull()
                            ?: throw CursorException(".debug_addr missing")
                        AddrTableReader(addrSec).get(tableBase, idx, asz, gnuStyle = !c.raw.dwarf5)
                    }
                    rr.readV5List(rl, headerOff, baseAttr ?: 0L, resolved, addrLookup, TargetAddress(cuLowPc))
                        .forEach { out.add(RangeWithOrigin(it, RangeOrigin.RNGLIST_V5)) }
                } else {
                    val rs = c.file.ctx.store.bytes(".debug_ranges")
                        ?: c.file.ctx.store.bytes(".debug_ranges.dwo")
                        ?: throw CursorException(".debug_ranges missing")
                    RangeReader(c.file.ctx)
                        .readV4(rs, rangesAttr.value as Long, c.raw.addressSize, c.raw.segmentSelectorSize, TargetAddress(cuLowPc))
                        .forEach { out.add(RangeWithOrigin(it, RangeOrigin.RANGES_V4)) }
                }
            } else if (lowPcV != null && highPcAttr != null) {
                val start = asAddr(lowPcV) ?: TargetAddress(asLong(lowPcV) ?: 0L)
                when (val hv = highPcAttr.value) {
                    is TargetAddress -> out.add(RangeWithOrigin(AddrRange(start, hv), RangeOrigin.LOW_HIGH_PC))
                    is Long -> {
                        val form = highPcAttr.formCode
                        if (FormReader.isAddressForm(form)) out.add(RangeWithOrigin(AddrRange(start, TargetAddress(hv, start.segment)), RangeOrigin.LOW_HIGH_PC))
                        else out.add(RangeWithOrigin(AddrRange(start, TargetAddress(start.offset + hv, start.segment)), RangeOrigin.LOW_HIGH_PC))
                    }
                }
            } else if (lowPcV != null) {
                val start = asAddr(lowPcV) ?: TargetAddress(asLong(lowPcV) ?: 0L)
                out.add(RangeWithOrigin(AddrRange(start, start), RangeOrigin.IMPLICIT_SINGLE_POINT))
            }
        } catch (e: Exception) {
            outWarn.add("ranges for DIE 0x${die.globalOffset.toString(16)}: ${e.message}")
            return emptyList<RangeWithOrigin>() to false
        }
        return out to true
    }


    private fun materialize(a: Asm): Pair<CompilationUnit, Int> {
        val skel = a.skel; val split = a.split
        val primary = skel ?: split!!
        val w = primary.warnings.toMutableList()
        skel?.warnings?.let { if (skel !== primary) w.addAll(it) }
        split?.warnings?.let { if (split !== primary) w.addAll(it) }

        val skelC = skel?.let { ctxOf(it) }
        val splitC = split?.let { ctxOf(it) }
        val primaryC = if (skelC != null) skelC else splitC!!
        val dwoMissing = skelC != null && splitC == null && skel!!.dwoId != null

        val dwoStatus: String
        val trust: String
        when {
            dwoMissing -> { dwoStatus = "SKELETON_NO_DWO"; trust = "RANGE_ONLY" }
            skelC != null && splitC != null -> { dwoStatus = "COMPANION_PRESENT"; trust = "FULL" }
            splitC != null -> { dwoStatus = "SPLIT_COMPANION"; trust = "FULL" }
            else -> { dwoStatus = "FULL"; trust = "FULL" }
        }

        val rootRaw = primary.dies[primary.rootOffset]!!
        val name = asStr(rootRaw.at(Dw.AT_NAME)?.value)
        val compDir = asStr(rootRaw.at(Dw.AT_COMP_DIR)?.value)
        val producer = asStr(rootRaw.at(Dw.AT_PRODUCER)?.value)
        val language = asLong(rootRaw.at(Dw.AT_LANGUAGE)?.value)
        val dwoName = asStr(rootRaw.at(Dw.AT_DWO_NAME)?.value)
        val stmtList = asLong(rootRaw.at(Dw.AT_STMT_LIST)?.value)
        val cuLowPc = asAddr(rootRaw.at(Dw.AT_LOW_PC)?.value)?.offset ?: 0L

        // Build nodes per unit, with resolved references across the pair.
        val nodes = LinkedHashMap<Long, DieNode>()
        val nodeOrder = mutableListOf<Long>()
        val nodeToCtx = HashMap<Long, UCtx>()

        fun processUnit(c: UCtx) {
            for ((local, die) in c.raw.dies) {
                val (ranges, rangesValid) = computeRanges(c, die, cuLowPc, w)
                val displayAttrs = LinkedHashMap<String, DieAttr>()
                for (ra in die.attrs) {
                    val attrName = AtNames.name(ra.atCode)
                    displayAttrs[attrName] = DieAttr(attrName, Dw.formName(ra.formCode), ra.display)
                }
                fun refGlobal(code: Long): Long? {
                    val v = die.at(code)?.value ?: return null
                    return resolveRef(c, v)?.let { (it.unit and 0xffffffffL) + it.local }
                }
                fun nameOf(): String? = followChain(c, die) { d ->
                    asStr(d.at(Dw.AT_NAME)?.value) ?: asStr(d.at(Dw.AT_LINKAGE_NAME)?.value)
                    ?: asStr(d.at(Dw.AT_MIPS_LINKAGE_NAME)?.value)
                }
                val node = DieNode(
                    globalOffset = local,
                    tag = Dw.tagName(die.tag),
                    tagCode = die.tag,
                    depth = die.depth,
                    parentOffset = die.parent,
                    childOffsets = die.children,
                    attrs = displayAttrs,
                    ranges = ranges,
                    name = nameOf(),
                    declFileIndex = asLong(die.at(Dw.AT_DECL_FILE)?.value),
                    declLine = asLong(die.at(Dw.AT_DECL_LINE)?.value),
                    declColumn = asLong(die.at(Dw.AT_DECL_COLUMN)?.value),
                    callFileIndex = asLong(die.at(Dw.AT_CALL_FILE)?.value),
                    callLine = asLong(die.at(Dw.AT_CALL_LINE)?.value),
                    callColumn = asLong(die.at(Dw.AT_CALL_COLUMN)?.value),
                    inlineCode = asLong(die.at(Dw.AT_INLINE)?.value),
                    abstractOriginGlobal = refGlobal(Dw.AT_ABSTRACT_ORIGIN),
                    specificationGlobal = refGlobal(Dw.AT_SPECIFICATION),
                    hasRangesAttr = die.at(Dw.AT_RANGES) != null,
                    rangesValid = rangesValid,
                )
                nodes[local] = node
                nodeOrder.add(local)
                nodeToCtx[local] = c
            }
        }
        splitC?.let { processUnit(it) }
        processUnit(primaryC)

        val rootRanges = nodes[primary.rootOffset]?.ranges ?: emptyList()

        // Line program: prefer skeleton .debug_line; then split (.debug_line.dwo/.debug_line).
        var lineProgram: LineProgram? = null
        if (stmtList != null) {
            val lpWarn = mutableListOf<ParseWarning>()
            val sources = listOfNotNull(skelC, splitC)
            for (c in sources) {
                val sec = c.file.ctx.store.bytesAny(".debug_line", ".debug_line.dwo") ?: continue
                lineProgram = LineProgramParser(c.file.ctx).parse(sec.first, sec.second, stmtList, lpWarn)
                if (lineProgram != null) break
            }
            if (lineProgram == null && !dwoMissing) {
                w.add("line program at stmt_list=0x${stmtList.toString(16)} could not be parsed: ${lpWarn.joinToString { it.message }}")
            }
            lpWarn.forEach { warnings.add(it) }
        }

        val unitType = unitTypeName(primary.unitType)
        val cu = CompilationUnit(
            globalOffset = primary.headerStart,
            version = primary.version,
            dwarf5 = primary.dwarf5,
            unitType = unitType,
            unitTypeCode = primary.unitType,
            addressSize = primary.addressSize,
            segmentSelectorSize = primary.segmentSelectorSize,
            dwoName = dwoName,
            dwoId = primary.dwoId,
            compDir = compDir,
            name = name,
            producer = producer,
            language = language,
            stmtListOffset = stmtList,
            dieCount = nodes.size,
            dies = nodes,
            rootOffset = primary.rootOffset,
            dieOrder = nodeOrder,
            ranges = rootRanges,
            lineProgram = lineProgram,
            dwoStatus = dwoStatus,
            trustLevel = trust,
            warnings = w,
        )
        return cu to primary.fileIndex
    }

    private fun unitTypeName(t: Int) = when (t) {
        Dw.UT_COMPILE -> "DW_UT_compile"
        Dw.UT_TYPE -> "DW_UT_type"
        Dw.UT_PARTIAL -> "DW_UT_partial"
        Dw.UT_SKELETON -> "DW_UT_skeleton"
        Dw.UT_SPLIT_COMPILE -> "DW_UT_split_compile"
        Dw.UT_SPLIT_TYPE -> "DW_UT_split_type"
        else -> "DW_UT_0x${t.toString(16)}"
    }
}
