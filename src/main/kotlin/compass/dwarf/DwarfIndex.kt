package compass.dwarf

import compass.elf.ElfFile

/** A function-like scope (concrete or abstract/inlined). */
data class Scope(
    val name: String,
    val cuOffset: Int,
    val dieOffset: Int,
    val tag: Int,
    val ranges: List<RangeEntry>,
    val inlineDepth: Int,
    val callFile: String?,
    val callLine: Int?,
    val abstract: Boolean,
    val concreteOriginOffset: Int?
)

/** One DWARF section with raw size + digest for the section map UI. */
data class SectionInfo(val name: String, val size: Long, val vma: Long, val sha256: String?)

/** Fully parsed, queryable debug information for one imported file version. */
class DwarfIndex(
    val elf: ElfFile,
    val cus: List<CompileUnit>,
    val scopes: List<Scope>,
    val sections: List<SectionInfo>,
    val rawSha256: String,
    val warnings: List<String>
) {
    val allSequences: List<LineSequence> = cus.flatMap { it.sequences }
}

object DwarfLoader {
    private val DWARF_SECTIONS = listOf(
        ".debug_info", ".debug_abbrev", ".debug_line", ".debug_line_str", ".debug_str",
        ".debug_str_offsets", ".debug_ranges", ".debug_rnglists", ".debug_addr",
        ".debug_info.dwo", ".debug_abbrev.dwo", ".debug_line.dwo", ".debug_line_str.dwo",
        ".debug_str.dwo", ".debug_str_offsets.dwo", ".debug_rnglists.dwo",
        ".debug_cu_index", ".debug_tu_index", ".gdb_index", ".debug_aranges"
    )

    fun load(elf: ElfFile): DwarfIndex {
        val warnings = ArrayList<String>()
        val bundle = DebugBundle(elf)
        if (bundle.info == null) {
            warnings.add("no .debug_info section — only ELF metadata is available")
        }
        val parsedCus = bundle.info?.let {
            try { DebugInfoParser(bundle).parse() }
            catch (e: Exception) { warnings.add(".debug_info parse failed: ${e.message}"); emptyList() }
        } ?: emptyList()

        val dwoCus = if (bundle.infoDwo != null) {
            try { DebugInfoParser(bundle, useDwo = true).parse() }
            catch (e: Exception) { warnings.add(".debug_info.dwo parse failed: ${e.message}"); emptyList() }
        } else emptyList()

        val cuNames = dwoCus.mapNotNull { it.root }
        val cus = ArrayList<CompileUnit>()
        val scopes = ArrayList<Scope>()

        val dwoByName = HashMap<String, DieNode>()
        for (pcu in dwoCus) {
            val root = pcu.root ?: continue
            val name = root.name()
            if (name != null) dwoByName[name] = root
        }

        for (pcu in parsedCus) {
            val root = pcu.root
            val notes = pcu.notes.toCollection(ArrayList())
            val lowPc = (root?.attr(DW.AT_LOW_PC) as? AttrValue.Address)?.v ?: 0L
            val addrBase = (root?.attr(DW.AT_ADDR_BASE) as? AttrValue.Constant)?.v ?: 0L
            val isSkeleton = pcu.version >= 5 && pcu.unitType == DebugInfoParser.DW_UT_SKELETON
            val isSplit = pcu.version >= 5 &&
                (pcu.unitType == DebugInfoParser.DW_UT_SPLIT_COMPILE || pcu.unitType == DebugInfoParser.DW_UT_SPLIT_TYPE)

            // CU-level ranges: AT_ranges, else low_pc/high_pc.
            val cuRanges = resolveCuRanges(bundle, pcu, root, lowPc, addrBase, notes)

            // Line programs for this CU (AT_stmt_list).
            val sequences = ArrayList<LineSequence>()
            val stmtOff = (root?.attr(DW.AT_STMT_LIST) as? AttrValue.Constant)?.v
            if (stmtOff != null && bundle.line != null) {
                val prog = LineProgramParser.parse(bundle, stmtOff, pcu.start, pcu.version)
                if (prog != null) { sequences.addAll(prog.sequences); notes.addAll(prog.notes) }
            }

            val dwoName = (root?.attr(DW.AT_DWO_NAME) as? AttrValue.StringVal)?.v
                ?: (root?.attr(DW.AT_GNU_DWO_NAME) as? AttrValue.StringVal)?.v
            val dwoAvailable = dwoName != null && dwoCus.isNotEmpty()
            if (isSkeleton && dwoName != null && dwoCus.isEmpty()) {
                notes.add("skeleton CU references '$dwoName' but no split DWARF (.dwo) was imported; " +
                    "line info remains usable, function/inlined-subroutine attribution may be incomplete")
            }

            // Scopes from the main/skeleton tree, plus split tree when available.
            val trees = ArrayList<Pair<DieNode, Boolean>>()
            if (root != null) trees.add(root to false)
            val dwoRoot = dwoName?.let { dwoByName[it] }
                ?: if (isSkeleton && dwoCus.size == 1) dwoCus.first().root else null
            if (dwoRoot != null) trees.add(dwoRoot to true)

            for ((treeRoot, fromSplit) in trees) {
                collectScopes(treeRoot, pcu.start, 0, scopes, cuRanges, bundle, pcu, lowPc, addrBase, fromSplit, notes)
            }
            if (root != null && dwoRoot == null && isSkeleton) {
                // skeleton may still carry the concrete outer subprogram ranges
                collectScopes(root, pcu.start, 0, scopes, cuRanges, bundle, pcu, lowPc, addrBase, false, notes)
            }

            val cu = CompileUnit(
                offset = pcu.start,
                version = pcu.version,
                unitType = pcu.unitType,
                is64 = pcu.is64,
                die = root ?: DieNode(pcu.start, 0, emptyMap(), 0),
                name = root?.name(),
                compDir = (root?.attr(DW.AT_COMP_DIR) as? AttrValue.StringVal)?.v,
                producer = (root?.attr(DW.AT_PRODUCER) as? AttrValue.StringVal)?.v,
                language = (root?.attr(DW.AT_LANGUAGE) as? AttrValue.Constant)?.v,
                stmtListOffset = stmtOff,
                rangesOffset = (root?.attr(DW.AT_RANGES) as? AttrValue.Constant)?.v,
                dwoName = dwoName,
                skeletonFor = isSkeleton,
                split = isSplit,
                addressSize = pcu.addressSize,
                strOffsetsBase = (root?.attr(DW.AT_STRL_OFFSETS_BASE) as? AttrValue.Constant)?.v ?: 0L,
                addrBase = addrBase,
                rangesBase = (root?.attr(DW.AT_RNGLISTS_OFFSETS_BASE) as? AttrValue.Constant)?.v ?: 0L,
                ranges = cuRanges,
                sequences = mergeSequences(sequences),
                notes = notes.distinct(),
                allDies = root?.flatten() ?: emptyList()
            )
            cus.add(cu)
        }

        val sections = DWARF_SECTIONS.mapNotNull { name ->
            elf.section(name)?.let { SectionInfo(name, it.size, it.addr, elf.sectionDigest(name)) }
        }
        return DwarfIndex(elf, cus, scopes.sortedWith(scopeOrder), sections, elf.rawSha256, warnings.distinct())
    }

    private val scopeOrder: Comparator<Scope> = compareBy(
        { it.cuOffset },
        { it.dieOffset }
    )

    private fun mergeSequences(seqs: List<LineSequence>): List<LineSequence> =
        seqs.sortedBy { it.startAddress }

    private fun DieNode.flatten(acc: MutableList<DieNode> = ArrayList()): List<DieNode> {
        acc.add(this)
        children.forEach { it.flatten(acc) }
        return acc
    }

    private fun resolveCuRanges(
        bundle: DebugBundle,
        pcu: ParsedCu,
        root: DieNode?,
        lowPc: Long,
        addrBase: Long,
        notes: MutableList<String>
    ): List<RangeEntry> {
        if (root == null) return emptyList()
        val rangesAttr = root.attr(DW.AT_RANGES)
        if (rangesAttr is AttrValue.Constant) {
            return if (pcu.version >= 5) {
                val res = RangeLists.parseDwarf5(bundle, rangesAttr.v, false, pcu.addressSize, addrBase)
                res.note?.let { notes.add(it) }
                res.ranges
            } else {
                runCatching { RangeLists.parseDwarf4(bundle, rangesAttr.v, pcu.addressSize, lowPc) }
                    .getOrElse { notes.add("CU .debug_ranges parse failed: ${it.message}"); emptyList() }
            }
        }
        val highPc = root.attr(DW.AT_HIGH_PC)
        return dieOwnRanges(root, lowPc, highPc, pcu.version, bundle, pcu, addrBase, notes)
    }

    private fun dieOwnRanges(
        die: DieNode,
        lowPc: Long?,
        highPc: AttrValue?,
        version: Int,
        bundle: DebugBundle,
        pcu: ParsedCu,
        addrBase: Long,
        notes: MutableList<String>
    ): List<RangeEntry> {
        if (lowPc != null) {
            return when (highPc) {
                is AttrValue.Address -> {
                    if (highPc.v == 0L) listOf(RangeEntry(lowPc, lowPc))
                    else listOf(RangeEntry(lowPc, highPc.v))
                }
                is AttrValue.Constant -> listOf(RangeEntry(lowPc, lowPc + highPc.v))
                else -> listOf(RangeEntry(lowPc, lowPc))
            }
        }
        val ra = die.attr(DW.AT_RANGES)
        if (ra is AttrValue.Constant) {
            return if (version >= 5) {
                RangeLists.parseDwarf5(bundle, ra.v, false, pcu.addressSize, addrBase).ranges
            } else {
                runCatching { RangeLists.parseDwarf4(bundle, ra.v, pcu.addressSize, 0L) }
                    .getOrElse { notes.add("ranges parse failed at DIE 0x${die.offset.toString(16)}: ${it.message}"); emptyList() }
            }
        }
        if (ra is AttrValue.Indexed) {
            notes.add("DW_FORM_rnglistx not supported for non-CU DIE at 0x${die.offset.toString(16)}")
        }
        return emptyList()
    }

    private fun collectScopes(
        die: DieNode,
        cuOffset: Int,
        depth: Int,
        out: MutableList<Scope>,
        cuRanges: List<RangeEntry>,
        bundle: DebugBundle,
        pcu: ParsedCu,
        cuLowPc: Long,
        addrBase: Long,
        fromSplit: Boolean,
        notes: MutableList<String>,
        originName: String? = null,
        originCall: Pair<String?, Int?>? = null
    ) {
        val interesting = die.tag == DW.TAG_SUBPROGRAM || die.tag == DW.TAG_INLINED_SUBROUTINE
        if (interesting) {
            val lowPc = (die.attr(DW.AT_LOW_PC) as? AttrValue.Address)?.v
            val highPc = die.attr(DW.AT_HIGH_PC)
            val rAttr = die.attr(DW.AT_RANGES)
            val ranges = when {
                rAttr is AttrValue.Constant -> if (pcu.version >= 5)
                    RangeLists.parseDwarf5(bundle, rAttr.v, fromSplit, pcu.addressSize, addrBase).ranges
                else runCatching { RangeLists.parseDwarf4(bundle, rAttr.v, pcu.addressSize, lowPc ?: cuLowPc) }
                    .getOrElse { emptyList() }
                lowPc != null -> dieOwnRanges(die, lowPc, highPc, pcu.version, bundle, pcu, addrBase, notes)
                else -> emptyList()
            }
            val abstract = lowPc == null && rAttr == null
            val inline = (die.attr(DW.AT_INLINE) as? AttrValue.Constant)?.v
            val callFile = (die.attr(DW.AT_CALL_FILE) as? AttrValue.Constant)?.v?.toInt()
            val callLine = (die.attr(DW.AT_CALL_LINE) as? AttrValue.Constant)?.v?.toInt()
            val name = die.name() ?: originName ?: "?:"
            out.add(Scope(
                name = name,
                cuOffset = cuOffset,
                dieOffset = die.offset,
                tag = die.tag,
                ranges = ranges,
                inlineDepth = if (die.tag == DW.TAG_INLINED_SUBROUTINE) depth else 0,
                callFile = originCall?.first,
                callLine = callLine ?: originCall?.second,
                abstract = abstract,
                concreteOriginOffset = null
            ))
        }
        die.children.forEach { child ->
            collectScopes(child, cuOffset, depth + 1, out, cuRanges, bundle, pcu, cuLowPc, addrBase,
                fromSplit, notes, die.name(), null)
        }
    }
}
