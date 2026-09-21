package compass.resolve

import compass.dwarf.*

/**
 * Extracts address-bearing scopes from every CU, resolving high_pc (both
 * constant-offset and absolute-address forms), DW_AT_ranges (v4/v5) and
 * following specification / abstract_origin links for inline subroutines.
 */
class ScopeExtractor(
    val dwarf: ParsedDwarf,
    private val cu: CompUnit,
) {
    private val warnings = ArrayList<String>()

    fun extract(): List<ScopeEntry> {
        val out = ArrayList<ScopeEntry>()
        walk(cu.root, 0, out)
        return out
    }

    fun entryForDie(die: Die): ScopeEntry? = extract().firstOrNull { it.die.offset == die.offset }

    private fun walk(die: Die, depth: Int, out: MutableList<ScopeEntry>) {
        if (isScope(die.tag)) {
            val ranges = resolveRanges(die)
            if (ranges.isNotEmpty() || hasExplicitRangeAttrs(die)) {
                val name = resolveName(die)
                val linkage = (die.attr(DW.AT_linkage_name) as? AttrValue.Str)?.value
                    ?: (die.attr(DW.AT_MIPS_linkage_name) as? AttrValue.Str)?.value
                val callLine = (die.attr(DW.AT_call_line) as? AttrValue.Num)?.value?.toInt()
                val callFile = resolveCallFile(die)
                out += ScopeEntry(
                    die = die,
                    name = name,
                    linkageName = linkage,
                    ranges = ranges,
                    depth = depth,
                    isInline = die.tag == DW.TAG_inlined_subroutine,
                    callFile = callFile,
                    callLine = callLine,
                    cuIndex = cu.index,
                )
            }
        }
        die.children.forEach { walk(it, depth + 1, out) }
    }

    private fun isScope(tag: Int) = tag == DW.TAG_subprogram ||
        tag == DW.TAG_inlined_subroutine || tag == DW.TAG_compile_unit

    private fun hasExplicitRangeAttrs(die: Die) = die.attr(DW.AT_low_pc) != null ||
        die.attr(DW.AT_ranges) != null

    /** Follow abstract_origin / specification chains with a hop limit. */
    private fun resolveName(start: Die): String? {
        var die: Die? = start
        var hops = 0
        while (die != null) {
            (die.attr(DW.AT_name) as? AttrValue.Str)?.value?.let { return it }
            (die.attr(DW.AT_linkage_name) as? AttrValue.Str)?.value?.let { return it }
            (die.attr(DW.AT_MIPS_linkage_name) as? AttrValue.Str)?.value?.let { return it }
            val ref = (die.attr(DW.AT_abstract_origin) ?: die.attr(DW.AT_specification)) as? AttrValue.Ref
            die = ref?.let { resolveRef(it.offset) }
            if (++hops > MAX_REF_HOPS) { warnings.add("abstract_origin 引用链过深"); return null }
        }
        return null
    }

    private fun resolveRef(globalOffset: Long): Die? {
        // DW_FORM_ref1..4 are CU-relative; the parser stores raw value here, so we
        // must distinguish. We instead normalise at decode time via a wrapper; here
        // the CU-relative forms are translated in [normalizeRefs]. After that all
        // refs are global .debug_info offsets.
        return cu.dies[globalOffset]
    }

    private fun resolveCallFile(die: Die): String? {
        val fileIdx = (die.attr(DW.AT_call_file) as? AttrValue.Num)?.value?.toInt() ?: return null
        val lp = cu.lineProgram ?: return null
        val f = lp.files.getOrNull(fileIdx - 1) ?: lp.files.getOrNull(fileIdx)
        return f?.fullPath ?: f?.name
    }

    private val rangeResolver = RangeListResolver(
        dwarf.sections, cu.addressSize, cu.is64Bit, warnings,
    ) { idx ->
        val base = cu.addrBase ?: 0L
        val table = chooseTable(base)
        table?.readAt(dwarf.sections.addr!!, base, idx)
            ?: run { warnings.add("addrx 索引 $idx 无法解析（base=$base）"); null }
    }

    private fun chooseTable(base: Long): AddrTable? {
        dwarf.addrTables[base]?.let { return it }
        return dwarf.addrTables.entries.filter { it.key <= base }.maxByOrNull { it.key }?.value
            ?: dwarf.addrTables[0L]
    }

    fun resolveRanges(die: Die): List<AddrRange> {
        val out = ArrayList<AddrRange>()
        val low = (die.attr(DW.AT_low_pc) as? AttrValue.Num)?.value
        val high = die.attr(DW.AT_high_pc)
        if (low != null && high != null) {
            val end = when (high) {
                is AttrValue.Num -> if (high.isAddress) high.value else low + high.value
                else -> null
            }
            if (end != null) out += AddrRange(low, end)
        } else if (low != null) {
            out += AddrRange(low, low) // zero-length: low only
        }
        val rangesAttr = die.attr(DW.AT_ranges)
        when (rangesAttr) {
            is AttrValue.SecOffset -> {
                val raw = rangesAttr.offset
                if (cu.version >= 5 && dwarf.sections.rnglists != null) {
                    out += rangeResolver.dwarf5Ranges(raw, useIndex = false, cu.rangesBase)
                } else {
                    out += rangeResolver.dwarf4Ranges(raw, low ?: 0L)
                }
            }
            is AttrValue.Num -> {
                if (cu.version >= 5 && dwarf.sections.rnglists != null) {
                    out += rangeResolver.dwarf5Ranges(rangesAttr.value, useIndex = false, cu.rangesBase)
                } else {
                    out += rangeResolver.dwarf4Ranges(rangesAttr.value, low ?: 0L)
                }
            }
            is AttrValue.RangeListIndex -> {
                out += rangeResolver.dwarf5Ranges(rangesAttr.index, useIndex = true, cu.rangesBase)
            }
            else -> {}
        }
        return out
    }

    val collectedWarnings: List<String> get() = warnings.distinct()

    companion object {
        const val MAX_REF_HOPS = 16
    }
}
