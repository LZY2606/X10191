package addresscompass.dwarf

import addresscompass.model.AddrRange
import addresscompass.model.CompileUnit
import addresscompass.model.DIE
import addresscompass.model.FormValue
import addresscompass.model.ParseIssue
import addresscompass.model.Severity
import java.nio.ByteOrder

/**
 * Post-parse resolution over a fully parsed .debug_info image:
 *  - materialize DIE ranges (low/high pc in both forms and range lists)
 *  - build a global offset index so specification / abstract_origin chains resolve
 *  - follow those chains (with a hop cap) to recover effective names
 */
class DieResolver(
    private val sections: DebugSections,
    private val endian: ByteOrder,
    private val cus: List<CompileUnit>,
) {
    private val issues = mutableListOf<ParseIssue>()

    /** absolute (CU section offset + DIE relative offset) -> DIE */
    private val globalIndex = HashMap<Long, DIE>()

    fun takeIssues(): List<ParseIssue> { val c = ArrayList(issues); issues.clear(); return c }

    fun resolveAll() {
        for (cu in cus) {
            cu.indexDies()
            val root = cu.root ?: continue
            walk(root) { globalIndex[cu.sectionOffset + it.offset] = it }
            resolveRanges(cu, root)
        }
        for (cu in cus) {
            val root = cu.root ?: continue
            walk(root) { /* name chain resolved lazily */ }
        }
    }

    private inline fun walk(die: DIE, sink: (DIE) -> Unit) {
        sink(die); die.children.forEach { walk(it, sink) }
    }

    private fun resolveRanges(cu: CompileUnit, die: DIE) {
        die.ranges = rangesOf(cu, die)
        die.children.forEach { resolveRanges(cu, it) }
    }

    fun rangesOf(cu: CompileUnit, die: DIE): List<AddrRange> {
        val out = mutableListOf<AddrRange>()
        val lowPc = (die.attr(Dwarf.DW_AT_low_pc)?.value as? FormValue.AddrV)?.v
        val highAttr = die.attr(Dwarf.DW_AT_high_pc)?.value
        val selector = (die.attr(Dwarf.DW_AT_segment)?.value as? FormValue.Udata)?.v?.toInt() ?: 0
        if (lowPc != null) {
            when (highAttr) {
                is FormValue.AddrV -> out += AddrRange(selector, lowPc, highAttr.v)
                is FormValue.Udata -> out += AddrRange(selector, lowPc, lowPc + highAttr.v)
                is FormValue.Sdata -> out += AddrRange(selector, lowPc, lowPc + highAttr.v)
                null -> out += AddrRange(selector, lowPc, lowPc)
            }
        }
        val rangesAttr = die.attr(Dwarf.DW_AT_ranges)?.value
        when (rangesAttr) {
            is FormValue.SecOffset -> {
                val off = rangesAttr.v
                val cuBase = cu.lowPc ?: lowPc ?: 0L
                if (cu.version >= 5) {
                    out += RangeResolver.readV5(sections.rnglists, off, cu.addressSize,
                        cu.rnglistsBase ?: 0L, sections.addr, cu.version, endian, issues)
                } else {
                    out += RangeResolver.readV4(sections.ranges, off, cuBase, selector, endian, issues)
                }
            }
            is FormValue.Indexed -> {
                val off = resolveRnglistx(cu, rangesAttr.index)
                if (off != null) {
                    out += RangeResolver.readV5(sections.rnglists, off, cu.addressSize,
                        cu.addrBase ?: 0L, sections.addr, cu.version, endian, issues)
                } else {
                    issues += ParseIssue(Severity.WARNING, ".debug_rnglists", 0,
                        "DW_FORM_rnglistx index ${rangesAttr.index} unresolvable", true)
                }
            }
            else -> {}
        }
        return out
    }

    private fun resolveRnglistx(cu: CompileUnit, index: Long): Long? {
        val sec = sections.rnglists ?: return null
        val base = cu.rnglistsBase ?: return null
        return try {
            val r = ByteReader(sec, endian = endian)
            r.seek(base.toInt())
            r.u32(); r.u16(); r.u8(); r.u8()
            val offSize = r.u8(); val offCount = r.u32().toInt()
            if (index >= offCount) null else {
                r.seek(r.pos + (index * offSize).toInt())
                r.sizedInt(offSize)
            }
        } catch (e: RuntimeException) { null }
    }

    /** Resolve a reference form value from within [cu] (needed for ref1/2/4/8/udata CU-relative). */
    fun resolveRef(cu: CompileUnit, v: FormValue): DIE? = when (v) {
        is FormValue.SecOffset -> globalIndex[v.v]
        is FormValue.Udata -> cu.dieAtRelative(v.v)
        else -> null
    }

    fun effectiveName(cu: CompileUnit, die: DIE): String? {
        val seen = HashSet<Long>()
        fun go(d: DIE, baseCu: CompileUnit): String? {
            val key = baseCu.sectionOffset + d.offset
            if (!seen.add(key)) return null
            d.string()?.let { return it }
            val ref = d.attr(Dwarf.DW_AT_abstract_origin)?.value
                ?: d.attr(Dwarf.DW_AT_specification)?.value
                ?: return null
            val target = resolveRef(baseCu, ref) ?: return null
            // cross-CU absolute refs land in another CU; locate it by key
            val owner = ownerCuOf(baseCu.sectionOffset + target.offset) ?: baseCu
            return go(target, owner)
        }
        return go(die, cu)
    }

    fun declPosition(cu: CompileUnit, die: DIE): Pair<Long?, Long?>? {
        val seen = HashSet<Long>()
        fun go(d: DIE, baseCu: CompileUnit): Pair<Long?, Long?>? {
            val key = baseCu.sectionOffset + d.offset
            if (!seen.add(key)) return null
            val f = d.declFile(); val l = d.declLine()
            if (f != null || l != null) return f to l
            val ref = d.attr(Dwarf.DW_AT_abstract_origin)?.value
                ?: d.attr(Dwarf.DW_AT_specification)?.value
                ?: return null
            val target = resolveRef(baseCu, ref) ?: return null
            val owner = ownerCuOf(baseCu.sectionOffset + target.offset) ?: baseCu
            return go(target, owner)
        }
        return go(die, cu)
    }

    private fun ownerCuOf(absOffset: Long): CompileUnit? =
        cus.lastOrNull { absOffset >= it.sectionOffset && absOffset < it.sectionOffset + it.unitLength + 12 }

    fun issuesOf(): List<ParseIssue> = issues
}
