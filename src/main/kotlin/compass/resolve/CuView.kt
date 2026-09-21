package compass.resolve

import compass.dwarf.AddrRange
import compass.dwarf.CompilationUnit
import compass.dwarf.DebugBundle
import compass.dwarf.Die
import compass.dwarf.DwTag

/**
 * Produces the effective CU list for address resolution:
 *  - normal full CUs pass through
 *  - a skeleton whose split companion is present is replaced by the split CU, with the
 *    skeleton's address ranges merged onto same-shape DIEs (by child index), so name,
 *    inline tree and line program come from the dwo while ranges come from the executable
 *  - a skeleton with missing dwo remains (ranges stay usable, line info simply absent)
 */
object CuView {

    data class EffectiveCu(val cu: CompilationUnit, val splitLinked: Boolean)

    fun effective(bundle: DebugBundle): List<EffectiveCu> {
        val splitByOffset = bundle.cus.filter { it.kind == "split" }.associateBy { it.offset }
        val out = ArrayList<EffectiveCu>()
        for (cu in bundle.cus) {
            when {
                cu.kind == "skeleton" -> {
                    val splitOff = bundle.splitLinks[cu.offset]
                    val split = splitOff?.let { splitByOffset[it] }
                    if (split != null) {
                        out += EffectiveCu(mergeRanges(split, cu), true)
                    } else {
                        out += EffectiveCu(cu, false)
                    }
                }
                cu.kind == "split" -> {
                    // only included via its skeleton
                    val hasSkeleton = bundle.cus.any { it.kind == "skeleton" && bundle.splitLinks[it.offset] == cu.offset }
                    if (!hasSkeleton) out += EffectiveCu(cu, false)
                }
                else -> out += EffectiveCu(cu, false)
            }
        }
        return out
    }

    private fun mergeRanges(split: CompilationUnit, skeleton: CompilationUnit): CompilationUnit {
        val skRangesByIdentity = HashMap<Int, List<AddrRange>>()
        val skScopeDies = skeleton.dies.filter { isScope(it) }
        val spScopeDies = split.dies.filter { isScope(it) }
        val mergedDies = split.dies.map { die -> die }
        val bySpIndex = spScopeDies.withIndex().associate { it.value.offset to it.index }
        // Pair scopes structurally: kth scope in skeleton corresponds to kth scope in split.
        val newDies = split.dies.toMutableList()
        for ((i, skDie) in skScopeDies.withIndex()) {
            val spDie = spScopeDies.getOrNull(i) ?: continue
            val idx = newDies.indexOfFirst { it.offset == spDie.offset }
            if (idx >= 0 && newDies[idx].ranges.isEmpty()) {
                newDies[idx] = newDies[idx].copy(
                    ranges = skDie.ranges,
                    callFile = newDies[idx].callFile,
                    callLine = newDies[idx].callLine ?: skDie.callLine
                )
            }
        }
        return split.copy(dies = newDies)
    }

    private fun isScope(d: Die) =
        d.tag == DwTag.SUBPROGRAM || d.tag == DwTag.INLINED_SUBROUTINE || d.tag == DwTag.LEXICAL_BLOCK
}
