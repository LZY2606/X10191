package compass.resolve

import compass.dwarf.AddrRange
import compass.store.LoadSnapshot
import compass.store.LoadedModule
import compass.store.ModuleLoad
import compass.store.Repository

data class BatchAddressResult(
    val ordinal: Int,
    val inputAddress: Long,
    val moduleKey: String?,
    val moduleVersion: Int?,
    val relativeAddress: Long?,
    val loadBias: Long?,
    val generation: Int?,
    val explanation: QueryExplanation?,
    val error: String?,
)

/**
 * Cross-module resolver. A runtime address is converted to a section-relative
 * address using the pinned snapshot (load bias + generation). Every module the
 * relative address could belong to is queried; candidates from all modules are
 * merged deterministically (independent of import order).
 */
class Workspace(val repo: Repository) {

    private val engines = HashMap<Long, AddressEngine>()
    fun engineFor(module: LoadedModule): AddressEngine =
        engines.getOrPut(module.id) { AddressEngine(module) }

    /** Parse pasted stack text: hex (0x..), decimal, octal; one per line/whitespace. */
    fun parseAddresses(raw: String): List<Long> =
        raw.split(Regex("[\\s,;]+"))
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { token ->
                val t = token.lowercase().removePrefix("0x")
                if (token.lowercase().startsWith("0x") || token.lowercase().startsWith("0X")) {
                    java.lang.Long.parseUnsignedLong(token.substring(2), 16)
                } else {
                    java.lang.Long.decode(token)
                }
            }

    /**
     * Decide which loaded module a runtime address belongs to. A module is
     * considered when runtime - bias lands within one of its PT_LOAD spans or
     * within known debug ranges. Returns all plausible loads (overlap-safe).
     */
    fun candidateLoads(snapshot: LoadSnapshot, runtime: Long): List<Pair<ModuleLoad, Long>> {
        val out = ArrayList<Pair<ModuleLoad, Long>>()
        for (load in snapshot.loads) {
            val module = repo.moduleByKeyVersion(load.moduleKey, load.moduleVersion) ?: continue
            val relative = runtime - load.loadBias
            val inSegment = module.elf.segments.any { it.containsVaddr(relative) }
            val inDebugRange = module.dwarf.cus.any { cu ->
                val engine = engineFor(module)
                val scopes = engine.scopesFor(cu.index)
                scopes.any { se -> se.ranges.any { it.length > 0 && it.contains(relative) } } ||
                    cu.lineProgram?.sequences?.any { relative in it.startAddress until it.endAddress } == true
            }
            if (inSegment || inDebugRange) out += load to relative
        }
        return out
    }

    fun resolveRuntime(snapshot: LoadSnapshot, runtime: Long): List<AddressCandidate> {
        val all = ArrayList<AddressCandidate>()
        for ((load, relative) in candidateLoads(snapshot, runtime)) {
            val module = repo.moduleByKeyVersion(load.moduleKey, load.moduleVersion) ?: continue
            val engine = engineFor(module)
            val explanation = engine.resolveRelative(relative, load.loadBias, load.generation)
            all += explanation.candidates
        }
        return all.sortedWith(globalComparator)
    }

    fun resolveBatch(snapshot: LoadSnapshot, addresses: List<Long>): List<BatchAddressResult> =
        addresses.mapIndexed { index, runtime ->
            val loads = candidateLoads(snapshot, runtime)
            if (loads.isEmpty()) {
                BatchAddressResult(index, runtime, null, null, null, null, null, null,
                    "地址不属于快照中任何已加载模块")
            } else {
                val (load, relative) = loads.first()
                val module = repo.moduleByKeyVersion(load.moduleKey, load.moduleVersion)
                val explanation = module?.let { engineFor(it).resolveRelative(relative, load.loadBias, load.generation) }
                // merge other plausible modules' candidates too
                val merged = resolveRuntime(snapshot, runtime)
                val primary = explanation?.copy(candidates = merged)
                BatchAddressResult(index, runtime, load.moduleKey, load.moduleVersion,
                    relative, load.loadBias, load.generation, primary, null)
            }
        }

    companion object {
        /** Deterministic across import order: key on content-independent ids plus bias. */
        val globalComparator = compareByDescending<AddressCandidate> { it.priority }
            .thenBy { it.rangeLength }
            .thenByDescending { it.inlineDepth }
            .thenBy { it.moduleKey }
            .thenBy { it.moduleVersion }
            .thenBy { it.cuIndex }
            .thenBy { it.dieOffset }
    }
}
