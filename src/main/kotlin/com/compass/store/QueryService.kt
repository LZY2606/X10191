package com.compass.store

import com.compass.dwarf.*

/** One address resolution including how the relative address was derived. */
data class AddressResult(
    val runtimeAddress: String,
    val relativeAddress: String,
    val loadBias: String,
    val generation: Int?,
    val module: String?,
    val candidates: List<QueryEngine.Candidate>
)

/**
 * Address resolution orchestration.
 *
 * runtime_addr - bias = relative address. When a crash/load snapshot is
 * pinned, the bias of the selected generation is used; otherwise the caller
 * can supply an explicit bias. The same relative address can resolve against
 * multiple load generations; we return one result per applicable generation.
 */
class QueryService(private val repo: Repository) {

    fun resolve(versionId: Long, runtimeHex: String, crashId: Long? = null,
                generation: Int? = null, explicitBiasHex: String? = null): List<AddressResult> {
        val bundle = repo.bundle(versionId) ?: error("版本 $versionId 未就绪")
        val engine = QueryEngine(listOf(bundle.merged))
        val runtime = Repository.parseAddr(runtimeHex)

        val loads = if (crashId != null) repo.loads(crashId) else emptyList()
        val scenarios: List<Triple<Int?, String, Long>> = when {
            loads.isNotEmpty() -> {
                val selected = when {
                    generation != null -> loads.filter { it.generation == generation }
                    else -> loads
                }
                selected.map { Triple(it.generation, it.moduleName, it.bias) }
            }
            explicitBiasHex != null -> listOf(Triple(null, "explicit", Repository.parseAddr(explicitBiasHex)))
            else -> listOf(Triple(null, "unrelocated", 0L))
        }
        return scenarios.map { (gen, module, bias) ->
            val rel = runtime - bias
            val cands = engine.query(rel)
            val result = AddressResult(Repository.hex(runtime), Repository.hex(rel), Repository.hex(bias),
                gen, module, cands)
            repo.recordQuery(crashId, versionId, gen, runtime, rel, bias,
                QueryService.buildJsonObject0(result).toString())
            result
        }
    }

    fun resolveRelative(versionId: Long, relativeHex: String, crashId: Long? = null): AddressResult {
        val bundle = repo.bundle(versionId) ?: error("版本 $versionId 未就绪")
        val rel = Repository.parseAddr(relativeHex)
        val cands = QueryEngine(listOf(bundle.merged)).query(rel)
        val result = AddressResult(Repository.hex(rel), Repository.hex(rel), "0x0", null, "relative", cands)
        repo.recordQuery(crashId, versionId, null, null, rel, 0L,
            QueryService.buildJsonObject0(result).toString())
        return result
    }

    companion object {
        fun buildJsonObject0(r: AddressResult) = kotlinx.serialization.json.buildJsonObject {
            put("runtimeAddress", kotlinx.serialization.json.JsonPrimitive(r.runtimeAddress))
            put("relativeAddress", kotlinx.serialization.json.JsonPrimitive(r.relativeAddress))
            put("loadBias", kotlinx.serialization.json.JsonPrimitive(r.loadBias))
            put("generation", if (r.generation == null) kotlinx.serialization.json.JsonNull else kotlinx.serialization.json.JsonPrimitive(r.generation))
            put("module", if (r.module == null) kotlinx.serialization.json.JsonNull else kotlinx.serialization.json.JsonPrimitive(r.module))
            put("candidates", kotlinx.serialization.json.JsonArray(r.candidates.map { JsonCodec.candidate(it) }))
        }
    }
}
