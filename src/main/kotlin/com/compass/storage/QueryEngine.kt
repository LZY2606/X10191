package com.compass.storage

import com.compass.dwarf.AddressExplanation
import com.compass.dwarf.AddressResolver
import com.compass.dwarf.DwarfRange
import com.compass.dwarf.QueryAddress
import com.compass.dwarf.DebugDocument

object QueryEngine {
    private val hex = Regex("(?:([0-9a-fA-F]+):)?(?:0[xX])?([0-9a-fA-F]{1,16})")

    fun batch(text: String, modules: List<SnapshotModule>, versions: Map<Long, StoredVersion>): List<AddressExplanation> {
        val addresses = parse(text)
        if (modules.isEmpty()) {
            val version = versions.values.minWithOrNull(compareBy<StoredVersion> { it.id })
            return addresses.map { AddressResolver.explain(version?.document ?: missingDocument(), it, null, null) }
        }
        return addresses.flatMap { address ->
            val moduleMatches = modules.mapNotNull { module ->
                val version = versions[module.versionId] ?: return@mapNotNull null
                val relative = toRelative(address, module, version.document)
                val query = address.copy(relative = relative)
                val explanation = AddressResolver.explain(version.document, query, module.loadBias, moduleLabel(module))
                if (explanation.matched) explanation else null
            }
            if (moduleMatches.isNotEmpty()) moduleMatches
            else modules.map { module ->
                val version = versions[module.versionId]
                val relative = toRelative(address, module, version?.document)
                AddressResolver.explain(version?.document ?: missingDocument(), address.copy(relative = relative), module.loadBias, moduleLabel(module))
            }
        }
    }

    fun parse(text: String): List<QueryAddress> = hex.findAll(text).map { match ->
        val segment = match.groupValues[1].takeIf { it.isNotEmpty() }?.toLong(16) ?: 0
        QueryAddress(segment, match.groupValues[2].toLong(16), match.groupValues[2].toLong(16))
    }.toList()

    private fun toRelative(input: QueryAddress, module: SnapshotModule, document: DebugDocument?): Long {
        val bounds = document?.let { coverage(it) }
        val candidate = input.runtime ?: input.relative
        val relative = candidate - module.loadBias
        return if (bounds == null || relative in bounds) relative else input.relative
    }

    private fun coverage(document: DebugDocument): LongRange {
        val ranges = document.compilationUnits.flatMap { cu ->
            cu.ranges.map { it.start..maxOf(it.end, it.start) } +
                (cu.lineProgram?.sequences?.map { it.startAddress..maxOf(it.endAddress, it.startAddress) } ?: emptyList())
        }
        return if (ranges.isEmpty()) LongRange(0, -1) else ranges.minOf { it.first }..ranges.maxOf { it.last }
    }

    private fun moduleLabel(module: SnapshotModule) =
        if (module.generation.isNullOrBlank()) module.name else "${module.name}#${module.generation}"

    private fun missingDocument() = DebugDocument(
        com.compass.dwarf.ElfSummary(0, true, 0, 0, 0), emptyList(),
        listOf("Module version referenced by fixed snapshot is absent")
    )
}
