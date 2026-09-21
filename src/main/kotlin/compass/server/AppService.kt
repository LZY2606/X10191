@file:Suppress("ArrayInDataClass")
package compass.server

import compass.dwarf.DebugBundle
import compass.dwarf.DebugBundleParser
import compass.dwarf.DebugInputs
import compass.elf.ElfParser
import compass.resolve.ResolveResult
import compass.storage.CrashRecord
import compass.storage.ModuleVersionRecord
import compass.storage.Repository
import compass.util.ParseException
import compass.util.U64
import org.slf4j.LoggerFactory

class ImportException(message: String) : RuntimeException(message)

data class ModuleDetail(
    val record: ModuleVersionRecord,
    val bundle: DebugBundle,
    val sectionNames: List<String>
)

class AppService(private val repo: Repository) {
    private val log = LoggerFactory.getLogger(AppService::class.java)

    fun importElf(fileName: String, bytes: ByteArray, companionBytes: List<ByteArray> = emptyList()): ModuleVersionRecord {
        val main = try {
            ElfParser.parse(bytes)
        } catch (e: ParseException) {
            throw ImportException("ELF parse failed for $fileName: ${e.message}")
        }
        val companions = companionBytes.mapIndexed { i, b ->
            try { ElfParser.parse(b) } catch (e: ParseException) {
                throw ImportException("companion debug file #$i parse failed: ${e.message}")
            }
        }
        val bundle = DebugBundleParser.parse(DebugInputs(main, companions))
        val rawSections = main.sectionBytes
        return repo.importModule(fileName, bundle, rawSections)
    }

    fun listModuleVersions() = repo.listModuleVersions()

    fun moduleDetail(versionId: Long): ModuleDetail {
        val bundle = repo.loadBundle(versionId)
        val record = repo.listModuleVersions().first { it.versionId == versionId }
        return ModuleDetail(record, bundle, bundle.sections.map { it.name })
    }

    fun rawSection(versionId: Long, name: String): ByteArray? = repo.rawSection(versionId, name)

    fun createSnapshot(name: String) = repo.createSnapshot(name)
    fun listSnapshots() = repo.listSnapshots()

    fun addEntry(snapshotId: Long, versionId: Long, loadBias: U64, baseAddress: U64?, generation: Int?): Map<String, Any?> {
        val bundle = repo.loadBundle(versionId)
        val preferred = baseAddress ?: preferredBase(bundle)
        val gen = generation ?: repo.nextGeneration(snapshotId, versionId)
        val id = repo.addSnapshotEntry(snapshotId, versionId, loadBias, preferred, gen)
        return mapOf(
            "entryId" to id, "snapshotId" to snapshotId, "moduleVersionId" to versionId,
            "loadBias" to loadBias.toString(), "baseAddress" to preferred.toString(),
            "generation" to gen
        )
    }

    private fun preferredBase(bundle: DebugBundle): U64 {
        val segs = bundle.elf.segments
        if (segs.isNotEmpty()) return segs.minBy { it.vaddr }.vaddr
        return bundle.elf.sections.filter { it.size.v != 0L && it.addr.v != 0L }
            .minByOrNull { it.addr }?.addr ?: U64.ZERO
    }

    fun resolve(snapshotId: Long, addresses: List<String>, segment: Int = 0): List<ResolveResult> =
        repo.resolve(snapshotId, addresses, segment)

    fun createCrash(label: String, snapshotId: Long?, addresses: List<String>, segment: Int = 0): CrashRecord =
        repo.createCrash(label, snapshotId, addresses, segment)

    fun listCrashes() = repo.listCrashes()
    fun getCrash(id: Long) = repo.getCrash(id)
}
