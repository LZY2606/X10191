package compass.service

import compass.dwarf.*
import compass.elf.ElfFile
import compass.elf.ElfFormatException
import compass.query.AddressExplanation
import compass.query.AddressResolver
import compass.store.Database
import compass.store.Snapshot
import compass.store.StoredVersion
import compass.dwarf.ByteDigest
import compass.web.Explanations
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.util.concurrent.ConcurrentHashMap

class ImportException(message: String) : RuntimeException(message)

/**
 * Application service. Importing a debug file always creates a *new immutable*
 * version; prior crash/batch records keep pointing at the version that explained
 * them. Parsed modules are cached by version id and rebuilt from stored bytes on
 * startup, so resolution never depends on mutable global state.
 */
class CompassService(val db: Database) {
    private data class Cached(val elf: ElfFile, val data: DwarfData, val module: DebugModule)

    private val cache = ConcurrentHashMap<Long, Cached>()

    init {
        db.listVersions().forEach { v ->
            runCatching { load(v.id) }
        }
    }

    fun versions(): List<StoredVersion> = db.listVersions()

    fun importFile(label: String, fileName: String, bytes: ByteArray): Long {
        val elf = try {
            ElfFile.parse(bytes)
        } catch (e: ElfFormatException) {
            throw ImportException("not an ELF file: ${e.message}")
        }
        val data = DwarfData(elf)
        if (data.debugInfo == null && data.debugInfoDwo == null) {
            data.warnings += "file contains neither .debug_info nor .debug_info.dwo"
        }
        val module = DebugModule.load(data)
        val digest = ByteDigest.of(bytes)
        return db.insertVersion(label, fileName, bytes, digest, elf, module)
    }

    private fun load(versionId: Long): Cached {
        cache[versionId]?.let { return it }
        val bytes = db.versionRawBytes(versionId)
            ?: throw ImportException("version $versionId not found")
        val elf = ElfFile.parse(bytes)
        val data = DwarfData(elf)
        val module = DebugModule.load(data)
        val c = Cached(elf, data, module)
        cache[versionId] = c
        return c
    }

    fun module(versionId: Long): DebugModule = load(versionId).module
    fun data(versionId: Long): DwarfData = load(versionId).data
    fun elf(versionId: Long): ElfFile = load(versionId).elf

    fun snapshots(versionId: Long? = null): List<Snapshot> = db.listSnapshots(versionId)

    fun createSnapshot(versionId: Long, loadBias: ULong, moduleBase: ULong? = null, note: String = ""): Long {
        load(versionId)
        val generation = (db.listSnapshots(versionId).maxOfOrNull { it.generation } ?: 0) + 1
        return db.createSnapshot(versionId, generation, loadBias, moduleBase, note)
    }

    fun resolve(versionId: Long, address: ULong, loadBias: ULong, snapshotId: String? = null,
                generation: Int? = null, moduleName: String? = null): AddressExplanation {
        val cached = load(versionId)
        val resolver = AddressResolver(cached.module)
        return resolver.resolve(address, loadBias, snapshotId, generation, moduleName)
    }

    fun resolveWithSnapshot(snapshotId: Long, addresses: List<ULong>): List<AddressExplanation> {
        val snap = db.listSnapshots().firstOrNull { it.id == snapshotId }
            ?: throw ImportException("snapshot $snapshotId not found")
        val cached = load(snap.versionId)
        val resolver = AddressResolver(cached.module)
        return addresses.map { a ->
            resolver.resolve(a, snap.loadBias, snapshotId.toString(), snap.generation,
                moduleName = "v${snap.versionId}#gen${snap.generation}")
        }
    }

    fun saveBatch(snapshotId: Long, rawInput: String, results: List<AddressExplanation>): Long {
        val snap = db.listSnapshots().firstOrNull { it.id == snapshotId }
            ?: throw ImportException("snapshot $snapshotId not found")
        val json = Json.encodeToString(
            ListSerializer(Explanations.serializer()),
            results.map { Explanations.from(it) },
        )
        return db.saveBatch(snapshotId, snap.versionId, rawInput, json)
    }
}
