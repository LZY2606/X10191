package compass.web

import compass.db.Database
import compass.dwarf.*
import compass.elf.ElfFile
import compass.elf.ElfFormatException
import java.io.File

/**
 * Application facade: registry (query authority) + database (durable versions
 * and immutable snapshots). Re-importing a new debug file creates a new
 * version; existing crash/query rows are never rewritten.
 */
class AppService(val db: Database) {
    val registry = Registry()
    private val snapshots = LinkedHashMap<Long, SnapshotView>()
    private val versionCounter = java.util.concurrent.atomic.AtomicInteger(0)

    init { rehydrate() }

    private fun rehydrate() {
        for (stored in db.allImports()) {
            val elf = try {
                ElfFile.parse(stored.blob, stored.path)
            } catch (e: Exception) {
                System.err.println("skipping corrupt import ${stored.id}: ${e.message}")
                continue
            }
            val parsed = FileParser.parse(stored.id, elf)
            registry.adopt(parsed)
        }
        registry.relink()
        for ((id, label, mods) in db.loadSnapshots()) {
            snapshots[id] = SnapshotView(id, label, java.time.Instant.now().toString(), mods)
        }
    }

    data class ImportResult(
        val id: Long, val deduped: Boolean, val versionLabel: String, val sha256: String,
        val issues: List<ParseIssue>, val units: Int, val scopes: Int
    )

    fun importBytes(bytes: ByteArray, path: String?): ImportResult {
        val elf = ElfFile.parse(bytes, path)
        val label = "v${versionCounter.incrementAndGetGet()}-${elf.fileSha256.take(8)}"
        val isDwo = elf.dwarfSection(".debug_info.dwo") != null
        val existing = db.findImportBySha(elf.fileSha256)
        val (parsed, created) = registry.importElf(elf)
        if (existing == null) {
            db.insertImport(elf, path, label, isDwo, parsed.id)
            db.persistParsed(parsed)
        }
        return ImportResult(parsed.id, !created, label, elf.fileSha256,
            parsed.allIssues(), parsed.units.size, parsed.scopes.size)
    }

    fun importFile(file: File): ImportResult = importBytes(file.readBytes(), file.absolutePath)

    fun snapshot(label: String, modules: List<SnapshotModule>): SnapshotView {
        val id = db.createSnapshot(label, modules)
        val snap = SnapshotView(id, label, java.time.Instant.now().toString(), modules)
        snapshots[id] = snap
        return snap
    }

    fun snapshots(): List<SnapshotView> = snapshots.values.toList()
    fun snapshot(id: Long): SnapshotView? = snapshots[id]

    fun query(raw: String, snapshotId: Long?): QueryResult {
        val input = QueryEngine(registry).parseInput(raw)
        val snap = snapshotId?.let { snapshots[it] }
        val result = QueryEngine(registry).query(input, snap)
        db.insertQueryLog(snapshotId, raw, result, QueryJson.encode(result))
        return result
    }
}

private fun java.util.concurrent.atomic.AtomicInteger.incrementAndGetGet(): Int = incrementAndGet()
