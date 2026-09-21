@file:Suppress("ArrayInDataClass")
package compass.storage

import compass.dwarf.DebugBundle
import compass.resolve.AddressResolver
import compass.resolve.LoadEntry
import compass.resolve.LoadedModule
import compass.resolve.ResolveResult
import compass.resolve.Snapshot
import compass.util.U64
import kotlinx.serialization.json.Json
import java.sql.ResultSet

data class ModuleVersionRecord(
    val moduleId: Long,
    val versionId: Long,
    val version: Int,
    val fileName: String,
    val buildId: String?,
    val contentSha256: String
)

data class SnapshotEntryRecord(
    val entryId: Long,
    val moduleVersionId: Long,
    val loadBias: U64,
    val baseAddress: U64,
    val generation: Int
)

data class CrashRecord(
    val id: Long,
    val label: String,
    val snapshotId: Long?,
    val createdAt: Long,
    val frames: List<CrashFrame>
)

data class CrashFrame(val ord: Int, val address: String, val result: ResolveResult?)

class Repository(private val db: Database) {
    private val json = Json {
        prettyPrint = false
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    private val resolver = AddressResolver()

    // -------- modules / versions --------

    fun importModule(fileName: String, bundle: DebugBundle, rawSections: Map<String, ByteArray>): ModuleVersionRecord {
        val now = System.currentTimeMillis()
        val moduleId: Long
        db.conn.prepareStatement(
            "INSERT INTO modules(file_name, build_id, content_sha256, created_at) VALUES(?,?,?,?) " +
                "ON CONFLICT(content_sha256) DO UPDATE SET file_name=excluded.file_name RETURNING id"
        ).use { ps ->
            ps.setString(1, fileName)
            ps.setString(2, bundle.buildId)
            ps.setString(3, bundle.contentSha256)
            ps.setLong(4, now)
            ps.executeQuery().use { rs ->
                rs.next(); moduleId = rs.getLong(1)
            }
        }
        val nextVersion: Int
        db.conn.prepareStatement("SELECT COALESCE(MAX(version),0)+1 FROM module_versions WHERE module_id=?").use { ps ->
            ps.setLong(1, moduleId)
            ps.executeQuery().use { rs -> rs.next(); nextVersion = rs.getInt(1) }
        }
        val versionId: Long
        db.conn.prepareStatement(
            "INSERT INTO module_versions(module_id, version, bundle_json, imported_at) VALUES(?,?,?,?) RETURNING id"
        ).use { ps ->
            ps.setLong(1, moduleId)
            ps.setInt(2, nextVersion)
            ps.setString(3, json.encodeToString(DebugBundle.serializer(), bundle))
            ps.setLong(4, now)
            ps.executeQuery().use { rs -> rs.next(); versionId = rs.getLong(1) }
        }
        db.conn.prepareStatement(
            "INSERT INTO module_sections(module_version_id, name, bytes) VALUES(?,?,?)"
        ).use { ps ->
            for ((name, bytes) in rawSections.toSortedMap()) {
                ps.setLong(1, versionId)
                ps.setString(2, name)
                ps.setBytes(3, bytes)
                ps.addBatch()
            }
            ps.executeBatch()
        }
        return ModuleVersionRecord(moduleId, versionId, nextVersion, fileName, bundle.buildId, bundle.contentSha256)
    }

    fun listModuleVersions(): List<ModuleVersionRecord> {
        val out = ArrayList<ModuleVersionRecord>()
        db.conn.prepareStatement(
            """SELECT mv.id, mv.module_id, mv.version, m.file_name, m.build_id, m.content_sha256, mv.imported_at
               FROM module_versions mv JOIN modules m ON m.id = mv.module_id
               ORDER BY mv.module_id, mv.version"""
        ).use { ps ->
            ps.executeQuery().use { rs ->
                while (rs.next()) {
                    out += ModuleVersionRecord(
                        rs.getLong(2), rs.getLong(1), rs.getInt(3),
                        rs.getString(4), rs.getString(5), rs.getString(6)
                    )
                }
            }
        }
        return out
    }

    private val bundleCache = HashMap<Long, DebugBundle>()
    private val moduleNameCache = HashMap<Long, String>()

    @Synchronized
    fun loadBundle(versionId: Long): DebugBundle {
        return bundleCache.getOrPut(versionId) {
            db.conn.prepareStatement("SELECT bundle_json FROM module_versions WHERE id=?").use { ps ->
                ps.setLong(1, versionId)
                ps.executeQuery().use { rs ->
                    if (!rs.next()) error("module version $versionId not found")
                    json.decodeFromString(DebugBundle.serializer(), rs.getString(1))
                }
            }
        }
    }

    fun moduleName(moduleId: Long): String {
        return moduleNameCache.getOrPut(moduleId) {
            db.conn.prepareStatement("SELECT file_name FROM modules WHERE id=?").use { ps ->
                ps.setLong(1, moduleId)
                ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else "module#$moduleId" }
            }
        }
    }

    fun moduleIdOfVersion(versionId: Long): Long {
        db.conn.prepareStatement("SELECT module_id FROM module_versions WHERE id=?").use { ps ->
            ps.setLong(1, versionId)
            ps.executeQuery().use { rs ->
                rs.next(); return rs.getLong(1)
            }
        }
    }

    fun rawSection(versionId: Long, name: String): ByteArray? {
        db.conn.prepareStatement(
            "SELECT bytes FROM module_sections WHERE module_version_id=? AND name=?"
        ).use { ps ->
            ps.setLong(1, versionId); ps.setString(2, name)
            ps.executeQuery().use { rs -> return if (rs.next()) rs.getBytes(1) else null }
        }
    }

    // -------- snapshots --------

    fun createSnapshot(name: String): Long {
        db.conn.prepareStatement("INSERT INTO snapshots(name, created_at) VALUES(?,?) RETURNING id").use { ps ->
            ps.setString(1, name); ps.setLong(2, System.currentTimeMillis())
            ps.executeQuery().use { rs -> rs.next(); return rs.getLong(1) }
        }
    }

    fun addSnapshotEntry(snapshotId: Long, moduleVersionId: Long, loadBias: U64, baseAddress: U64, generation: Int): Long {
        db.conn.prepareStatement(
            """INSERT INTO snapshot_entries(snapshot_id, module_version_id, load_bias, base_address, generation)
               VALUES(?,?,?,?,?) RETURNING id"""
        ).use { ps ->
            ps.setLong(1, snapshotId); ps.setLong(2, moduleVersionId)
            ps.setString(3, loadBias.toString()); ps.setString(4, baseAddress.toString())
            ps.setInt(5, generation)
            ps.executeQuery().use { rs -> rs.next(); return rs.getLong(1) }
        }
    }

    fun nextGeneration(snapshotId: Long, moduleVersionId: Long): Int {
        db.conn.prepareStatement(
            "SELECT COALESCE(MAX(generation),0)+1 FROM snapshot_entries WHERE snapshot_id=? AND module_version_id=?"
        ).use { ps ->
            ps.setLong(1, snapshotId); ps.setLong(2, moduleVersionId)
            ps.executeQuery().use { rs -> rs.next(); return rs.getInt(1) }
        }
    }

    @Synchronized
    fun loadSnapshot(snapshotId: Long): Snapshot {
        var name = "snapshot#$snapshotId"
        db.conn.prepareStatement("SELECT name FROM snapshots WHERE id=?").use { ps ->
            ps.setLong(1, snapshotId)
            ps.executeQuery().use { rs -> if (rs.next()) name = rs.getString(1) }
        }
        val entries = ArrayList<LoadEntry>()
        db.conn.prepareStatement(
            "SELECT module_version_id, load_bias, base_address, generation FROM snapshot_entries WHERE snapshot_id=? ORDER BY id"
        ).use { ps ->
            ps.setLong(1, snapshotId)
            ps.executeQuery().use { rs ->
                while (rs.next()) {
                    val versionId = rs.getLong(1)
                    val moduleId = moduleIdOfVersion(versionId)
                    val bundle = loadBundle(versionId)
                    val mod = LoadedModule(moduleId, moduleName(moduleId), bundle)
                    entries += LoadEntry(mod, U64.parse(rs.getString(2)), U64.parse(rs.getString(3)), rs.getInt(4))
                }
            }
        }
        return Snapshot(snapshotId, name, entries)
    }

    fun listSnapshots(): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        db.conn.prepareStatement(
            """SELECT s.id, s.name, s.created_at,
                      (SELECT COUNT(*) FROM snapshot_entries e WHERE e.snapshot_id=s.id) AS n
               FROM snapshots s ORDER BY s.id"""
        ).use { ps ->
            ps.executeQuery().use { rs ->
                while (rs.next()) {
                    out += mapOf("id" to rs.getLong(1), "name" to rs.getString(2),
                        "createdAt" to rs.getLong(3), "entries" to rs.getInt(4))
                }
            }
        }
        return out
    }

    // -------- resolution --------

    @Synchronized
    fun resolve(snapshotId: Long, addresses: List<String>, segment: Int = 0): List<ResolveResult> {
        val snap = loadSnapshot(snapshotId)
        return resolver.resolveBatch(snap, addresses, segment)
    }

    // -------- crashes (immutable records) --------

    fun createCrash(label: String, snapshotId: Long?, addresses: List<String>, segment: Int = 0): CrashRecord {
        val now = System.currentTimeMillis()
        val results = if (snapshotId != null) resolve(snapshotId, addresses, segment) else emptyList()
        val crashId: Long
        db.conn.prepareStatement(
            "INSERT INTO crashes(label, snapshot_id, created_at) VALUES(?,?,?) RETURNING id"
        ).use { ps ->
            ps.setString(1, label); if (snapshotId == null) ps.setNull(2, java.sql.Types.INTEGER) else ps.setLong(2, snapshotId)
            ps.setLong(3, now)
            ps.executeQuery().use { rs -> rs.next(); crashId = rs.getLong(1) }
        }
        db.conn.prepareStatement(
            "INSERT INTO crash_frames(crash_id, ord, address, result_json) VALUES(?,?,?,?)"
        ).use { ps ->
            addresses.forEachIndexed { i, addr ->
                ps.setLong(1, crashId); ps.setInt(2, i); ps.setString(3, addr)
                ps.setString(4, results.getOrNull(i)?.let { json.encodeToString(ResolveResult.serializer(), it) })
                ps.addBatch()
            }
            ps.executeBatch()
        }
        return CrashRecord(crashId, label, snapshotId, now,
            addresses.mapIndexed { i, a -> CrashFrame(i, a, results.getOrNull(i)) })
    }

    fun listCrashes(): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        db.conn.prepareStatement("SELECT id, label, snapshot_id, created_at FROM crashes ORDER BY id").use { ps ->
            ps.executeQuery().use { rs ->
                while (rs.next()) {
                    out += mapOf(
                        "id" to rs.getLong(1), "label" to rs.getString(2),
                        "snapshotId" to (rs.getObject(3) as? Number)?.toLong(),
                        "createdAt" to rs.getLong(4)
                    )
                }
            }
        }
        return out
    }

    fun getCrash(id: Long): CrashRecord? {
        var label = ""
        var snapshotId: Long? = null
        var createdAt = 0L
        db.conn.prepareStatement("SELECT label, snapshot_id, created_at FROM crashes WHERE id=?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                if (!rs.next()) return null
                label = rs.getString(1)
                snapshotId = (rs.getObject(2) as? Number)?.toLong()
                createdAt = rs.getLong(3)
            }
        }
        val frames = ArrayList<CrashFrame>()
        db.conn.prepareStatement(
            "SELECT ord, address, result_json FROM crash_frames WHERE crash_id=? ORDER BY ord"
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                while (rs.next()) {
                    val j = rs.getString(3)
                    frames += CrashFrame(rs.getInt(1), rs.getString(2),
                        j?.let { json.decodeFromString(ResolveResult.serializer(), it) })
                }
            }
        }
        return CrashRecord(id, label, snapshotId, createdAt, frames)
    }
}
