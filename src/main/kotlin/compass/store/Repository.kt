package compass.store

import compass.dwarf.DwarfParser
import compass.dwarf.ParsedDwarf
import compass.elf.ElfFile
import compass.elf.ElfParser
import java.nio.file.Files
import java.nio.file.Path
import java.sql.Connection
import java.sql.DriverManager
import java.time.Instant

/**
 * SQLite-backed repository. Debug files are stored on disk as immutable blobs;
 * importing the same module key again creates a NEW version and never mutates
 * existing crash records or snapshots.
 */
class Repository(private val dataDir: Path) {
    private val dbFile: Path = dataDir.resolve("compass.db")
    private val blobDir: Path = dataDir.resolve("blobs")
    private lateinit var conn: Connection

    val modules = LinkedHashMap<Long, LoadedModule>()

    fun init() {
        Files.createDirectories(blobDir)
        conn = DriverManager.getConnection("jdbc:sqlite:$dbFile")
        conn.createStatement().executeUpdate(
            """
            CREATE TABLE IF NOT EXISTS module_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              module_key TEXT NOT NULL,
              version INTEGER NOT NULL,
              file_name TEXT NOT NULL,
              sha256 TEXT NOT NULL,
              blob_path TEXT NOT NULL,
              imported_at TEXT NOT NULL,
              UNIQUE(module_key, version)
            );
            CREATE TABLE IF NOT EXISTS snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snapshot_loads (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              snapshot_id INTEGER NOT NULL,
              module_key TEXT NOT NULL,
              module_version INTEGER NOT NULL,
              load_bias INTEGER NOT NULL,
              generation INTEGER NOT NULL,
              label TEXT,
              FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
            );
            CREATE TABLE IF NOT EXISTS crash_batches (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              snapshot_id INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              raw_input TEXT NOT NULL,
              FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
            );
            CREATE TABLE IF NOT EXISTS crash_addresses (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              batch_id INTEGER NOT NULL,
              ordinal INTEGER NOT NULL,
              address INTEGER NOT NULL,
              FOREIGN KEY(batch_id) REFERENCES crash_batches(id)
            );
            """.trimIndent()
        )
        loadExisting()
    }

    private fun loadExisting() {
        val rs = conn.prepareStatement(
            "SELECT id, module_key, version, file_name, sha256, blob_path, imported_at FROM module_versions ORDER BY id"
        ).executeQuery()
        while (rs.next()) {
            val id = rs.getLong(1)
            val key = rs.getString(2)
            val version = rs.getInt(3)
            val fileName = rs.getString(4)
            val sha = rs.getString(5)
            val blobPath = Path.of(rs.getString(6))
            val bytes = Files.readAllBytes(blobPath)
            val elf = ElfParser.parse(bytes)
            val dwarf = DwarfParser.parse(elf)
            val superseded = isSuperseded(key, version)
            modules[id] = LoadedModule(id, key, version, fileName, sha, elf, dwarf, rs.getString(7), superseded)
        }
    }

    private fun isSuperseded(key: String, version: Int): Boolean {
        val q = conn.prepareStatement("SELECT MAX(version) FROM module_versions WHERE module_key = ?")
        q.setString(1, key)
        val rs = q.executeQuery()
        return rs.next() && rs.getInt(1) > version
    }

    fun importModule(key: String, fileName: String, bytes: ByteArray): LoadedModule {
        // reject exact duplicate (same key + same content)
        val sha = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        val dup = conn.prepareStatement("SELECT id FROM module_versions WHERE module_key = ? AND sha256 = ?")
        dup.setString(1, key); dup.setString(2, sha)
        val existing = dup.executeQuery()
        if (existing.next()) {
            return modules[existing.getLong(1)]!!
        }
        val versionQ = conn.prepareStatement("SELECT COALESCE(MAX(version),0)+1 FROM module_versions WHERE module_key = ?")
        versionQ.setString(1, key)
        val vrs = versionQ.executeQuery(); vrs.next()
        val version = vrs.getInt(1)
        val now = Instant.now().toString()
        val blobPath = blobDir.resolve("${key.replace(Regex("[^A-Za-z0-9_.-]"), "_")}-v$version-$sha.tmpbin")
        Files.write(blobPath, bytes)
        val ins = conn.prepareStatement(
            "INSERT INTO module_versions(module_key, version, file_name, sha256, blob_path, imported_at) VALUES(?,?,?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS,
        )
        ins.setString(1, key); ins.setInt(2, version); ins.setString(3, fileName)
        ins.setString(4, sha); ins.setString(5, blobPath.toString()); ins.setString(6, now)
        ins.executeUpdate()
        val gen = ins.generatedKeys
        gen.next()
        val id = gen.getLong(1)
        // mark older versions superseded in memory
        modules.replaceAll { _, m -> if (m.key == key) m.copy(superseded = true) else m }
        val elf = ElfParser.parse(bytes)
        val parsed = DwarfParser.parse(elf)
        val mod = LoadedModule(id, key, version, fileName, sha, elf, parsed, now, false)
        modules[id] = mod
        return mod
    }

    fun moduleByKeyVersion(key: String, version: Int?): LoadedModule? {
        val list = modules.values.filter { it.key == key }
        if (list.isEmpty()) return null
        if (version != null) return list.firstOrNull { it.version == version }
        return list.maxByOrNull { it.version }
    }

    fun createSnapshot(name: String, loads: List<ModuleLoad>): LoadSnapshot {
        val now = Instant.now().toString()
        val ins = conn.prepareStatement("INSERT INTO snapshots(name, created_at) VALUES(?,?)", java.sql.Statement.RETURN_GENERATED_KEYS)
        ins.setString(1, name); ins.setString(2, now); ins.executeUpdate()
        val k = ins.generatedKeys; k.next(); val id = k.getLong(1)
        for (l in loads) {
            val p = conn.prepareStatement(
                "INSERT INTO snapshot_loads(snapshot_id, module_key, module_version, load_bias, generation, label) VALUES(?,?,?,?,?,?)"
            )
            p.setLong(1, id); p.setString(2, l.moduleKey); p.setInt(3, l.moduleVersion)
            p.setLong(4, l.loadBias); p.setInt(5, l.generation); p.setString(6, l.label)
            p.executeUpdate()
        }
        return LoadSnapshot(id, name, now, loads)
    }

    fun listSnapshots(): List<LoadSnapshot> {
        val out = ArrayList<LoadSnapshot>()
        val rs = conn.createStatement().executeQuery("SELECT id, name, created_at FROM snapshots ORDER BY id")
        while (rs.next()) {
            val id = rs.getLong(1)
            out += LoadSnapshot(id, rs.getString(2), rs.getString(3), loadsOf(id))
        }
        return out
    }

    fun snapshot(id: Long): LoadSnapshot? = listSnapshots().firstOrNull { it.id == id }

    private fun loadsOf(snapshotId: Long): List<ModuleLoad> {
        val q = conn.prepareStatement(
            "SELECT module_key, module_version, load_bias, generation, label FROM snapshot_loads WHERE snapshot_id = ? ORDER BY id"
        )
        q.setLong(1, snapshotId)
        val rs = q.executeQuery()
        val out = ArrayList<ModuleLoad>()
        while (rs.next()) {
            out += ModuleLoad(rs.getString(1), rs.getInt(2), rs.getLong(3), rs.getInt(4), rs.getString(5))
        }
        return out
    }

    fun saveCrashBatch(name: String, snapshotId: Long, rawInput: String, addresses: List<Long>): CrashBatch {
        val now = Instant.now().toString()
        val ins = conn.prepareStatement("INSERT INTO crash_batches(name, snapshot_id, created_at, raw_input) VALUES(?,?,?,?)", java.sql.Statement.RETURN_GENERATED_KEYS)
        ins.setString(1, name); ins.setLong(2, snapshotId); ins.setString(3, now); ins.setString(4, rawInput)
        ins.executeUpdate()
        val k = ins.generatedKeys; k.next(); val id = k.getLong(1)
        addresses.forEachIndexed { idx, a ->
            val p = conn.prepareStatement("INSERT INTO crash_addresses(batch_id, ordinal, address) VALUES(?,?,?)")
            p.setLong(1, id); p.setInt(2, idx); p.setLong(3, a); p.executeUpdate()
        }
        return CrashBatch(id, name, snapshotId, now, rawInput, addresses)
    }

    fun listCrashBatches(): List<CrashBatch> {
        val out = ArrayList<CrashBatch>()
        val rs = conn.createStatement().executeQuery("SELECT id, name, snapshot_id, created_at, raw_input FROM crash_batches ORDER BY id")
        while (rs.next()) {
            val id = rs.getLong(1)
            out += CrashBatch(id, rs.getString(2), rs.getLong(3), rs.getString(4), rs.getString(5), addressesOf(id))
        }
        return out
    }

    private fun addressesOf(batchId: Long): List<Long> {
        val q = conn.prepareStatement("SELECT address FROM crash_addresses WHERE batch_id = ? ORDER BY ordinal")
        q.setLong(1, batchId)
        val rs = q.executeQuery()
        val out = ArrayList<Long>()
        while (rs.next()) out += rs.getLong(1)
        return out
    }

    fun close() = conn.close()
}
