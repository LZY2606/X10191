package compass.storage

import compass.model.AddrRange
import compass.resolve.ModuleSnapshot
import java.sql.Connection
import java.sql.DriverManager
import java.time.Instant

data class DebugVersion(
    val id: Long,
    val originalFilename: String,
    val sha256: String,
    val buildId: String?,
    val elfClass: String,
    val machine: Int,
    val importedAt: String,
    val fileBlob: ByteArray,
)

data class CrashRecord(
    val id: Long,
    val label: String,
    val createdAt: String,
    val snapshotId: Long,
    val addressesJson: String,
    val resultJson: String,
    val versionFingerprint: String,
)

class Database(private val path: String) {
    private val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path").apply {
        createStatement().execute("PRAGMA foreign_keys = ON")
    }

    init { migrate() }

    private fun migrate() {
        conn.createStatement().use { st ->
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS debug_versions (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  original_filename TEXT NOT NULL,
                  sha256 TEXT NOT NULL UNIQUE,
                  build_id TEXT,
                  elf_class TEXT NOT NULL,
                  machine INTEGER NOT NULL,
                  imported_at TEXT NOT NULL,
                  file_blob BLOB NOT NULL,
                  is_split INTEGER NOT NULL DEFAULT 0,
                  dwo_id TEXT
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS sections (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  version_id INTEGER NOT NULL REFERENCES debug_versions(id),
                  name TEXT NOT NULL,
                  addr INTEGER NOT NULL,
                  file_offset INTEGER NOT NULL,
                  size INTEGER NOT NULL,
                  sha256 TEXT
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS load_segments (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  version_id INTEGER NOT NULL REFERENCES debug_versions(id),
                  flags INTEGER NOT NULL,
                  file_offset INTEGER NOT NULL,
                  vaddr INTEGER NOT NULL,
                  memsz INTEGER NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  version_id INTEGER NOT NULL REFERENCES debug_versions(id),
                  label TEXT NOT NULL,
                  load_base INTEGER NOT NULL,
                  first_segment_vaddr INTEGER NOT NULL,
                  generation INTEGER NOT NULL,
                  frozen_at TEXT NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS crashes (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  label TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  snapshot_id INTEGER REFERENCES snapshots(id),
                  addresses_json TEXT NOT NULL,
                  result_json TEXT NOT NULL,
                  version_fingerprint TEXT NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS parse_issues (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  version_id INTEGER NOT NULL REFERENCES debug_versions(id),
                  severity TEXT NOT NULL,
                  code TEXT NOT NULL,
                  message TEXT NOT NULL,
                  section TEXT,
                  offset INTEGER
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS summary_ranges (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  version_id INTEGER NOT NULL REFERENCES debug_versions(id),
                  cu_name TEXT,
                  kind TEXT NOT NULL,
                  name TEXT,
                  selector INTEGER NOT NULL,
                  start_addr INTEGER NOT NULL,
                  end_addr INTEGER NOT NULL,
                  inline_depth INTEGER NOT NULL DEFAULT 0
                )
                """.trimIndent()
            )
        }
    }

    fun insertVersion(
        filename: String, sha256: String, buildId: String?, elfClass: String, machine: Int,
        fileBlob: ByteArray, isSplit: Boolean, dwoId: String?,
    ): Long {
        val existing = conn.prepareStatement("SELECT id FROM debug_versions WHERE sha256 = ?").use {
            it.setString(1, sha256); it.executeQuery().use { q -> if (q.next()) q.getLong(1) else null }
        }
        if (existing != null) return existing
        return conn.prepareStatement(
            """INSERT INTO debug_versions(original_filename, sha256, build_id, elf_class, machine, imported_at, file_blob, is_split, dwo_id)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            java.sql.Statement.RETURN_GENERATED_KEYS,
        ).use {
            it.setString(1, filename); it.setString(2, sha256); it.setString(3, buildId)
            it.setString(4, elfClass); it.setInt(5, machine); it.setString(6, Instant.now().toString())
            it.setBytes(7, fileBlob); it.setInt(8, if (isSplit) 1 else 0); it.setString(9, dwoId)
            it.executeUpdate()
            it.generatedKeys.use { k -> if (k.next()) k.getLong(1) else error("no version id") }
        }
    }

    fun insertSection(versionId: Long, name: String, addr: Long, offset: Long, size: Long, sha: String?) {
        conn.prepareStatement("INSERT INTO sections(version_id,name,addr,file_offset,size,sha256) VALUES(?,?,?,?,?,?)").use {
            it.setLong(1, versionId); it.setString(2, name); it.setLong(3, addr)
            it.setLong(4, offset); it.setLong(5, size); it.setString(6, sha)
            it.executeUpdate()
        }
    }

    fun sectionsExist(versionId: Long): Boolean =
        conn.prepareStatement("SELECT 1 FROM sections WHERE version_id=? LIMIT 1").use {
            it.setLong(1, versionId)
            it.executeQuery().use { q -> q.next() }
        }

    fun insertSegment(versionId: Long, flags: Int, offset: Long, vaddr: Long, memsz: Long) {
        conn.prepareStatement("INSERT INTO load_segments(version_id,flags,file_offset,vaddr,memsz) VALUES(?,?,?,?,?)").use {
            it.setLong(1, versionId); it.setInt(2, flags); it.setLong(3, offset)
            it.setLong(4, vaddr); it.setLong(5, memsz); it.executeUpdate()
        }
    }

    fun insertIssue(versionId: Long, severity: String, code: String, message: String, section: String?, offset: Long?) {
        conn.prepareStatement("INSERT INTO parse_issues(version_id,severity,code,message,section,offset) VALUES(?,?,?,?,?,?)").use {
            it.setLong(1, versionId); it.setString(2, severity); it.setString(3, code)
            it.setString(4, message); it.setString(5, section); if (offset == null) it.setNull(6, -5) else it.setLong(6, offset)
            it.executeUpdate()
        }
    }

    fun insertSummaryRange(versionId: Long, cuName: String?, kind: String, name: String?, r: AddrRange, depth: Int) {
        conn.prepareStatement("INSERT INTO summary_ranges(version_id,cu_name,kind,name,selector,start_addr,end_addr,inline_depth) VALUES(?,?,?,?,?,?,?,?)").use {
            it.setLong(1, versionId); it.setString(2, cuName); it.setString(3, kind); it.setString(4, name)
            it.setLong(5, r.selector); it.setLong(6, r.start); it.setLong(7, r.end); it.setInt(8, depth)
            it.executeUpdate()
        }
    }

    fun listVersions(): List<DebugVersion> {
        val out = ArrayList<DebugVersion>()
        conn.createStatement().executeQuery(
            """SELECT id, original_filename, sha256, build_id, elf_class, machine, imported_at, file_blob
               FROM debug_versions ORDER BY id ASC"""
        ).use { q ->
            while (q.next()) {
                out += DebugVersion(
                    q.getLong(1), q.getString(2), q.getString(3), q.getString(4),
                    q.getString(5), q.getInt(6), q.getString(7), q.getBytes(8),
                )
            }
        }
        return out
    }

    fun getVersion(id: Long): DebugVersion? = listVersions().firstOrNull { it.id == id }

    fun addSnapshot(versionId: Long, label: String, loadBase: Long, firstVaddr: Long, generation: Int): Long {
        return conn.prepareStatement(
            "INSERT INTO snapshots(version_id,label,load_base,first_segment_vaddr,generation,frozen_at) VALUES(?,?,?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS,
        ).use {
            it.setLong(1, versionId); it.setString(2, label); it.setLong(3, loadBase)
            it.setLong(4, firstVaddr); it.setInt(5, generation); it.setString(6, Instant.now().toString())
            it.executeUpdate(); it.generatedKeys.use { k -> if (k.next()) k.getLong(1) else error("snapshot id") }
        }
    }

    fun listSnapshots(versionId: Long): List<ModuleSnapshot> {
        val out = ArrayList<ModuleSnapshot>()
        conn.prepareStatement(
            "SELECT id, version_id, label, load_base, first_segment_vaddr, frozen_at, generation FROM snapshots WHERE version_id=? ORDER BY generation ASC, id ASC"
        ).use {
            it.setLong(1, versionId)
            it.executeQuery().use { q ->
                while (q.next()) {
                    out += ModuleSnapshot(
                        q.getLong(1), q.getLong(2), q.getString(3), q.getLong(4), q.getLong(5),
                        q.getString(6), q.getInt(7),
                    )
                }
            }
        }
        return out
    }

    fun insertCrash(label: String, snapshotId: Long?, addressesJson: String, resultJson: String, fingerprint: String): Long {
        return conn.prepareStatement(
            "INSERT INTO crashes(label,created_at,snapshot_id,addresses_json,result_json,version_fingerprint) VALUES(?,?,?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS,
        ).use {
            it.setString(1, label); it.setString(2, Instant.now().toString())
            if (snapshotId == null) it.setNull(3, -5) else it.setLong(3, snapshotId)
            it.setString(4, addressesJson); it.setString(5, resultJson); it.setString(6, fingerprint)
            it.executeUpdate(); it.generatedKeys.use { k -> if (k.next()) k.getLong(1) else error("crash id") }
        }
    }

    fun listCrashes(): List<CrashRecord> {
        val out = ArrayList<CrashRecord>()
        conn.createStatement().executeQuery(
            "SELECT id,label,created_at,snapshot_id,addresses_json,result_json,version_fingerprint FROM crashes ORDER BY id DESC"
        ).use { q ->
            while (q.next()) {
                val snap = q.getObject(4)
                out += CrashRecord(
                    q.getLong(1), q.getString(2), q.getString(3),
                    if (snap == null) 0L else q.getLong(4),
                    q.getString(5), q.getString(6), q.getString(7),
                )
            }
        }
        return out
    }

    fun close() = conn.close()
}
