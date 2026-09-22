package compass.db

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import java.time.Instant

data class VersionRow(
    val id: Long, val label: String, val mainFileName: String,
    val mainSha256: String, val createdAt: String, val dwoCount: Int,
)

data class SectionRow(val versionId: Long, val name: String, val type: Long, val flags: Long,
    val addr: Long, val offset: Long, val size: Long, val addralign: Long, val sha256: String)

data class SnapshotRow(val id: Long, val versionId: Long, val label: String, val createdAt: String, val payload: String)
data class ModuleRow(val snapshotId: Long, val moduleName: String, val runtimeBase: Long?, val fileBase: Long?, val note: String?)
data class CrashRow(val id: Long, val snapshotId: Long, val versionId: Long, val addressHex: String, val label: String, val createdAt: String)

class Database(private val path: Path) {
    private val conn: Connection

    init {
        Files.createDirectories(path.toAbsolutePath().parent)
        conn = DriverManager.getConnection("jdbc:sqlite:$path")
        conn.createStatement().execute("PRAGMA foreign_keys=ON")
        migrate()
    }

    private fun migrate() {
        conn.createStatement().use { st ->
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS debug_version (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label TEXT NOT NULL,
                    main_file_name TEXT NOT NULL,
                    main_sha256 TEXT NOT NULL,
                    main_bytes BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    dwo_count INTEGER NOT NULL DEFAULT 0
                )""".trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS dwo_file (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES debug_version(id),
                    file_name TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    bytes BLOB NOT NULL
                )""".trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS section_digest (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES debug_version(id),
                    name TEXT NOT NULL,
                    sh_type INTEGER NOT NULL,
                    flags INTEGER NOT NULL,
                    vaddr INTEGER NOT NULL,
                    file_off INTEGER NOT NULL,
                    size INTEGER NOT NULL,
                    addralign INTEGER NOT NULL,
                    sha256 TEXT NOT NULL
                )""".trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS load_snapshot (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES debug_version(id),
                    label TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    module_json TEXT NOT NULL
                )""".trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS crash_record (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL REFERENCES load_snapshot(id),
                    version_id INTEGER NOT NULL REFERENCES debug_version(id),
                    address_hex TEXT NOT NULL,
                    label TEXT,
                    created_at TEXT NOT NULL
                )""".trimIndent()
            )
        }
    }

    fun sha256(bytes: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(bytes)
        return d.joinToString("") { "%02x".format(it) }
    }

    fun createVersion(label: String, mainFileName: String, mainBytes: ByteArray, dwos: List<Pair<String, ByteArray>>): VersionRow {
        val hash = sha256(mainBytes)
        val now = Instant.now().toString()
        val vid: Long
        conn.prepareStatement(
            "INSERT INTO debug_version(label, main_file_name, main_sha256, main_bytes, created_at, dwo_count) VALUES(?,?,?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS
        ).use { ps ->
            ps.setString(1, label); ps.setString(2, mainFileName); ps.setString(3, hash)
            ps.setBytes(4, mainBytes); ps.setString(5, now); ps.setInt(6, dwos.size)
            ps.executeUpdate()
            ps.generatedKeys.use { if (it.next()) vid = it.getLong(1) else error("no id") }
        }
        conn.prepareStatement("INSERT INTO dwo_file(version_id,file_name,sha256,bytes) VALUES(?,?,?,?)").use { ps ->
            dwos.forEach { (name, bytes) ->
                ps.setLong(1, vid); ps.setString(2, name); ps.setString(3, sha256(bytes)); ps.setBytes(4, bytes)
                ps.addBatch()
            }
            if (dwos.isNotEmpty()) ps.executeBatch()
        }
        return VersionRow(vid, label, mainFileName, hash, now, dwos.size)
    }

    fun addSections(versionId: Long, sections: List<SectionRow>) {
        conn.prepareStatement("""INSERT INTO section_digest(version_id,name,sh_type,flags,vaddr,file_off,size,addralign,sha256)
            |VALUES(?,?,?,?,?,?,?,?,?)""".trimMargin()).use { ps ->
            sections.forEach { s ->
                ps.setLong(1, s.versionId); ps.setString(2, s.name); ps.setLong(3, s.type)
                ps.setLong(4, s.flags); ps.setLong(5, s.addr); ps.setLong(6, s.offset)
                ps.setLong(7, s.size); ps.setLong(8, s.addralign); ps.setString(9, s.sha256)
                ps.addBatch()
            }
            if (sections.isNotEmpty()) ps.executeBatch()
        }
    }

    fun listVersions(): List<VersionRow> {
        val out = mutableListOf<VersionRow>()
        conn.prepareStatement("SELECT id,label,main_file_name,main_sha256,created_at,dwo_count FROM debug_version ORDER BY id").use { ps ->
            ps.executeQuery().use { rs ->
                while (rs.next()) out.add(VersionRow(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getInt(6)))
            }
        }
        return out
    }

    fun loadVersionBytes(id: Long): Triple<ByteArray, List<Pair<String, ByteArray>>, VersionRow> {
        val main: ByteArray; var row: VersionRow
        conn.prepareStatement("SELECT label,main_file_name,main_sha256,main_bytes,created_at,dwo_count FROM debug_version WHERE id=?").use { ps ->
            ps.setLong(1, id); ps.executeQuery().use { rs ->
                if (!rs.next()) error("version $id not found")
                row = VersionRow(id, rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(5), rs.getInt(6))
                main = rs.getBytes(4)
            }
        }
        val dwos = mutableListOf<Pair<String, ByteArray>>()
        conn.prepareStatement("SELECT file_name,bytes FROM dwo_file WHERE version_id=? ORDER BY id").use { ps ->
            ps.setLong(1, id); ps.executeQuery().use { rs -> while (rs.next()) dwos.add(rs.getString(1) to rs.getBytes(2)) }
        }
        return Triple(main, dwos, row)
    }

    fun sections(versionId: Long): List<SectionRow> {
        val out = mutableListOf<SectionRow>()
        conn.prepareStatement("SELECT version_id,name,sh_type,flags,vaddr,file_off,size,addralign,sha256 FROM section_digest WHERE version_id=? ORDER BY file_off").use { ps ->
            ps.setLong(1, versionId); ps.executeQuery().use { rs ->
                while (rs.next()) out.add(SectionRow(rs.getLong(1), rs.getString(2), rs.getLong(3), rs.getLong(4),
                    rs.getLong(5), rs.getLong(6), rs.getLong(7), rs.getLong(8), rs.getString(9)))
            }
        }
        return out
    }

    fun createSnapshot(versionId: Long, label: String, moduleJson: String): SnapshotRow {
        val now = Instant.now().toString()
        val id: Long
        conn.prepareStatement("INSERT INTO load_snapshot(version_id,label,created_at,module_json) VALUES(?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS).use { ps ->
            ps.setLong(1, versionId); ps.setString(2, label); ps.setString(3, now); ps.setString(4, moduleJson)
            ps.executeUpdate(); ps.generatedKeys.use { if (it.next()) id = it.getLong(1) else error("no id") }
        }
        return SnapshotRow(id, versionId, label, now, moduleJson)
    }

    fun listSnapshots(): List<SnapshotRow> {
        val out = mutableListOf<SnapshotRow>()
        conn.createStatement().executeQuery("SELECT id,version_id,label,created_at,module_json FROM load_snapshot ORDER BY id").use { rs ->
            while (rs.next()) out.add(SnapshotRow(rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getString(4), rs.getString(5)))
        }
        return out
    }

    /** Crash records are immutable and keep their version_id — new imports never rewrite them. */
    fun addCrash(snapshotId: Long, versionId: Long, addressHex: String, label: String?): Long {
        val id: Long
        conn.prepareStatement("INSERT INTO crash_record(snapshot_id,version_id,address_hex,label,created_at) VALUES(?,?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS).use { ps ->
            ps.setLong(1, snapshotId); ps.setLong(2, versionId); ps.setString(3, addressHex)
            ps.setString(4, label ?: ""); ps.setString(5, Instant.now().toString())
            ps.executeUpdate(); ps.generatedKeys.use { if (it.next()) id = it.getLong(1) else error("no id") }
        }
        return id
    }

    fun listCrashes(snapshotId: Long? = null): List<CrashRow> {
        val out = mutableListOf<CrashRow>()
        val sql = "SELECT id,snapshot_id,version_id,address_hex,label,created_at FROM crash_record" +
            (if (snapshotId != null) " WHERE snapshot_id=?" else "") + " ORDER BY id"
        conn.prepareStatement(sql).use { ps ->
            if (snapshotId != null) ps.setLong(1, snapshotId)
            ps.executeQuery().use { rs ->
                while (rs.next()) out.add(CrashRow(rs.getLong(1), rs.getLong(2), rs.getLong(3), rs.getString(4), rs.getString(5), rs.getString(6)))
            }
        }
        return out
    }
}
