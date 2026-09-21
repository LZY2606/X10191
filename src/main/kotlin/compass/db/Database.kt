package compass.db

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager

/**
 * SQLite-backed storage. Every debug-file import creates a new, immutable
 * version; old crash records keep their version_id and are never rewritten.
 */
class CompassDatabase(private val dbFile: Path) {
    private val conn: Connection

    init {
        Class.forName("org.sqlite.JDBC")
        Files.createDirectories(dbFile.toAbsolutePath().parent)
        conn = DriverManager.getConnection("jdbc:sqlite:$dbFile")
        conn.createStatement().use { st ->
            st.executeUpdate("PRAGMA foreign_keys=ON")
        }
        schema()
    }

    private fun schema() = conn.createStatement().use { st ->
        st.executeUpdate(
            """
            CREATE TABLE IF NOT EXISTS debug_version (
              id INTEGER PRIMARY KEY,
              imported_at INTEGER NOT NULL,
              label TEXT NOT NULL,
              file_name TEXT NOT NULL,
              sha256 TEXT NOT NULL,
              size INTEGER NOT NULL,
              kind TEXT NOT NULL,                 -- executable | debug | dwo
              split_status TEXT NOT NULL,
              note TEXT
            )""".trimIndent()
        )
        st.executeUpdate(
            """
            CREATE TABLE IF NOT EXISTS section_map (
              id INTEGER PRIMARY KEY,
              version_id INTEGER NOT NULL REFERENCES debug_version(id),
              name TEXT NOT NULL,
              addr INTEGER NOT NULL,
              offset INTEGER NOT NULL,
              size INTEGER NOT NULL,
              flags INTEGER NOT NULL,
              sha256 TEXT NOT NULL,
              byte_summary TEXT NOT NULL
            )""".trimIndent()
        )
        st.executeUpdate(
            """
            CREATE TABLE IF NOT EXISTS module_snapshot (
              id INTEGER PRIMARY KEY,
              version_id INTEGER NOT NULL REFERENCES debug_version(id),
              created_at INTEGER NOT NULL,
              module_name TEXT NOT NULL,
              preferred_base INTEGER NOT NULL,
              load_base INTEGER NOT NULL,
              generation INTEGER NOT NULL
            )""".trimIndent()
        )
        st.executeUpdate(
            """
            CREATE TABLE IF NOT EXISTS crash_record (
              id INTEGER PRIMARY KEY,
              created_at INTEGER NOT NULL,
              label TEXT NOT NULL,
              snapshot_id INTEGER REFERENCES module_snapshot(id),
              version_id INTEGER NOT NULL REFERENCES debug_version(id)
            )""".trimIndent()
        )
        st.executeUpdate(
            """
            CREATE TABLE IF NOT EXISTS crash_frame (
              id INTEGER PRIMARY KEY,
              crash_id INTEGER NOT NULL REFERENCES crash_record(id) ON DELETE CASCADE,
              ordinal INTEGER NOT NULL,
              runtime_pc INTEGER NOT NULL,
              result_json TEXT NOT NULL
            )""".trimIndent()
        )
    }

    fun createVersion(
        label: String, fileName: String, bytes: ByteArray, kind: String,
        splitStatus: String, note: String?
    ): Long {
        val sha = sha256(bytes)
        val st = conn.prepareStatement(
            """INSERT INTO debug_version(imported_at,label,file_name,sha256,size,kind,split_status,note)
               VALUES(?,?,?,?,?,?,?,?)""",
            java.sql.Statement.RETURN_GENERATED_KEYS
        )
        st.use {
            it.setLong(1, System.currentTimeMillis())
            it.setString(2, label); it.setString(3, fileName); it.setString(4, sha)
            it.setLong(5, bytes.size.toLong()); it.setString(6, kind)
            it.setString(7, splitStatus); it.setString(8, note)
            it.executeUpdate()
            it.generatedKeys.use { k -> k.next(); return k.getLong(1) }
        }
    }

    fun addSection(
        versionId: Long, name: String, addr: Long, offset: Long, size: Long,
        flags: Long, bytes: ByteArray?
    ) {
        val digest = bytes?.let { sha256(it) } ?: "absent"
        val summary = bytes?.let { byteSummary(it) } ?: ""
        val st = conn.prepareStatement(
            """INSERT INTO section_map(version_id,name,addr,offset,size,flags,sha256,byte_summary)
               VALUES(?,?,?,?,?,?,?,?)"""
        )
        st.use {
            it.setLong(1, versionId); it.setString(2, name); it.setLong(3, addr)
            it.setLong(4, offset); it.setLong(5, size); it.setLong(6, flags)
            it.setString(7, digest); it.setString(8, summary)
            it.executeUpdate()
        }
    }

    fun createSnapshot(
        versionId: Long, moduleName: String, preferredBase: Long, loadBase: Long, generation: Int
    ): Long {
        val st = conn.prepareStatement(
            """INSERT INTO module_snapshot(version_id,created_at,module_name,preferred_base,load_base,generation)
               VALUES(?,?,?,?,?,?)""",
            java.sql.Statement.RETURN_GENERATED_KEYS
        )
        st.use {
            it.setLong(1, versionId); it.setLong(2, System.currentTimeMillis())
            it.setString(3, moduleName); it.setLong(4, preferredBase)
            it.setLong(5, loadBase); it.setInt(6, generation)
            it.executeUpdate()
            it.generatedKeys.use { k -> k.next(); return k.getLong(1) }
        }
    }

    fun createCrash(label: String, snapshotId: Long?, versionId: Long): Long {
        val st = conn.prepareStatement(
            "INSERT INTO crash_record(created_at,label,snapshot_id,version_id) VALUES(?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS
        )
        st.use {
            it.setLong(1, System.currentTimeMillis()); it.setString(2, label)
            if (snapshotId == null) it.setNull(3, java.sql.Types.INTEGER) else it.setLong(3, snapshotId)
            it.setLong(4, versionId); it.executeUpdate()
            it.generatedKeys.use { k -> k.next(); return k.getLong(1) }
        }
    }

    fun addFrame(crashId: Long, ordinal: Int, runtimePc: Long, resultJson: String) {
        conn.prepareStatement(
            "INSERT INTO crash_frame(crash_id,ordinal,runtime_pc,result_json) VALUES(?,?,?,?)"
        ).use {
            it.setLong(1, crashId); it.setInt(2, ordinal); it.setLong(3, runtimePc)
            it.setString(4, resultJson); it.executeUpdate()
        }
    }

    fun listVersions(): List<Map<String, Any?>> = query(
        """SELECT id,imported_at,label,file_name,sha256,size,kind,split_status,note
           FROM debug_version ORDER BY id"""
    )

    fun listSections(versionId: Long): List<Map<String, Any?>> {
        val st = conn.prepareStatement("SELECT * FROM section_map WHERE version_id=? ORDER BY id")
        st.use {
            it.setLong(1, versionId)
            return readRows(it.executeQuery())
        }
    }

    fun listSnapshots(versionId: Long): List<Map<String, Any?>> {
        val st = conn.prepareStatement("SELECT * FROM module_snapshot WHERE version_id=? ORDER BY generation,id")
        st.use {
            it.setLong(1, versionId)
            return readRows(it.executeQuery())
        }
    }

    fun listCrashes(versionId: Long): List<Map<String, Any?>> {
        val st = conn.prepareStatement("SELECT * FROM crash_record WHERE version_id=? ORDER BY id DESC")
        st.use {
            it.setLong(1, versionId)
            return readRows(it.executeQuery())
        }
    }

    fun framesOf(crashId: Long): List<Map<String, Any?>> {
        val st = conn.prepareStatement("SELECT * FROM crash_frame WHERE crash_id=? ORDER BY ordinal")
        st.use {
            it.setLong(1, crashId)
            return readRows(it.executeQuery())
        }
    }

    private fun query(sql: String): List<Map<String, Any?>> =
        conn.createStatement().use { readRows(it.executeQuery(sql)) }

    private fun readRows(rs: java.sql.ResultSet): List<Map<String, Any?>> {
        val meta = rs.metaData
        val out = ArrayList<Map<String, Any?>>()
        while (rs.next()) {
            val row = LinkedHashMap<String, Any?>()
            for (i in 1..meta.columnCount) row[meta.getColumnName(i)] = rs.getObject(i)
            out.add(row)
        }
        return out
    }

    fun close() = conn.close()

    companion object {
        fun sha256(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        /** Compact raw-byte fingerprint: first/last 16 bytes hex + length + density. */
        fun byteSummary(bytes: ByteArray): String {
            val n = bytes.size
            val head = bytes.copyOfRange(0, minOf(8, n)).joinToString("") { "%02x".format(it) }
            val tail = bytes.copyOfRange(maxOf(0, n - 8), n).joinToString("") { "%02x".format(it) }
            var nz = 0
            for (b in bytes) if (b.toInt() != 0) nz++
            return "len=$n head=$head tail=$tail nonzero=$nz"
        }
    }
}
