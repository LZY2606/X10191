package compass.core

import compass.elf.ElfFile
import java.sql.Connection
import java.sql.DriverManager

data class DebugFileRow(
    val id: Long, val name: String, val importedAt: String,
    val sha256: String, val priority: Int, val size: Long,
)

data class SnapshotRow(
    val id: Long, val name: String, val debugFileId: Long,
    val debugFileName: String, val loadBias: Long, val createdAt: String,
)

data class CrashRow(
    val id: Long, val snapshotId: Long, val snapshotName: String,
    val createdAt: String, val note: String, val frames: List<Long>,
)

/** SQLite-backed persistence. Importing a debug file creates a new version
 * row; existing snapshots and crash records keep pointing at their version. */
class Store(path: String) {
    private val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path")
    private val modelCache = HashMap<Long, DebugFileModel>()

    init {
        conn.createStatement().use { st ->
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS debug_file(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    imported_at TEXT NOT NULL DEFAULT (datetime('now')),
                    sha256 TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 0,
                    bytes BLOB NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS section(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER NOT NULL REFERENCES debug_file(id),
                    name TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    bytes BLOB NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS snapshot(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    debug_file_id INTEGER NOT NULL REFERENCES debug_file(id),
                    load_bias INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS crash(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL REFERENCES snapshot(id),
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    note TEXT NOT NULL DEFAULT ''
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS crash_frame(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    crash_id INTEGER NOT NULL REFERENCES crash(id),
                    idx INTEGER NOT NULL,
                    address INTEGER NOT NULL
                )
                """.trimIndent()
            )
        }
    }

    fun importDebugFile(name: String, bytes: ByteArray, priority: Int = 0): Long {
        val elf = ElfFile.parse(bytes) // throws on invalid input; nothing stored
        val sha = ElfFile.digest(bytes)
        conn.autoCommit = false
        try {
            val id: Long
            conn.prepareStatement(
                "INSERT INTO debug_file(name, sha256, priority, bytes) VALUES(?,?,?,?)"
            ).use { ps ->
                ps.setString(1, name)
                ps.setString(2, sha)
                ps.setInt(3, priority)
                ps.setBytes(4, bytes)
                ps.executeUpdate()
                id = ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
            }
            conn.prepareStatement(
                "INSERT INTO section(file_id, name, size, sha256, bytes) VALUES(?,?,?,?,?)"
            ).use { ps ->
                for (s in elf.sections) {
                    val sb = elf.sectionBytes(s)
                    ps.setLong(1, id)
                    ps.setString(2, s.name)
                    ps.setLong(3, s.size)
                    ps.setString(4, ElfFile.digest(sb))
                    ps.setBytes(5, sb)
                    ps.addBatch()
                }
                ps.executeBatch()
            }
            conn.commit()
            return id
        } finally {
            conn.autoCommit = true
        }
    }

    fun listDebugFiles(): List<DebugFileRow> =
        conn.createStatement().use { st ->
            st.executeQuery(
                "SELECT id, name, imported_at, sha256, priority, length(bytes) FROM debug_file ORDER BY id"
            ).use { rs ->
                buildList {
                    while (rs.next()) {
                        add(DebugFileRow(rs.getLong(1), rs.getString(2), rs.getString(3),
                            rs.getString(4), rs.getInt(5), rs.getLong(6)))
                    }
                }
            }
        }

    fun sectionsOf(fileId: Long): List<SectionInfo> =
        conn.prepareStatement(
            "SELECT name, size, sha256 FROM section WHERE file_id=? ORDER BY id"
        ).use { ps ->
            ps.setLong(1, fileId)
            ps.executeQuery().use { rs ->
                buildList {
                    while (rs.next()) add(SectionInfo(rs.getString(1), rs.getLong(2), rs.getString(3), true))
                }
            }
        }

    private fun fileBytes(fileId: Long): ByteArray? =
        conn.prepareStatement("SELECT bytes FROM debug_file WHERE id=?").use { ps ->
            ps.setLong(1, fileId)
            ps.executeQuery().use { rs -> if (rs.next()) rs.getBytes(1) else null }
        }

    fun fileRow(fileId: Long): DebugFileRow? =
        conn.prepareStatement(
            "SELECT id, name, imported_at, sha256, priority, length(bytes) FROM debug_file WHERE id=?"
        ).use { ps ->
            ps.setLong(1, fileId)
            ps.executeQuery().use { rs ->
                if (rs.next()) DebugFileRow(rs.getLong(1), rs.getString(2), rs.getString(3),
                    rs.getString(4), rs.getInt(5), rs.getLong(6)) else null
            }
        }

    /** Parsed model for a stored version, cached in memory. */
    fun model(fileId: Long): DebugFileModel? {
        modelCache[fileId]?.let { return it }
        val bytes = fileBytes(fileId) ?: return null
        val row = fileRow(fileId) ?: return null
        val m = ModelBuilder.build(row.name, ElfFile.parse(bytes))
        modelCache[fileId] = m
        return m
    }

    fun priorityOf(fileId: Long): Int = fileRow(fileId)?.priority ?: 0

    fun createSnapshot(name: String, debugFileId: Long, loadBias: Long): Long =
        conn.prepareStatement(
            "INSERT INTO snapshot(name, debug_file_id, load_bias) VALUES(?,?,?)"
        ).use { ps ->
            ps.setString(1, name)
            ps.setLong(2, debugFileId)
            ps.setLong(3, loadBias)
            ps.executeUpdate()
            ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
        }

    fun listSnapshots(): List<SnapshotRow> =
        conn.createStatement().use { st ->
            st.executeQuery(
                """SELECT s.id, s.name, s.debug_file_id, d.name, s.load_bias, s.created_at
                   FROM snapshot s JOIN debug_file d ON d.id = s.debug_file_id ORDER BY s.id"""
            ).use { rs ->
                buildList {
                    while (rs.next()) {
                        add(SnapshotRow(rs.getLong(1), rs.getString(2), rs.getLong(3),
                            rs.getString(4), rs.getLong(5), rs.getString(6)))
                    }
                }
            }
        }

    fun snapshot(id: Long): SnapshotRow? =
        conn.prepareStatement(
            """SELECT s.id, s.name, s.debug_file_id, d.name, s.load_bias, s.created_at
               FROM snapshot s JOIN debug_file d ON d.id = s.debug_file_id WHERE s.id=?"""
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                if (rs.next()) SnapshotRow(rs.getLong(1), rs.getString(2), rs.getLong(3),
                    rs.getString(4), rs.getLong(5), rs.getString(6)) else null
            }
        }

    fun createCrash(snapshotId: Long, note: String, addresses: List<Long>): Long {
        conn.autoCommit = false
        try {
            val id: Long
            conn.prepareStatement("INSERT INTO crash(snapshot_id, note) VALUES(?,?)").use { ps ->
                ps.setLong(1, snapshotId)
                ps.setString(2, note)
                ps.executeUpdate()
                id = ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
            }
            conn.prepareStatement("INSERT INTO crash_frame(crash_id, idx, address) VALUES(?,?,?)").use { ps ->
                addresses.forEachIndexed { i, a ->
                    ps.setLong(1, id); ps.setInt(2, i); ps.setLong(3, a); ps.addBatch()
                }
                ps.executeBatch()
            }
            conn.commit()
            return id
        } finally {
            conn.autoCommit = true
        }
    }

    fun listCrashes(): List<CrashRow> =
        conn.createStatement().use { st ->
            st.executeQuery(
                """SELECT c.id, c.snapshot_id, s.name, c.created_at, c.note
                   FROM crash c JOIN snapshot s ON s.id = c.snapshot_id ORDER BY c.id"""
            ).use { rs ->
                buildList {
                    while (rs.next()) {
                        add(CrashRow(rs.getLong(1), rs.getLong(2), rs.getString(3),
                            rs.getString(4), rs.getString(5), emptyList()))
                    }
                }
            }
        }

    fun crash(id: Long): CrashRow? {
        val head = conn.prepareStatement(
            """SELECT c.id, c.snapshot_id, s.name, c.created_at, c.note
               FROM crash c JOIN snapshot s ON s.id = c.snapshot_id WHERE c.id=?"""
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                if (rs.next()) CrashRow(rs.getLong(1), rs.getLong(2), rs.getString(3),
                    rs.getString(4), rs.getString(5), emptyList()) else null
            }
        } ?: return null
        val frames = conn.prepareStatement(
            "SELECT address FROM crash_frame WHERE crash_id=? ORDER BY idx"
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                buildList { while (rs.next()) add(rs.getLong(1)) }
            }
        }
        return head.copy(frames = frames)
    }

    fun close() = conn.close()
}
