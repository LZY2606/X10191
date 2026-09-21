@file:Suppress("ArrayInDataClass")
package compass.storage

import compass.dwarf.DebugBundle
import java.sql.Connection
import java.sql.DriverManager
import java.util.Properties

class Database(path: String) {
    val conn: Connection

    init {
        Class.forName("org.sqlite.JDBC")
        val url = if (path == ":memory:") "jdbc:sqlite::memory:" else "jdbc:sqlite:$path"
        val props = Properties().apply {
            setProperty("foreign_keys", "true")
        }
        conn = DriverManager.getConnection(url, props)
        conn.createStatement().use { st ->
            st.executeUpdate("PRAGMA journal_mode=WAL")
            st.executeUpdate("PRAGMA foreign_keys=ON")
        }
        migrate()
    }

    private fun migrate() {
        conn.createStatement().use { st ->
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS modules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT NOT NULL,
                    build_id TEXT,
                    content_sha256 TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE(content_sha256)
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS module_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_id INTEGER NOT NULL REFERENCES modules(id),
                    version INTEGER NOT NULL,
                    bundle_json TEXT NOT NULL,
                    imported_at INTEGER NOT NULL,
                    UNIQUE(module_id, version)
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS module_sections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_version_id INTEGER NOT NULL REFERENCES module_versions(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    bytes BLOB NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS snapshot_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
                    module_version_id INTEGER NOT NULL REFERENCES module_versions(id),
                    load_bias TEXT NOT NULL,
                    base_address TEXT NOT NULL,
                    generation INTEGER NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS crashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label TEXT NOT NULL,
                    snapshot_id INTEGER REFERENCES snapshots(id),
                    created_at INTEGER NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS crash_frames (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    crash_id INTEGER NOT NULL REFERENCES crashes(id) ON DELETE CASCADE,
                    ord INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    result_json TEXT
                )
                """.trimIndent()
            )
        }
    }

    fun close() = conn.close()
}
