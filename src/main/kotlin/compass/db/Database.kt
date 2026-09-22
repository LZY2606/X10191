package compass.db

import org.sqlite.SQLiteConfig
import java.sql.Connection
import java.sql.DriverManager
import java.io.File

class Database(path: String) {
    val conn: Connection

    init {
        Class.forName("org.sqlite.JDBC")
        if (path != ":memory:") File(path).absoluteFile.parentFile?.mkdirs()
        val cfg = SQLiteConfig().apply {
            setJournalMode(SQLiteConfig.JournalMode.WAL)
        }
        conn = DriverManager.getConnection("jdbc:sqlite:$path", cfg.toProperties())
        conn.createStatement().use { it.execute("PRAGMA foreign_keys=ON") }
        createSchema()
    }

    private fun createSchema() {
        conn.createStatement().use { st ->
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS debug_file_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT NOT NULL,
                    build_id TEXT,
                    sha256 TEXT NOT NULL,
                    elf_class TEXT,
                    endian TEXT,
                    machine INTEGER,
                    dwarf_versions TEXT,
                    cu_count INTEGER,
                    section_count INTEGER,
                    has_dwo INTEGER,
                    warnings TEXT,
                    imported_at INTEGER NOT NULL
                );
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS crash_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS session_modules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL REFERENCES crash_sessions(id) ON DELETE CASCADE,
                    version_id INTEGER NOT NULL REFERENCES debug_file_versions(id),
                    module_name TEXT NOT NULL,
                    build_id TEXT,
                    load_bias INTEGER NOT NULL,
                    generation INTEGER NOT NULL,
                    segment INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(session_id, module_name, generation)
                );
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS debug_blobs (
                    version_id INTEGER PRIMARY KEY REFERENCES debug_file_versions(id) ON DELETE CASCADE,
                    bytes BLOB NOT NULL
                );
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS address_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL REFERENCES crash_sessions(id) ON DELETE CASCADE,
                    runtime_address INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL,
                    result_json TEXT NOT NULL,
                    queried_at INTEGER NOT NULL
                );
                """.trimIndent()
            )
        }
    }
}
