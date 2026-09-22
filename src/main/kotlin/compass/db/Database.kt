package compass.db

import java.nio.file.Files
import java.nio.file.Path
import java.sql.Connection
import java.sql.DriverManager

class Database(private val dbPath: Path) {
    val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$dbPath")

    init {
        Class.forName("org.sqlite.JDBC")
        conn.createStatement().executeUpdate("PRAGMA journal_mode=WAL")
        conn.createStatement().executeUpdate("PRAGMA foreign_keys=ON")
        migrate()
    }

    private fun migrate() {
        val st = conn.createStatement()
        st.executeUpdate(
            """
            CREATE TABLE IF NOT EXISTS modules (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              created_at INTEGER NOT NULL
            )
            """.trimIndent()
        )
        st.executeUpdate(
            """
            CREATE TABLE IF NOT EXISTS module_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              module_id INTEGER NOT NULL REFERENCES modules(id),
              version INTEGER NOT NULL,
              filename TEXT,
              sha256 TEXT NOT NULL,
              size INTEGER NOT NULL,
              elf_class INTEGER,
              machine INTEGER,
              imported_at INTEGER NOT NULL,
              raw_path TEXT NOT NULL,
              raw_sections_json TEXT NOT NULL,
              warnings_json TEXT NOT NULL,
              UNIQUE(module_id, version)
            )
            """.trimIndent()
        )
        st.executeUpdate(
            """
            CREATE TABLE IF NOT EXISTS snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              module_version_id INTEGER NOT NULL REFERENCES module_versions(id),
              generation INTEGER NOT NULL,
              load_bias INTEGER NOT NULL,
              note TEXT,
              created_at INTEGER NOT NULL,
              UNIQUE(module_version_id, generation)
            )
            """.trimIndent()
        )
        st.executeUpdate(
            """
            CREATE TABLE IF NOT EXISTS crashes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              title TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              addresses_json TEXT NOT NULL,
              snapshot_id INTEGER REFERENCES snapshots(id)
            )
            """.trimIndent()
        )
    }

    fun close() = conn.close()

    companion object {
        fun open(dir: Path): Database {
            Files.createDirectories(dir)
            return Database(dir.resolve("compass.sqlite"))
        }
    }
}
