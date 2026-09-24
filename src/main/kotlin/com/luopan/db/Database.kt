package com.luopan.db

import java.sql.Connection
import java.sql.DriverManager

object DatabaseFactory {
    fun open(path: String): Connection {
        Class.forName("org.sqlite.JDBC")
        val conn = DriverManager.getConnection("jdbc:sqlite:$path")
        conn.createStatement().use { it.execute("PRAGMA foreign_keys = ON") }
        Schema.migrate(conn)
        return conn
    }
}

object Schema {
    fun migrate(conn: Connection) {
        conn.createStatement().use { st ->
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS debug_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_key TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    imported_at INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    build_id TEXT,
                    dwarf_summary TEXT NOT NULL,
                    blob BLOB NOT NULL,
                    UNIQUE(module_key, sha256)
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS crashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    version_id INTEGER,
                    actual_base INTEGER NOT NULL,
                    preferred_base INTEGER NOT NULL,
                    FOREIGN KEY(version_id) REFERENCES debug_versions(id)
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS crash_addresses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    crash_id INTEGER NOT NULL,
                    seq INTEGER NOT NULL,
                    label TEXT,
                    address INTEGER NOT NULL,
                    segment INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(crash_id) REFERENCES crashes(id) ON DELETE CASCADE
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS load_generations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_key TEXT NOT NULL,
                    version_id INTEGER NOT NULL,
                    generation INTEGER NOT NULL,
                    actual_base INTEGER NOT NULL,
                    preferred_base INTEGER NOT NULL,
                    recorded_at INTEGER NOT NULL,
                    UNIQUE(module_key, generation),
                    FOREIGN KEY(version_id) REFERENCES debug_versions(id)
                )
                """.trimIndent()
            )
        }
    }
}
