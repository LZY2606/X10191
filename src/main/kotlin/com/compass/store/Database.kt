package com.compass.store

import java.sql.Connection
import java.sql.DriverManager
import java.io.File

/**
 * SQLite-backed store. Debug files form immutable versions: importing a new
 * file creates a new version and never rewrites prior crash records, which
 * keep a pinned version_id.
 */
class Database(path: String = "compass.db") {
    val conn: Connection

    init {
        Class.forName("org.sqlite.JDBC")
        val file = File(path)
        conn = DriverManager.getConnection("jdbc:sqlite:${file.absolutePath}")
        conn.createStatement().execute("PRAGMA foreign_keys = ON")
        migrate()
    }

    private fun migrate() {
        conn.createStatement().use { st ->
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS debug_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    role TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    head16 TEXT NOT NULL,
                    tail16 TEXT NOT NULL,
                    elf_class TEXT,
                    machine INTEGER,
                    data BLOB NOT NULL,
                    imported_at INTEGER NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    note TEXT
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS sections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER NOT NULL REFERENCES debug_files(id),
                    name TEXT NOT NULL,
                    type INTEGER,
                    addr TEXT,
                    file_offset TEXT,
                    size TEXT,
                    addralign TEXT
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS cus (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER NOT NULL REFERENCES debug_files(id),
                    cu_offset TEXT,
                    version INTEGER,
                    unit_type INTEGER,
                    is_split INTEGER,
                    dwo_id TEXT,
                    name TEXT,
                    comp_dir TEXT,
                    low_pc TEXT,
                    ranges_json TEXT,
                    dies_json TEXT,
                    line_json TEXT,
                    issues_json TEXT,
                    dwo_resolved INTEGER
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS crashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES versions(id),
                    label TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS module_loads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    crash_id INTEGER NOT NULL REFERENCES crashes(id),
                    generation INTEGER NOT NULL,
                    module_name TEXT NOT NULL,
                    file_sha TEXT,
                    runtime_base TEXT NOT NULL,
                    link_base TEXT NOT NULL,
                    bias TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """.trimIndent()
            )
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS query_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    crash_id INTEGER REFERENCES crashes(id),
                    version_id INTEGER,
                    generation INTEGER,
                    runtime_addr TEXT,
                    relative_addr TEXT,
                    bias TEXT,
                    result_json TEXT,
                    created_at INTEGER NOT NULL
                )
                """.trimIndent()
            )
        }
    }

    fun close() = conn.close()
}
