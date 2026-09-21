package compass.db

import java.sql.Connection
import java.sql.DriverManager

object Schema {
    const val VERSION = 1

    val DDL = """
    CREATE TABLE IF NOT EXISTS debug_version (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT NOT NULL,
        file_name TEXT,
        sha256 TEXT NOT NULL,
        build_id TEXT,
        size_bytes INTEGER NOT NULL,
        elf_class INTEGER NOT NULL,
        little_endian INTEGER NOT NULL,
        machine INTEGER NOT NULL,
        priority INTEGER NOT NULL DEFAULT 100,
        imported_at INTEGER NOT NULL,
        table_version TEXT NOT NULL,
        has_split INTEGER NOT NULL DEFAULT 0,
        split_sha256 TEXT
    );

    CREATE TABLE IF NOT EXISTS raw_section (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version_id INTEGER NOT NULL REFERENCES debug_version(id),
        name TEXT NOT NULL,
        addr INTEGER NOT NULL,
        offset INTEGER NOT NULL,
        size INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        bytes BLOB NOT NULL,
        UNIQUE(version_id, name)
    );

    CREATE TABLE IF NOT EXISTS comp_unit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version_id INTEGER NOT NULL REFERENCES debug_version(id),
        cu_offset INTEGER NOT NULL,
        dwarf_version INTEGER NOT NULL,
        unit_type INTEGER NOT NULL,
        address_size INTEGER NOT NULL,
        name TEXT,
        comp_dir TEXT,
        is_skeleton INTEGER NOT NULL DEFAULT 0,
        is_dwo INTEGER NOT NULL DEFAULT 0,
        dwo_id TEXT,
        dwo_name TEXT,
        dwo_resolved INTEGER NOT NULL DEFAULT 0,
        UNIQUE(version_id, cu_offset)
    );

    CREATE TABLE IF NOT EXISTS die_node (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version_id INTEGER NOT NULL REFERENCES debug_version(id),
        cu_offset INTEGER NOT NULL,
        die_offset INTEGER NOT NULL,
        tag INTEGER NOT NULL,
        depth INTEGER NOT NULL,
        parent_offset INTEGER,
        name TEXT,
        linkage_name TEXT,
        low_pc TEXT,
        high_pc TEXT,
        decl_file TEXT,
        decl_line INTEGER,
        is_inline INTEGER NOT NULL DEFAULT 0,
        UNIQUE(version_id, die_offset)
    );

    CREATE TABLE IF NOT EXISTS address_range (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version_id INTEGER NOT NULL REFERENCES debug_version(id),
        die_offset INTEGER NOT NULL,
        start INTEGER NOT NULL,
        end INTEGER NOT NULL,
        zero_length INTEGER NOT NULL,
        source TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS line_sequence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version_id INTEGER NOT NULL REFERENCES debug_version(id),
        seq_local_id INTEGER NOT NULL,
        cu_offset INTEGER NOT NULL,
        start_address INTEGER NOT NULL,
        end_address INTEGER NOT NULL,
        dwarf_version INTEGER NOT NULL,
        segmented INTEGER NOT NULL,
        UNIQUE(version_id, seq_local_id)
    );

    CREATE TABLE IF NOT EXISTS line_row (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seq_pk INTEGER NOT NULL REFERENCES line_sequence(id),
        address INTEGER NOT NULL,
        file_id INTEGER NOT NULL,
        file_name TEXT,
        line INTEGER NOT NULL,
        column INTEGER NOT NULL,
        is_stmt INTEGER NOT NULL,
        end_sequence INTEGER NOT NULL,
        prologue_end INTEGER NOT NULL,
        discriminator INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS line_event (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seq_pk INTEGER NOT NULL REFERENCES line_sequence(id),
        seq_pos INTEGER NOT NULL,
        address INTEGER NOT NULL,
        file TEXT,
        line INTEGER NOT NULL,
        column INTEGER NOT NULL,
        is_stmt INTEGER NOT NULL,
        kind TEXT NOT NULL,
        detail TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS parse_diagnostic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version_id INTEGER NOT NULL REFERENCES debug_version(id),
        severity TEXT NOT NULL,
        code TEXT NOT NULL,
        message TEXT NOT NULL,
        section TEXT,
        offset INTEGER
    );

    CREATE TABLE IF NOT EXISTS module_load (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_id INTEGER NOT NULL REFERENCES load_snapshot(id),
        version_id INTEGER NOT NULL REFERENCES debug_version(id),
        generation INTEGER NOT NULL,
        base_address INTEGER NOT NULL,
        bias INTEGER NOT NULL,
        loaded_at INTEGER NOT NULL,
        label TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS load_snapshot (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        note TEXT
    );

    CREATE TABLE IF NOT EXISTS crash_record (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_id INTEGER NOT NULL REFERENCES load_snapshot(id),
        created_at INTEGER NOT NULL,
        title TEXT NOT NULL,
        frozen_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS crash_query (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        crash_id INTEGER NOT NULL REFERENCES crash_record(id),
        ordinal INTEGER NOT NULL,
        address INTEGER NOT NULL,
        answer_json TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_range_lookup ON address_range(version_id, start, end);
    CREATE INDEX IF NOT EXISTS idx_seq_lookup ON line_sequence(version_id, start_address, end_address);
    CREATE INDEX IF NOT EXISTS idx_die_cu ON die_node(version_id, cu_offset);
    """
}

class Database(val path: String) {
    val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path").apply {
        createStatement().use { it.executeUpdate("PRAGMA foreign_keys=ON") }
        createStatement().use { it.executeUpdate("PRAGMA journal_mode=WAL") }
    }

    init {
        conn.createStatement().use { st -> Schema.DDL.trimIndent().split(";").filter { it.isNotBlank() }.forEach { st.execute(it) } }
    }

    fun close() = conn.close()
}
