package compass.store

object Schema {
    const val VERSION = 1

    val DDL = """
    CREATE TABLE IF NOT EXISTS debug_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        label TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        crc32 INTEGER NOT NULL,
        elf_class TEXT,
        endian TEXT,
        machine INTEGER,
        dwarf_versions TEXT,
        is_split INTEGER NOT NULL DEFAULT 0,
        warnings TEXT NOT NULL DEFAULT '[]',
        raw_bytes BLOB NOT NULL
    );

    CREATE TABLE IF NOT EXISTS section_summaries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version_id INTEGER NOT NULL REFERENCES debug_versions(id),
        name TEXT NOT NULL,
        size INTEGER NOT NULL,
        addr TEXT,
        allocated INTEGER NOT NULL,
        sha256 TEXT,
        error TEXT
    );

    -- A module load snapshot fixes the bias at a point in time. The same relative
    -- address can be explained under several generations of loading.
    CREATE TABLE IF NOT EXISTS load_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        version_id INTEGER NOT NULL REFERENCES debug_versions(id),
        generation INTEGER NOT NULL,
        load_bias TEXT NOT NULL,
        module_base TEXT,
        note TEXT NOT NULL DEFAULT ''
    );

    -- Crash / stack records are immutable once stored. Newly imported debug files
    -- produce new versions but never rewrite these rows.
    CREATE TABLE IF NOT EXISTS crash_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        snapshot_id INTEGER NOT NULL REFERENCES load_snapshots(id),
        label TEXT NOT NULL,
        runtime_address TEXT NOT NULL,
        explanation_json TEXT NOT NULL,
        version_id_at_crash INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS batch_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        snapshot_id INTEGER NOT NULL REFERENCES load_snapshots(id),
        version_id INTEGER NOT NULL,
        raw_input TEXT NOT NULL,
        results_json TEXT NOT NULL
    );
    """.trimIndent()
}
