package compass.db

object Schema {
    const val CREATE = """
CREATE TABLE IF NOT EXISTS debug_import (
    id INTEGER PRIMARY KEY,
    path TEXT,
    sha256 TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    imported_at TEXT NOT NULL,
    version_label TEXT NOT NULL,
    elf_blob BLOB NOT NULL,
    is_dwo INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS section_digest (
    id INTEGER PRIMARY KEY,
    import_id INTEGER NOT NULL REFERENCES debug_import(id),
    name TEXT NOT NULL,
    type INTEGER NOT NULL,
    addr INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT
);

CREATE TABLE IF NOT EXISTS parse_issue (
    id INTEGER PRIMARY KEY,
    import_id INTEGER NOT NULL REFERENCES debug_import(id),
    severity TEXT NOT NULL,
    location TEXT NOT NULL,
    message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS comp_unit (
    id INTEGER PRIMARY KEY,
    import_id INTEGER NOT NULL REFERENCES debug_import(id),
    unit_offset INTEGER NOT NULL,
    next_offset INTEGER NOT NULL,
    version INTEGER NOT NULL,
    unit_type INTEGER NOT NULL,
    address_size INTEGER NOT NULL,
    name TEXT,
    dwo_id TEXT,
    is_skeleton INTEGER NOT NULL,
    is_split INTEGER NOT NULL,
    stmt_list INTEGER,
    linked_import_id INTEGER,
    linked_unit_offset INTEGER
);

CREATE TABLE IF NOT EXISTS scope_die (
    id INTEGER PRIMARY KEY,
    import_id INTEGER NOT NULL REFERENCES debug_import(id),
    unit_offset INTEGER NOT NULL,
    die_offset INTEGER NOT NULL,
    tag INTEGER NOT NULL,
    name TEXT,
    inline_depth INTEGER NOT NULL,
    call_file TEXT,
    call_line INTEGER,
    call_column INTEGER
);

CREATE TABLE IF NOT EXISTS die_range (
    id INTEGER PRIMARY KEY,
    scope_id INTEGER NOT NULL REFERENCES scope_die(id),
    start_addr INTEGER NOT NULL,
    end_addr INTEGER NOT NULL,
    segment INTEGER NOT NULL DEFAULT 0,
    zero_length INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS line_file (
    id INTEGER PRIMARY KEY,
    import_id INTEGER NOT NULL REFERENCES debug_import(id),
    stmt_list INTEGER NOT NULL,
    file_index INTEGER NOT NULL,
    name TEXT NOT NULL,
    directory TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS line_row (
    id INTEGER PRIMARY KEY,
    import_id INTEGER NOT NULL REFERENCES debug_import(id),
    stmt_list INTEGER NOT NULL,
    seq_index INTEGER NOT NULL,
    address INTEGER NOT NULL,
    file_index INTEGER NOT NULL,
    line INTEGER NOT NULL,
    column INTEGER NOT NULL,
    is_stmt INTEGER NOT NULL,
    end_sequence INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS line_sequence (
    id INTEGER PRIMARY KEY,
    import_id INTEGER NOT NULL REFERENCES debug_import(id),
    stmt_list INTEGER NOT NULL,
    seq_index INTEGER NOT NULL,
    start_addr INTEGER NOT NULL,
    end_addr INTEGER NOT NULL,
    segment INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS load_snapshot (
    id INTEGER PRIMARY KEY,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshot_module (
    id INTEGER PRIMARY KEY,
    snapshot_id INTEGER NOT NULL REFERENCES load_snapshot(id),
    name TEXT NOT NULL,
    import_id INTEGER NOT NULL REFERENCES debug_import(id),
    base_addr INTEGER NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS query_log (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    snapshot_id INTEGER REFERENCES load_snapshot(id),
    raw_input TEXT NOT NULL,
    runtime_addr INTEGER,
    relative_addr INTEGER,
    load_bias INTEGER,
    module_name TEXT,
    result_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_section_import ON section_digest(import_id);
CREATE INDEX IF NOT EXISTS idx_unit_import ON comp_unit(import_id);
CREATE INDEX IF NOT EXISTS idx_scope_import ON scope_die(import_id);
CREATE INDEX IF NOT EXISTS idx_range_start ON die_range(start_addr, end_addr);
CREATE INDEX IF NOT EXISTS idx_row_addr ON line_row(import_id, stmt_list, address);
"""
}
