package com.linecompass.db

object Schema {
    const val DDL = """
CREATE TABLE IF NOT EXISTS debug_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    raw_summary TEXT NOT NULL,
    imported_at INTEGER NOT NULL,
    version_no INTEGER NOT NULL,
    supersedes_file_id INTEGER
);

CREATE TABLE IF NOT EXISTS debug_sections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    debug_file_id INTEGER NOT NULL REFERENCES debug_files(id),
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    vaddr TEXT NOT NULL,
    summary TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS parse_issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    debug_file_id INTEGER NOT NULL REFERENCES debug_files(id),
    section TEXT NOT NULL,
    severity TEXT NOT NULL,
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    offset_value TEXT,
    cu_offset TEXT
);

CREATE TABLE IF NOT EXISTS compilation_units (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    debug_file_id INTEGER NOT NULL REFERENCES debug_files(id),
    offset_value TEXT NOT NULL,
    length_value TEXT NOT NULL,
    version INTEGER NOT NULL,
    dwarf_64 INTEGER NOT NULL,
    unit_type INTEGER NOT NULL,
    kind TEXT NOT NULL,
    address_size INTEGER NOT NULL,
    name TEXT,
    comp_dir TEXT,
    producer TEXT,
    dwo_id TEXT,
    split_missing INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS address_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    debug_file_id INTEGER NOT NULL REFERENCES debug_files(id),
    cu_id INTEGER REFERENCES compilation_units(id),
    die_offset TEXT,
    segment INTEGER NOT NULL,
    start_value TEXT NOT NULL,
    end_value TEXT NOT NULL,
    zero_length INTEGER NOT NULL,
    kind TEXT NOT NULL,
    explicit_priority INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS line_sequences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cu_id INTEGER NOT NULL REFERENCES compilation_units(id),
    start_value TEXT NOT NULL,
    end_value TEXT NOT NULL,
    segment INTEGER NOT NULL,
    row_count INTEGER NOT NULL,
    table_version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS line_rows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sequence_id INTEGER NOT NULL REFERENCES line_sequences(id),
    ord INTEGER NOT NULL,
    address_value TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    column_no INTEGER NOT NULL,
    is_stmt INTEGER NOT NULL,
    end_sequence INTEGER NOT NULL,
    isa INTEGER NOT NULL,
    discriminator INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS load_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    fixed INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS module_loads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL REFERENCES load_snapshots(id),
    module_name TEXT NOT NULL,
    debug_file_id INTEGER NOT NULL REFERENCES debug_files(id),
    base_address TEXT NOT NULL,
    generation INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS crashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER REFERENCES load_snapshots(id),
    title TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    raw_input TEXT NOT NULL,
    resolution_json TEXT NOT NULL
);
"""
}
