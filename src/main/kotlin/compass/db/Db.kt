package compass.db

import compass.dwarf.CompilationUnit
import compass.dwarf.ParsedDwarf
import compass.elf.ElfFile
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager

fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

class Db(path: String) {
    val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path")

    init {
        conn.createStatement().use { st ->
            st.executeUpdate("PRAGMA journal_mode=WAL")
            st.executeUpdate("PRAGMA foreign_keys=ON")
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS module_versions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    version_no INTEGER NOT NULL,
                    imported_at TEXT NOT NULL DEFAULT (datetime('now')),
                    sha256 TEXT NOT NULL,
                    elf_class TEXT NOT NULL,
                    elf_type INTEGER NOT NULL,
                    preferred_base INTEGER NOT NULL,
                    parse_issues TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS sections(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_version_id INTEGER NOT NULL REFERENCES module_versions(id),
                    idx INTEGER NOT NULL, name TEXT NOT NULL, type INTEGER NOT NULL,
                    flags INTEGER NOT NULL, addr INTEGER NOT NULL, offset INTEGER NOT NULL,
                    size INTEGER NOT NULL, sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS compile_units(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_version_id INTEGER NOT NULL REFERENCES module_versions(id),
                    cu_offset INTEGER NOT NULL, version INTEGER NOT NULL, unit_type INTEGER NOT NULL,
                    addr_size INTEGER NOT NULL, name TEXT, comp_dir TEXT, low_pc INTEGER,
                    stmt_list INTEGER, line_version INTEGER, rnglists_version INTEGER,
                    dwo_name TEXT, dwo_missing INTEGER NOT NULL, truncated INTEGER NOT NULL,
                    issues TEXT NOT NULL DEFAULT '', content_key TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cu_ranges(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cu_id INTEGER NOT NULL REFERENCES compile_units(id),
                    begin INTEGER NOT NULL, end INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS line_rows(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cu_id INTEGER NOT NULL REFERENCES compile_units(id),
                    seq INTEGER NOT NULL, address INTEGER NOT NULL, end_address INTEGER NOT NULL,
                    file TEXT NOT NULL, line INTEGER NOT NULL, col INTEGER NOT NULL,
                    is_stmt INTEGER NOT NULL, basic_block INTEGER NOT NULL, end_sequence INTEGER NOT NULL,
                    prologue_end INTEGER NOT NULL, epilogue_begin INTEGER NOT NULL,
                    discriminator INTEGER NOT NULL, file_index INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_line_rows_addr ON line_rows(address, end_address);
                CREATE TABLE IF NOT EXISTS inlines(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cu_id INTEGER NOT NULL REFERENCES compile_units(id),
                    parent_id INTEGER, depth INTEGER NOT NULL, name TEXT NOT NULL,
                    call_file TEXT, call_line INTEGER, die_offset INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS inline_ranges(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    inline_id INTEGER NOT NULL REFERENCES inlines(id),
                    begin INTEGER NOT NULL, end INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS snapshots(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS snapshot_modules(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
                    module_version_id INTEGER NOT NULL REFERENCES module_versions(id),
                    load_base INTEGER NOT NULL, generation INTEGER NOT NULL DEFAULT 1, note TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS crash_records(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
                    addresses_text TEXT NOT NULL, results_json TEXT NOT NULL
                );
                """.trimIndent()
            )
        }
    }

    /** Import a parsed module as a NEW version; never mutates existing rows. */
    fun importModule(name: String, elf: ElfFile, rawBytes: ByteArray, parsed: ParsedDwarf): Long {
        val versionNo = conn.prepareStatement(
            "SELECT COALESCE(MAX(version_no),0)+1 FROM module_versions WHERE name=?"
        ).use { ps ->
            ps.setString(1, name)
            ps.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
        val mvId: Long
        conn.prepareStatement(
            "INSERT INTO module_versions(name,version_no,sha256,elf_class,elf_type,preferred_base,parse_issues) VALUES(?,?,?,?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS,
        ).use { ps ->
            ps.setString(1, name)
            ps.setLong(2, versionNo)
            ps.setString(3, sha256Hex(rawBytes))
            ps.setString(4, if (elf.is64) "ELF64" else "ELF32")
            ps.setInt(5, elf.elfType)
            ps.setLong(6, elf.preferredBase)
            ps.setString(7, parsed.issues.joinToString("\n"))
            ps.executeUpdate()
            mvId = ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
        }
        conn.prepareStatement(
            "INSERT INTO sections(module_version_id,idx,name,type,flags,addr,offset,size,sha256) VALUES(?,?,?,?,?,?,?,?,?)"
        ).use { ps ->
            for (s in elf.sections) {
                ps.setLong(1, mvId); ps.setInt(2, s.index); ps.setString(3, s.name)
                ps.setLong(4, s.type); ps.setLong(5, s.flags); ps.setLong(6, s.addr)
                ps.setLong(7, s.offset); ps.setLong(8, s.size); ps.setString(9, sha256Hex(s.bytes))
                ps.addBatch()
            }
            ps.executeBatch()
        }
        for (cu in parsed.units) insertCu(mvId, cu)
        return mvId
    }

    private fun insertCu(mvId: Long, cu: CompilationUnit) {
        val cuId: Long
        conn.prepareStatement(
            """INSERT INTO compile_units(module_version_id,cu_offset,version,unit_type,addr_size,name,comp_dir,low_pc,
               stmt_list,line_version,rnglists_version,dwo_name,dwo_missing,truncated,issues,content_key)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            java.sql.Statement.RETURN_GENERATED_KEYS,
        ).use { ps ->
            ps.setLong(1, mvId); ps.setLong(2, cu.offset); ps.setInt(3, cu.version)
            ps.setInt(4, cu.unitType); ps.setInt(5, cu.addrSize)
            ps.setString(6, cu.name); ps.setString(7, cu.compDir)
            if (cu.lowPc != null) ps.setLong(8, cu.lowPc) else ps.setNull(8, java.sql.Types.INTEGER)
            if (cu.stmtListOffset != null) ps.setLong(9, cu.stmtListOffset) else ps.setNull(9, java.sql.Types.INTEGER)
            if (cu.lineVersion != null) ps.setInt(10, cu.lineVersion) else ps.setNull(10, java.sql.Types.INTEGER)
            if (cu.rnglistsVersion != null) ps.setInt(11, cu.rnglistsVersion) else ps.setNull(11, java.sql.Types.INTEGER)
            ps.setString(12, cu.dwoName)
            ps.setInt(13, if (cu.dwoMissing) 1 else 0)
            ps.setInt(14, if (cu.truncated) 1 else 0)
            ps.setString(15, cu.issues.joinToString("\n"))
            ps.setString(16, cu.contentKey)
            ps.executeUpdate()
            cuId = ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
        }
        conn.prepareStatement("INSERT INTO cu_ranges(cu_id,begin,end) VALUES(?,?,?)").use { ps ->
            for (r in cu.ranges) { ps.setLong(1, cuId); ps.setLong(2, r.begin); ps.setLong(3, r.end); ps.addBatch() }
            ps.executeBatch()
        }
        conn.prepareStatement(
            """INSERT INTO line_rows(cu_id,seq,address,end_address,file,line,col,is_stmt,basic_block,
               end_sequence,prologue_end,epilogue_begin,discriminator,file_index) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
        ).use { ps ->
            for (r in cu.lineRows) {
                ps.setLong(1, cuId); ps.setInt(2, r.sequence); ps.setLong(3, r.address); ps.setLong(4, r.endAddress)
                ps.setString(5, r.file); ps.setInt(6, r.line); ps.setInt(7, r.column)
                ps.setInt(8, if (r.isStmt) 1 else 0); ps.setInt(9, if (r.basicBlock) 1 else 0)
                ps.setInt(10, if (r.endSequence) 1 else 0); ps.setInt(11, if (r.prologueEnd) 1 else 0)
                ps.setInt(12, if (r.epilogueBegin) 1 else 0); ps.setLong(13, r.discriminator); ps.setInt(14, r.fileIndex)
                ps.addBatch()
            }
            ps.executeBatch()
        }
        val inlineIds = LongArray(cu.inlines.size)
        conn.prepareStatement(
            "INSERT INTO inlines(cu_id,parent_id,depth,name,call_file,call_line,die_offset) VALUES(?,?,?,?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS,
        ).use { ps ->
            for ((i, inl) in cu.inlines.withIndex()) {
                ps.setLong(1, cuId)
                if (inl.parentIndex >= 0) ps.setLong(2, inlineIds[inl.parentIndex]) else ps.setNull(2, java.sql.Types.INTEGER)
                ps.setInt(3, inl.depth); ps.setString(4, inl.name)
                ps.setString(5, inl.callFile)
                if (inl.callLine != null) ps.setLong(6, inl.callLine) else ps.setNull(6, java.sql.Types.INTEGER)
                ps.setLong(7, inl.dieOffset)
                ps.executeUpdate()
                inlineIds[i] = ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
            }
        }
        conn.prepareStatement("INSERT INTO inline_ranges(inline_id,begin,end) VALUES(?,?,?)").use { ps ->
            for ((i, inl) in cu.inlines.withIndex()) {
                for (r in inl.ranges) { ps.setLong(1, inlineIds[i]); ps.setLong(2, r.begin); ps.setLong(3, r.end); ps.addBatch() }
            }
            ps.executeBatch()
        }
    }

    fun createSnapshot(name: String, modules: List<Triple<Long, Long, Int>>): Long {
        val sid: Long
        conn.prepareStatement("INSERT INTO snapshots(name) VALUES(?)", java.sql.Statement.RETURN_GENERATED_KEYS).use { ps ->
            ps.setString(1, name); ps.executeUpdate()
            sid = ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
        }
        conn.prepareStatement("INSERT INTO snapshot_modules(snapshot_id,module_version_id,load_base,generation) VALUES(?,?,?,?)").use { ps ->
            for ((mv, base, gen) in modules) {
                ps.setLong(1, sid); ps.setLong(2, mv); ps.setLong(3, base); ps.setInt(4, gen)
                ps.addBatch()
            }
            ps.executeBatch()
        }
        return sid
    }

    fun saveCrashRecord(snapshotId: Long, addressesText: String, resultsJson: String): Long =
        conn.prepareStatement(
            "INSERT INTO crash_records(snapshot_id,addresses_text,results_json) VALUES(?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS,
        ).use { ps ->
            ps.setLong(1, snapshotId); ps.setString(2, addressesText); ps.setString(3, resultsJson)
            ps.executeUpdate()
            ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
        }
}
