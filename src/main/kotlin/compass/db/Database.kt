package compass.db

import compass.dwarf.*
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager

fun sha256Hex(data: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

class Database(path: String) {
    val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path")

    init {
        conn.createStatement().use { st ->
            st.executeUpdate("PRAGMA journal_mode=WAL")
            st.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS debug_file(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sha256 TEXT NOT NULL,
              name TEXT NOT NULL,
                  imported_at TEXT NOT NULL DEFAULT (datetime('now')),
                  link_base INTEGER NOT NULL DEFAULT 0,
                  priority INTEGER NOT NULL DEFAULT 0,
                  notes TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS section(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  file_id INTEGER NOT NULL REFERENCES debug_file(id),
                  name TEXT NOT NULL,
                  offset INTEGER NOT NULL,
                  size INTEGER NOT NULL,
                  addr INTEGER NOT NULL,
                  sha256 TEXT NOT NULL,
                  data BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS compile_unit(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  file_id INTEGER NOT NULL REFERENCES debug_file(id),
                  cu_offset INTEGER NOT NULL,
                  version INTEGER NOT NULL,
                  dwarf64 INTEGER NOT NULL,
                  unit_type INTEGER,
                  addr_size INTEGER NOT NULL,
                  name TEXT NOT NULL,
                  comp_dir TEXT,
                  producer TEXT,
                  dwo_name TEXT,
                  is_skeleton INTEGER NOT NULL,
                  line_version INTEGER,
                  warnings TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS line_row(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  cu_id INTEGER NOT NULL REFERENCES compile_unit(id),
                  seq INTEGER NOT NULL,
                  row_index INTEGER NOT NULL,
                  address INTEGER NOT NULL,
                  file TEXT NOT NULL,
                  line INTEGER NOT NULL,
                  col INTEGER NOT NULL,
                  is_stmt INTEGER NOT NULL,
                  end_seq INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_line_row ON line_row(cu_id, seq, address);
                CREATE TABLE IF NOT EXISTS function(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  cu_id INTEGER NOT NULL REFERENCES compile_unit(id),
                  name TEXT NOT NULL,
                  die_offset INTEGER NOT NULL,
                  depth INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS func_range(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  function_id INTEGER NOT NULL REFERENCES function(id),
                  start INTEGER NOT NULL,
                  end INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_func_range ON func_range(start, end);
                CREATE TABLE IF NOT EXISTS inline_site(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  function_id INTEGER NOT NULL REFERENCES function(id),
                  name TEXT NOT NULL,
                  call_file TEXT,
                  call_line INTEGER,
                  call_col INTEGER,
                  depth INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS inline_range(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  inline_id INTEGER NOT NULL REFERENCES inline_site(id),
                  start INTEGER NOT NULL,
                  end INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS load_snapshot(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  module TEXT NOT NULL,
                  base_address INTEGER NOT NULL,
                  generation INTEGER NOT NULL,
                  note TEXT NOT NULL DEFAULT '',
                  created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS crash_record(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  file_id INTEGER NOT NULL REFERENCES debug_file(id),
                  snapshot_id INTEGER REFERENCES load_snapshot(id),
                  module TEXT NOT NULL,
                  address INTEGER NOT NULL,
                  result_json TEXT NOT NULL,
                  created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                """.trimIndent()
            )
        }
    }

    private fun <T> tx(block: () -> T): T {
        conn.autoCommit = false
        try {
            val v = block()
            conn.commit()
            return v
        } catch (e: Exception) {
            conn.rollback()
            throw e
        } finally {
            conn.autoCommit = true
        }
    }

    /** Imports a parsed debug file as a new immutable version. Existing versions/crash records are untouched. */
    fun importFile(name: String, bytes: ByteArray, elf: ElfFile, parsed: ParsedDebugFile, priority: Int = 0): Long = tx {
        val digest = sha256Hex(bytes)
        val fileId: Long
        conn.prepareStatement(
            "INSERT INTO debug_file(sha256,name,link_base,priority,notes) VALUES(?,?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS
        ).use { ps ->
            ps.setString(1, digest); ps.setString(2, name); ps.setLong(3, elf.linkTimeBase)
            ps.setInt(4, priority); ps.setString(5, parsed.warnings.joinToString("\n"))
            ps.executeUpdate()
            fileId = ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
        }
        for (s in elf.sections) {
            conn.prepareStatement("INSERT INTO section(file_id,name,offset,size,addr,sha256,data) VALUES(?,?,?,?,?,?,?)").use { ps ->
                ps.setLong(1, fileId); ps.setString(2, s.name); ps.setLong(3, s.offset); ps.setLong(4, s.size)
                ps.setLong(5, s.addr); ps.setString(6, sha256Hex(s.data)); ps.setBytes(7, s.data)
                ps.executeUpdate()
            }
        }
        for (cu in parsed.cus) {
            val cuId: Long
            conn.prepareStatement(
                "INSERT INTO compile_unit(file_id,cu_offset,version,dwarf64,unit_type,addr_size,name,comp_dir,producer,dwo_name,is_skeleton,line_version,warnings) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                java.sql.Statement.RETURN_GENERATED_KEYS
            ).use { ps ->
                ps.setLong(1, fileId); ps.setLong(2, cu.cuOffset); ps.setInt(3, cu.version)
                ps.setInt(4, if (cu.dwarf64) 1 else 0)
                if (cu.unitType != null) ps.setInt(5, cu.unitType) else ps.setNull(5, java.sql.Types.INTEGER)
                ps.setInt(6, cu.addrSize); ps.setString(7, cu.name); ps.setString(8, cu.compDir)
                ps.setString(9, cu.producer); ps.setString(10, cu.dwoName)
                ps.setInt(11, if (cu.isSkeleton) 1 else 0)
                if (cu.lineProgram != null) ps.setInt(12, cu.lineProgram.version) else ps.setNull(12, java.sql.Types.INTEGER)
                ps.setString(13, cu.warnings.joinToString("\n"))
                ps.executeUpdate()
                cuId = ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
            }
            cu.lineProgram?.rows?.forEachIndexed { idx, row ->
                conn.prepareStatement("INSERT INTO line_row(cu_id,seq,row_index,address,file,line,col,is_stmt,end_seq) VALUES(?,?,?,?,?,?,?,?,?)").use { ps ->
                    ps.setLong(1, cuId); ps.setInt(2, row.sequence); ps.setInt(3, idx); ps.setLong(4, row.address)
                    ps.setString(5, row.fileName); ps.setLong(6, row.line); ps.setLong(7, row.column)
                    ps.setInt(8, if (row.isStmt) 1 else 0); ps.setInt(9, if (row.endSequence) 1 else 0)
                    ps.executeUpdate()
                }
            }
            for (fn in cu.functions) {
                val fnId: Long
                conn.prepareStatement("INSERT INTO function(cu_id,name,die_offset,depth) VALUES(?,?,?,?)", java.sql.Statement.RETURN_GENERATED_KEYS).use { ps ->
                    ps.setLong(1, cuId); ps.setString(2, fn.name); ps.setLong(3, fn.offset); ps.setInt(4, fn.depth)
                    ps.executeUpdate()
                    fnId = ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
                }
                for (rg in fn.ranges) {
                    conn.prepareStatement("INSERT INTO func_range(function_id,start,end) VALUES(?,?,?)").use { ps ->
                        ps.setLong(1, fnId); ps.setLong(2, rg.start); ps.setLong(3, rg.end); ps.executeUpdate()
                    }
                }
                for (inl in fn.inlines) {
                    val inlId: Long
                    conn.prepareStatement("INSERT INTO inline_site(function_id,name,call_file,call_line,call_col,depth) VALUES(?,?,?,?,?,?)", java.sql.Statement.RETURN_GENERATED_KEYS).use { ps ->
                        ps.setLong(1, fnId); ps.setString(2, inl.name); ps.setString(3, inl.callFile)
                        if (inl.callLine != null) ps.setLong(4, inl.callLine) else ps.setNull(4, java.sql.Types.BIGINT)
                        if (inl.callColumn != null) ps.setLong(5, inl.callColumn) else ps.setNull(5, java.sql.Types.BIGINT)
                        ps.setInt(6, inl.depth)
                        ps.executeUpdate()
                        inlId = ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
                    }
                    for (rg in inl.ranges) {
                        conn.prepareStatement("INSERT INTO inline_range(inline_id,start,end) VALUES(?,?,?)").use { ps ->
                            ps.setLong(1, inlId); ps.setLong(2, rg.start); ps.setLong(3, rg.end); ps.executeUpdate()
                        }
                    }
                }
            }
        }
        fileId
    }

    fun addSnapshot(module: String, base: Long, generation: Int, note: String = ""): Long {
        conn.prepareStatement("INSERT INTO load_snapshot(module,base_address,generation,note) VALUES(?,?,?,?)", java.sql.Statement.RETURN_GENERATED_KEYS).use { ps ->
            ps.setString(1, module); ps.setLong(2, base); ps.setInt(3, generation); ps.setString(4, note)
            ps.executeUpdate()
            return ps.generatedKeys.use { rs -> rs.next(); rs.getLong(1) }
        }
    }

    fun saveCrashRecord(fileId: Long, snapshotId: Long?, module: String, address: Long, resultJson: String) {
        conn.prepareStatement("INSERT INTO crash_record(file_id,snapshot_id,module,address,result_json) VALUES(?,?,?,?,?)").use { ps ->
            ps.setLong(1, fileId)
            if (snapshotId != null) ps.setLong(2, snapshotId) else ps.setNull(2, java.sql.Types.BIGINT)
            ps.setString(3, module); ps.setLong(4, address); ps.setString(5, resultJson)
            ps.executeUpdate()
        }
    }

    fun query(sql: String, vararg args: Any?, map: (java.sql.ResultSet) -> Unit) {
        conn.prepareStatement(sql).use { ps ->
            args.forEachIndexed { i, a ->
                when (a) {
                    is Long -> ps.setLong(i + 1, a)
                    is Int -> ps.setInt(i + 1, a)
                    is String -> ps.setString(i + 1, a)
                    null -> ps.setNull(i + 1, java.sql.Types.VARCHAR)
                    else -> ps.setObject(i + 1, a)
                }
            }
            ps.executeQuery().use { rs -> while (rs.next()) map(rs) }
        }
    }
}
