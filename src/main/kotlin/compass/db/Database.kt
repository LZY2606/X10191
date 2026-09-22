package compass.db

import compass.elf.ElfFile
import compass.model.DieNode
import compass.model.LineRow
import compass.model.ParsedDwarf
import java.sql.Connection
import java.sql.DriverManager
import java.sql.Statement

class Database(path: String) {
    val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path")

    init {
        conn.autoCommit = true
        val st = conn.createStatement()
        st.executeUpdate("PRAGMA journal_mode=WAL")
        st.executeUpdate("""
            CREATE TABLE IF NOT EXISTS debug_file(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              imported_at TEXT NOT NULL DEFAULT (datetime('now')),
              version_no INTEGER NOT NULL,
              sha256 TEXT NOT NULL,
              is64 INTEGER NOT NULL,
              machine INTEGER NOT NULL
            )""")
        st.executeUpdate("""
            CREATE TABLE IF NOT EXISTS section(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              file_id INTEGER NOT NULL REFERENCES debug_file(id),
              name TEXT NOT NULL, type INTEGER NOT NULL, addr INTEGER NOT NULL,
              offset INTEGER NOT NULL, size INTEGER NOT NULL,
              sha256 TEXT NOT NULL, data BLOB NOT NULL
            )""")
        st.executeUpdate("""
            CREATE TABLE IF NOT EXISTS cu(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              file_id INTEGER NOT NULL REFERENCES debug_file(id),
              idx INTEGER NOT NULL, offset INTEGER NOT NULL, version INTEGER NOT NULL,
              unit_type INTEGER NOT NULL, addr_size INTEGER NOT NULL,
              name TEXT, comp_dir TEXT, producer TEXT, dwo_name TEXT,
              stmt_list INTEGER, low_pc INTEGER, high_pc INTEGER, high_pc_is_addr INTEGER NOT NULL DEFAULT 0,
              status TEXT NOT NULL
            )""")
        st.executeUpdate("""
            CREATE TABLE IF NOT EXISTS line_row(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              file_id INTEGER NOT NULL REFERENCES debug_file(id),
              cu_id INTEGER NOT NULL REFERENCES cu(id),
              seq INTEGER NOT NULL, address INTEGER NOT NULL, end_address INTEGER NOT NULL,
              segment INTEGER NOT NULL DEFAULT 0,
              file TEXT NOT NULL, line INTEGER NOT NULL, col INTEGER NOT NULL,
              is_stmt INTEGER NOT NULL, basic_block INTEGER NOT NULL,
              prologue_end INTEGER NOT NULL, epilogue_begin INTEGER NOT NULL,
              isa INTEGER NOT NULL, discriminator INTEGER NOT NULL, end_seq INTEGER NOT NULL
            )""")
        st.executeUpdate("CREATE INDEX IF NOT EXISTS idx_line_addr ON line_row(file_id, address)")
        st.executeUpdate("""
            CREATE TABLE IF NOT EXISTS die(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              file_id INTEGER NOT NULL REFERENCES debug_file(id),
              cu_id INTEGER NOT NULL REFERENCES cu(id),
              offset INTEGER NOT NULL, depth INTEGER NOT NULL, tag INTEGER NOT NULL,
              name TEXT, low_pc INTEGER, high_pc INTEGER, high_pc_is_addr INTEGER NOT NULL DEFAULT 0,
              call_file INTEGER, call_line INTEGER, call_column INTEGER,
              abstract_origin INTEGER, spec INTEGER
            )""")
        st.executeUpdate("""
            CREATE TABLE IF NOT EXISTS die_range(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              die_id INTEGER NOT NULL REFERENCES die(id),
              begin INTEGER NOT NULL, end INTEGER NOT NULL, segment INTEGER NOT NULL DEFAULT 0
            )""")
        st.executeUpdate("CREATE INDEX IF NOT EXISTS idx_range ON die_range(begin, end)")
        st.executeUpdate("""
            CREATE TABLE IF NOT EXISTS issue(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              file_id INTEGER NOT NULL REFERENCES debug_file(id),
              section TEXT NOT NULL, offset INTEGER NOT NULL,
              severity TEXT NOT NULL, message TEXT NOT NULL
            )""")
        st.executeUpdate("""
            CREATE TABLE IF NOT EXISTS meta(
              file_id INTEGER NOT NULL REFERENCES debug_file(id),
              key TEXT NOT NULL, value TEXT NOT NULL,
              PRIMARY KEY(file_id, key)
            )""")
        st.executeUpdate("""
            CREATE TABLE IF NOT EXISTS snapshot(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              file_id INTEGER NOT NULL REFERENCES debug_file(id),
              base_address INTEGER NOT NULL,
              generation INTEGER NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )""")
        st.executeUpdate("""
            CREATE TABLE IF NOT EXISTS crash(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              snapshot_id INTEGER NOT NULL REFERENCES snapshot(id),
              file_id INTEGER NOT NULL REFERENCES debug_file(id),
              note TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )""")
        st.executeUpdate("""
            CREATE TABLE IF NOT EXISTS crash_frame(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              crash_id INTEGER NOT NULL REFERENCES crash(id),
              idx INTEGER NOT NULL, address INTEGER NOT NULL
            )""")
        st.close()
    }

    /** Import a parsed ELF+DWARF as a new immutable version. Never mutates older rows. */
    fun importFile(name: String, bytes: ByteArray, elf: ElfFile, parsed: ParsedDwarf): Long {
        conn.autoCommit = false
        try {
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it) }
            val versionNo = queryLong("SELECT COALESCE(MAX(version_no),0)+1 FROM debug_file WHERE name=?", name)
            val fileId: Long
            run {
                val ps = conn.prepareStatement(
                    "INSERT INTO debug_file(name, version_no, sha256, is64, machine) VALUES(?,?,?,?,?)",
                    Statement.RETURN_GENERATED_KEYS)
                ps.setString(1, name); ps.setLong(2, versionNo); ps.setString(3, digest)
                ps.setInt(4, if (elf.is64) 1 else 0); ps.setInt(5, elf.machine)
                ps.executeUpdate()
                fileId = ps.generatedKeys.apply { next() }.getLong(1)
                ps.close()
            }
            val secPs = conn.prepareStatement(
                "INSERT INTO section(file_id,name,type,addr,offset,size,sha256,data) VALUES(?,?,?,?,?,?,?,?)")
            for (s in elf.sections) {
                secPs.setLong(1, fileId); secPs.setString(2, s.name); secPs.setLong(3, s.type)
                secPs.setLong(4, s.addr); secPs.setLong(5, s.offset); secPs.setLong(6, s.size)
                secPs.setString(7, s.sha256); secPs.setBytes(8, s.data)
                secPs.addBatch()
            }
            secPs.executeBatch(); secPs.close()

            val cuPs = conn.prepareStatement(
                "INSERT INTO cu(file_id,idx,offset,version,unit_type,addr_size,name,comp_dir,producer,dwo_name,stmt_list,low_pc,high_pc,high_pc_is_addr,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                Statement.RETURN_GENERATED_KEYS)
            val cuIds = HashMap<Int, Long>()
            for (cu in parsed.units) {
                cuPs.setLong(1, fileId); cuPs.setInt(2, cu.index); cuPs.setLong(3, cu.offset)
                cuPs.setInt(4, cu.version); cuPs.setInt(5, cu.unitType); cuPs.setInt(6, cu.addrSize)
                cuPs.setString(7, cu.name); cuPs.setString(8, cu.compDir); cuPs.setString(9, cu.producer)
                cuPs.setString(10, cu.dwoName)
                if (cu.stmtList != null) cuPs.setLong(11, cu.stmtList) else cuPs.setNull(11, java.sql.Types.INTEGER)
                if (cu.lowPc != null) cuPs.setLong(12, cu.lowPc) else cuPs.setNull(12, java.sql.Types.INTEGER)
                if (cu.highPc != null) cuPs.setLong(13, cu.highPc) else cuPs.setNull(13, java.sql.Types.INTEGER)
                cuPs.setInt(14, if (cu.highPcIsAddress) 1 else 0)
                cuPs.setString(15, cu.status)
                cuPs.executeUpdate()
                cuIds[cu.index] = cuPs.generatedKeys.apply { next() }.getLong(1)
            }
            cuPs.close()

            val linePs = conn.prepareStatement(
                "INSERT INTO line_row(file_id,cu_id,seq,address,end_address,segment,file,line,col,is_stmt,basic_block,prologue_end,epilogue_begin,isa,discriminator,end_seq) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            for (row in parsed.lineRows) {
                val cuId = cuIds[row.cuIndex] ?: continue
                linePs.setLong(1, fileId); linePs.setLong(2, cuId); linePs.setInt(3, row.sequence)
                linePs.setLong(4, row.address); linePs.setLong(5, row.endAddress); linePs.setLong(6, row.segment)
                linePs.setString(7, row.file); linePs.setLong(8, row.line); linePs.setLong(9, row.column)
                linePs.setInt(10, if (row.isStmt) 1 else 0); linePs.setInt(11, if (row.basicBlock) 1 else 0)
                linePs.setInt(12, if (row.prologueEnd) 1 else 0); linePs.setInt(13, if (row.epilogueBegin) 1 else 0)
                linePs.setLong(14, row.isa); linePs.setLong(15, row.discriminator); linePs.setInt(16, if (row.endSequence) 1 else 0)
                linePs.addBatch()
            }
            linePs.executeBatch(); linePs.close()

            val diePs = conn.prepareStatement(
                "INSERT INTO die(file_id,cu_id,offset,depth,tag,name,low_pc,high_pc,high_pc_is_addr,call_file,call_line,call_column,abstract_origin,spec) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                Statement.RETURN_GENERATED_KEYS)
            val rangePs = conn.prepareStatement("INSERT INTO die_range(die_id,begin,end,segment) VALUES(?,?,?,?)")
            for (die in parsed.dies) {
                val cuId = cuIds[die.cuIndex] ?: continue
                diePs.setLong(1, fileId); diePs.setLong(2, cuId); diePs.setLong(3, die.offset)
                diePs.setInt(4, die.depth); diePs.setLong(5, die.tag); diePs.setString(6, die.name)
                if (die.lowPc != null) diePs.setLong(7, die.lowPc) else diePs.setNull(7, java.sql.Types.INTEGER)
                if (die.highPc != null) diePs.setLong(8, die.highPc) else diePs.setNull(8, java.sql.Types.INTEGER)
                diePs.setInt(9, if (die.highPcIsAddress) 1 else 0)
                if (die.callFile != null) diePs.setLong(10, die.callFile) else diePs.setNull(10, java.sql.Types.INTEGER)
                if (die.callLine != null) diePs.setLong(11, die.callLine) else diePs.setNull(11, java.sql.Types.INTEGER)
                if (die.callColumn != null) diePs.setLong(12, die.callColumn) else diePs.setNull(12, java.sql.Types.INTEGER)
                if (die.abstractOrigin != null) diePs.setLong(13, die.abstractOrigin) else diePs.setNull(13, java.sql.Types.INTEGER)
                if (die.specification != null) diePs.setLong(14, die.specification) else diePs.setNull(14, java.sql.Types.INTEGER)
                diePs.executeUpdate()
                val dieId = diePs.generatedKeys.apply { next() }.getLong(1)
                for (rg in die.ranges) {
                    rangePs.setLong(1, dieId); rangePs.setLong(2, rg.begin); rangePs.setLong(3, rg.end)
                    rangePs.setLong(4, rg.segment)
                    rangePs.addBatch()
                }
            }
            diePs.close(); rangePs.executeBatch(); rangePs.close()

            val issuePs = conn.prepareStatement("INSERT INTO issue(file_id,section,offset,severity,message) VALUES(?,?,?,?,?)")
            for (iss in parsed.issues) {
                issuePs.setLong(1, fileId); issuePs.setString(2, iss.section); issuePs.setLong(3, iss.offset)
                issuePs.setString(4, iss.severity); issuePs.setString(5, iss.message)
                issuePs.addBatch()
            }
            issuePs.executeBatch(); issuePs.close()

            val metaPs = conn.prepareStatement("INSERT INTO meta(file_id,key,value) VALUES(?,?,?)")
            for ((k, v) in parsed.tableVersions) {
                metaPs.setLong(1, fileId); metaPs.setString(2, "table.$k"); metaPs.setString(3, v)
                metaPs.addBatch()
            }
            for ((cuIdx, files) in parsed.cuFiles) {
                metaPs.setLong(1, fileId); metaPs.setString(2, "cufiles.$cuIdx")
                metaPs.setString(3, files.joinToString("\n"))
                metaPs.addBatch()
            }
            metaPs.executeBatch(); metaPs.close()

            conn.commit()
            return fileId
        } catch (e: Exception) {
            conn.rollback()
            throw e
        } finally {
            conn.autoCommit = true
        }
    }

    fun queryLong(sql: String, vararg args: Any?): Long {
        val ps = conn.prepareStatement(sql)
        args.forEachIndexed { i, a -> setArg(ps, i + 1, a) }
        val rs = ps.executeQuery()
        val v = if (rs.next()) rs.getLong(1) else 0L
        ps.close()
        return v
    }

    fun <T> query(sql: String, args: List<Any?> = emptyList(), map: (java.sql.ResultSet) -> T): List<T> {
        val ps = conn.prepareStatement(sql)
        args.forEachIndexed { i, a -> setArg(ps, i + 1, a) }
        val rs = ps.executeQuery()
        val out = ArrayList<T>()
        while (rs.next()) out.add(map(rs))
        ps.close()
        return out
    }

    fun execute(sql: String, vararg args: Any?): Long {
        val ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)
        args.forEachIndexed { i, a -> setArg(ps, i + 1, a) }
        ps.executeUpdate()
        val keys = ps.generatedKeys
        val id = if (keys.next()) keys.getLong(1) else -1L
        ps.close()
        return id
    }

    private fun setArg(ps: java.sql.PreparedStatement, i: Int, a: Any?) {
        when (a) {
            null -> ps.setNull(i, java.sql.Types.NULL)
            is Long -> ps.setLong(i, a)
            is Int -> ps.setInt(i, a)
            is String -> ps.setString(i, a)
            is ByteArray -> ps.setBytes(i, a)
            else -> ps.setString(i, a.toString())
        }
    }
}
