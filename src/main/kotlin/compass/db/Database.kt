package compass.db

import compass.dwarf.*
import compass.elf.ElfFile
import java.nio.file.Files
import java.nio.file.Path
import java.sql.Connection
import java.sql.DriverManager
import java.time.Instant

/** SQLite-backed persistence. The registry remains the query authority;
 *  the database preserves import versions, digests, parsed artifacts and
 *  immutable crash snapshots/logs across restarts. */
class Database(path: String) {
    val conn: Connection

    init {
        if (path != ":memory:") Files.createDirectories(Path.of(path).toAbsolutePath().parent)
        conn = DriverManager.getConnection("jdbc:sqlite:$path")
        conn.createStatement().execute("PRAGMA foreign_keys = ON")
        conn.createStatement().execute("PRAGMA journal_mode = WAL")
        conn.createStatement().use { it.executeUpdate(Schema.CREATE) }
    }

    data class StoredImport(
        val id: Long, val path: String?, val sha256: String, val versionLabel: String,
        val importedAt: String, val blob: ByteArray, val isDwo: Boolean
    )

    fun findImportBySha(sha: String): StoredImport? {
        conn.prepareStatement(
            "SELECT id,path,sha256,version_label,imported_at,elf_blob,is_dwo FROM debug_import WHERE sha256=?"
        ).use { ps ->
            ps.setString(1, sha)
            ps.executeQuery().use { rs ->
                if (!rs.next()) return null
                return StoredImport(rs.getLong(1), rs.getString(2), rs.getString(3),
                    rs.getString(4), rs.getString(5), rs.getBytes(6), rs.getInt(7) != 0)
            }
        }
    }

    /** Insert a new immutable import version. Returns assigned id. */
    fun insertImport(elf: ElfFile, path: String?, label: String, isDwo: Boolean, assignedId: Long): Long {
        conn.prepareStatement("""
            INSERT INTO debug_import(id,path,sha256,size,imported_at,version_label,elf_blob,is_dwo)
            VALUES(?,?,?,?,?,?,?,?)
        """).use { ps ->
            ps.setLong(1, assignedId)
            ps.setString(2, path)
            ps.setString(3, elf.fileSha256)
            ps.setLong(4, elf.bytes.size.toLong())
            ps.setString(5, Instant.now().toString())
            ps.setString(6, label)
            ps.setBytes(7, elf.bytes)
            ps.setInt(8, if (isDwo) 1 else 0)
            ps.executeUpdate()
        }
        return assignedId
    }

    fun allImports(): List<StoredImport> {
        val out = ArrayList<StoredImport>()
        conn.prepareStatement(
            "SELECT id,path,sha256,version_label,imported_at,elf_blob,is_dwo FROM debug_import ORDER BY id"
        ).use { ps ->
            ps.executeQuery().use { rs ->
                while (rs.next()) out.add(StoredImport(rs.getLong(1), rs.getString(2), rs.getString(3),
                    rs.getString(4), rs.getString(5), rs.getBytes(6), rs.getInt(7) != 0))
            }
        }
        return out
    }

    fun persistParsed(parsed: ParsedFile) {
        val autoCommit = conn.autoCommit
        conn.autoCommit = false
        try {
            // sections
            conn.prepareStatement("""INSERT INTO section_digest
                (import_id,name,type,addr,file_offset,size,sha256) VALUES(?,?,?,?,?,?,?)""").use { ps ->
                for (s in parsed.elf.sections) {
                    ps.setLong(1, parsed.id)
                    ps.setString(2, s.name); ps.setInt(3, s.type); ps.setLong(4, s.addr)
                    ps.setLong(5, s.offset); ps.setLong(6, s.size)
                    ps.setString(7, s.sha256)
                    ps.addBatch()
                }
                ps.executeBatch()
            }
            // issues
            conn.prepareStatement(
                "INSERT INTO parse_issue(import_id,severity,location,message) VALUES(?,?,?,?)"
            ).use { ps ->
                for (i in parsed.allIssues()) {
                    ps.setLong(1, parsed.id); ps.setString(2, i.severity)
                    ps.setString(3, i.where); ps.setString(4, i.message); ps.addBatch()
                }
                ps.executeBatch()
            }
            // CUs
            conn.prepareStatement("""INSERT INTO comp_unit
                (import_id,unit_offset,next_offset,version,unit_type,address_size,name,dwo_id,
                 is_skeleton,is_split,stmt_list,linked_import_id,linked_unit_offset)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""").use { ps ->
                for (u in parsed.units) {
                    ps.setLong(1, parsed.id); ps.setLong(2, u.unitOffset); ps.setLong(3, u.nextOffset)
                    ps.setInt(4, u.version); ps.setInt(5, u.unitType); ps.setInt(6, u.addressSize)
                    ps.setString(7, u.name()); ps.setString(8, u.dwoId?.toString(16))
                    ps.setInt(9, if (u.isSkeleton) 1 else 0); ps.setInt(10, if (u.isSplit) 1 else 0)
                    val stmt = (u.root.attr(DW.AT_stmt_list)?.value as? FormValue.SectionOffset)?.value
                    if (stmt == null) ps.setNull(11, java.sql.Types.INTEGER) else ps.setLong(11, stmt)
                    if (u.linkedDwoFileId == null) ps.setNull(12, java.sql.Types.INTEGER)
                    else ps.setLong(12, u.linkedDwoFileId!!)
                    if (u.linkedDwoUnitOffset == null) ps.setNull(13, java.sql.Types.INTEGER)
                    else ps.setLong(13, u.linkedDwoUnitOffset!!)
                    ps.addBatch()
                }
                ps.executeBatch()
            }
            persistScopes(parsed)
            persistLine(parsed)
            conn.commit()
        } catch (e: Exception) {
            conn.rollback(); throw e
        } finally {
            conn.autoCommit = autoCommit
        }
    }

    private fun persistScopes(parsed: ParsedFile) {
        val scopeIds = HashMap<DieNode, Long>()
        conn.prepareStatement("""INSERT INTO scope_die
            (import_id,unit_offset,die_offset,tag,name,inline_depth,call_file,call_line,call_column)
            VALUES(?,?,?,?,?,?,?,?,?)""").use { ps ->
                var nextId = nextScopeId()
                for (sc in parsed.scopes) {
                    val id = nextId++
                    scopeIds[sc.die] = id
                    val d = sc.die
                    ps.setLong(1, parsed.id); ps.setLong(2, sc.unit.unitOffset)
                    ps.setLong(3, d.offset); ps.setInt(4, d.tag)
                    ps.setString(5, runCatching {
                        compass.dwarf.DwarfNames { fid, off ->
                            parsed.dieAtGlobalOffset(off)?.second
                        }.name(d, sc.unit)
                    }.getOrNull())
                    ps.setInt(6, sc.inlineDepth)
                    ps.setString(7, (d.attr(DW.AT_call_file)?.value as? FormValue.Number)
                        ?.let { "file#${it.value}" })
                    val cl = d.num(DW.AT_call_line); if (cl == null) ps.setNull(8, java.sql.Types.INTEGER) else ps.setLong(8, cl)
                    val cc = d.num(DW.AT_call_column); if (cc == null) ps.setNull(9, java.sql.Types.INTEGER) else ps.setLong(9, cc)
                    ps.addBatch()
                }
                ps.executeBatch()
            }
        conn.prepareStatement("""INSERT INTO die_range
            (scope_id,start_addr,end_addr,segment,zero_length) VALUES(?,?,?,?,?)""").use { ps ->
            for (sc in parsed.scopes) {
                val id = scopeIds.getValue(sc.die)
                for (r in sc.ranges) {
                    ps.setLong(1, id); ps.setLong(2, r.start); ps.setLong(3, r.end)
                    ps.setInt(4, r.segment); ps.setInt(5, if (r.zeroLength) 1 else 0); ps.addBatch()
                }
                ps.executeBatch()
            }
        }
    }

    private fun persistLine(parsed: ParsedFile) {
        val programs = parsed.units.mapNotNull { u ->
            try {
                parsed.lineProgramFor(u)
            } catch (e: Exception) {
                null
            }
        }.distinctBy { it.sectionOffset }
        conn.prepareStatement("""INSERT INTO line_file
            (import_id,stmt_list,file_index,name,directory) VALUES(?,?,?,?,?)""").use { ps ->
            for (lp in programs) for (f in lp.files) {
                ps.setLong(1, parsed.id); ps.setLong(2, lp.sectionOffset)
                ps.setLong(3, f.index); ps.setString(4, f.name); ps.setString(5, f.directory)
                ps.addBatch()
            }
            ps.executeBatch()
        }
        conn.prepareStatement("""INSERT INTO line_row
            (import_id,stmt_list,seq_index,address,file_index,line,column,is_stmt,end_sequence)
            VALUES(?,?,?,?,?,?,?,?,?)""").use { ps ->
            for (lp in programs) for (r in lp.rows) {
                ps.setLong(1, parsed.id); ps.setLong(2, lp.sectionOffset)
                ps.setInt(3, r.sequenceIndex); ps.setLong(4, r.address)
                ps.setLong(5, r.fileIndex); ps.setLong(6, r.line); ps.setLong(7, r.column)
                ps.setInt(8, if (r.isStmt) 1 else 0); ps.setInt(9, if (r.endSequence) 1 else 0)
                ps.addBatch()
            }
            ps.executeBatch()
        }
        conn.prepareStatement("""INSERT INTO line_sequence
            (import_id,stmt_list,seq_index,start_addr,end_addr,segment) VALUES(?,?,?,?,?,?)""").use { ps ->
            for (lp in programs) for (s in lp.sequences) {
                ps.setLong(1, parsed.id); ps.setLong(2, lp.sectionOffset)
                ps.setInt(3, s.index); ps.setLong(4, s.startAddress); ps.setLong(5, s.endAddress)
                ps.setInt(6, s.segment); ps.addBatch()
            }
            ps.executeBatch()
        }
    }

    private fun nextScopeId(): Long =
        conn.createStatement().executeQuery("SELECT COALESCE(MAX(id),0)+1 FROM scope_die")
            .let { it.next(); it.getLong(1) }

    // ----- snapshots -----
    fun createSnapshot(label: String, modules: List<SnapshotModule>): Long {
        val id = conn.createStatement().executeQuery("SELECT COALESCE(MAX(id),0)+1 FROM load_snapshot")
            .let { it.next(); it.getLong(1) }
        conn.prepareStatement(
            "INSERT INTO load_snapshot(id,label,created_at) VALUES(?,?,?)"
        ).use { ps ->
            ps.setLong(1, id); ps.setString(2, label); ps.setString(3, Instant.now().toString())
            ps.executeUpdate()
        }
        conn.prepareStatement("""INSERT INTO snapshot_module
            (snapshot_id,name,import_id,base_addr,generation) VALUES(?,?,?,?,?)""").use { ps ->
            for (m in modules) {
                ps.setLong(1, id); ps.setString(2, m.name); ps.setLong(3, m.fileId)
                ps.setLong(4, m.base); ps.setInt(5, m.generation); ps.addBatch()
            }
            ps.executeBatch()
        }
        return id
    }

    fun loadSnapshots(): List<Triple<Long, String, List<SnapshotModule>>> {
        val rows = ArrayList<Triple<Long, String, List<SnapshotModule>>>()
        conn.createStatement().executeQuery(
            "SELECT id,label,created_at FROM load_snapshot ORDER BY id"
        ).use { rs ->
            while (rs.next()) {
                val id = rs.getLong(1); val label = rs.getString(2)
                val mods = ArrayList<SnapshotModule>()
                conn.prepareStatement("""SELECT name,import_id,base_addr,generation
                    FROM snapshot_module WHERE snapshot_id=? ORDER BY id""").use { ps ->
                    ps.setLong(1, id)
                    ps.executeQuery().use { mr ->
                        while (mr.next()) mods.add(SnapshotModule(mr.getString(1),
                            mr.getLong(2), mr.getLong(3), mr.getInt(4)))
                    }
                }
                rows.add(Triple(id, label, mods))
            }
        }
        return rows
    }

    fun insertQueryLog(snapshotId: Long?, raw: String, q: QueryResult, json: String) {
        conn.prepareStatement("""INSERT INTO query_log
            (created_at,snapshot_id,raw_input,runtime_addr,relative_addr,load_bias,module_name,result_json)
            VALUES(?,?,?,?,?,?,?,?)""").use { ps ->
            ps.setString(1, Instant.now().toString())
            if (snapshotId == null) ps.setNull(2, java.sql.Types.INTEGER) else ps.setLong(2, snapshotId)
            ps.setString(3, raw); ps.setLong(4, q.runtimeAddress); ps.setLong(5, q.relativeAddress)
            if (q.loadBias == null) ps.setNull(6, java.sql.Types.INTEGER) else ps.setLong(6, q.loadBias)
            ps.setString(7, q.moduleName); ps.setString(8, json)
            ps.executeUpdate()
        }
    }

    fun updateLinks() {
        conn.prepareStatement("""UPDATE comp_unit SET linked_import_id=?, linked_unit_offset=?
            WHERE import_id=? AND unit_offset=?""").use { ps ->
            // links are re-derived at registry level; table values recorded at import time
        }
    }
}
