package com.linecompass.db

import com.linecompass.compass.AddressResolution
import com.linecompass.dwarf.AddressRange
import com.linecompass.dwarf.CompilationUnit
import com.linecompass.dwarf.DebugFileParser
import com.linecompass.dwarf.LineSequence
import com.linecompass.dwarf.ParsedDebugFile
import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet
import java.sql.Statement

data class StoredDebugFile(
    val id: Long,
    val name: String,
    val sha256: String,
    val versionNo: Int,
    val parsed: ParsedDebugFile,
    val importedAt: Long
)

data class StoredSnapshot(
    val id: Long,
    val name: String,
    val fixed: Boolean,
    val createdAt: Long,
    val loads: List<StoredModuleLoad>
)

data class StoredModuleLoad(
    val id: Long,
    val moduleName: String,
    val debugFileId: Long,
    val baseAddress: Long,
    val generation: Int
)

data class StoredCrash(
    val id: Long,
    val snapshotId: Long?,
    val title: String,
    val createdAt: Long,
    val rawInput: String,
    val resolutionJson: String
)

class Repository(private val dbPath: String) {
    private val conn: Connection

    init {
        Class.forName("org.sqlite.JDBC")
        conn = DriverManager.getConnection("jdbc:sqlite:$dbPath")
        conn.createStatement().use { st ->
            Schema.DDL.trimIndent().split(";").map { it.trim() }.filter { it.isNotEmpty() }.forEach {
                st.execute(it)
            }
        }
        conn.autoCommit = true
    }

    fun close() = conn.close()

    // ---- debug files -------------------------------------------------------

    fun importDebugFile(name: String, bytes: ByteArray, supersedesId: Long? = null): StoredDebugFile {
        val parsed = DebugFileParser.parse(bytes)
        val sha = parsed.fileSummary.substringAfter("sha256=").substringBefore(" ")
        val now = System.currentTimeMillis()
        val nextVersion = (supersedesId?.let { versionOf(it) } ?: latestVersionOfName(name)) + 1
        val id = conn.prepareStatement(
            """INSERT INTO debug_files(name, sha256, size, raw_summary, imported_at, version_no, supersedes_file_id)
               VALUES (?,?,?,?,?,?,?)""", Statement.RETURN_GENERATED_KEYS
        ).use { ps ->
            ps.setString(1, name); ps.setString(2, sha); ps.setLong(3, bytes.size.toLong())
            ps.setString(4, parsed.fileSummary); ps.setLong(5, now)
            ps.setInt(6, nextVersion); if (supersedesId == null) ps.setNull(7, java.sql.Types.INTEGER)
            else ps.setLong(7, supersedesId)
            ps.executeUpdate()
            ps.generatedKeys.use { if (it.next()) it.getLong(1) else error("no id") }
        }
        storeParsed(id, parsed)
        storeRawBytes(id, bytes)
        return StoredDebugFile(id, name, sha, nextVersion, parsed, now)
    }

    private fun versionOf(fileId: Long): Int = conn.prepareStatement(
        "SELECT version_no FROM debug_files WHERE id=?").use { ps ->
        ps.setLong(1, fileId); ps.executeQuery().use { if (it.next()) it.getInt(1) else 0 }
    }

    private fun latestVersionOfName(name: String): Int = conn.prepareStatement(
        "SELECT COALESCE(MAX(version_no),0) FROM debug_files WHERE name=?").use { ps ->
        ps.setString(1, name); ps.executeQuery().use { if (it.next()) it.getInt(1) else 0 }
    }

    private fun storeParsed(fileId: Long, parsed: ParsedDebugFile) {
        conn.autoCommit = false
        try {
            for ((name, blob) in parsed.sections.sections) {
                conn.prepareStatement(
                    """INSERT INTO debug_sections(debug_file_id,name,size,vaddr,summary)
                       VALUES (?,?,?,?,?)""").use { ps ->
                    ps.setLong(1, fileId); ps.setString(2, name)
                    ps.setLong(3, blob.bytes.size.toLong())
                    ps.setString(4, hex(blob.vaddr))
                    ps.setString(5, com.linecompass.io.Hashes.rawSummary(blob.bytes))
                    ps.executeUpdate()
                }
            }
            for (issue in parsed.issues) {
                conn.prepareStatement(
                    """INSERT INTO parse_issues(debug_file_id,section,severity,code,message,offset_value,cu_offset)
                       VALUES (?,?,?,?,?,?,?)""").use { ps ->
                    ps.setLong(1, fileId); ps.setString(2, issue.section)
                    ps.setString(3, issue.severity); ps.setString(4, issue.code)
                    ps.setString(5, issue.message)
                    ps.setString(6, issue.offset?.let(::hex)); ps.setString(7, issue.cuOffset?.let(::hex))
                    ps.executeUpdate()
                }
            }
            val cuIdByKey = HashMap<Long, Long>()
            for (cu in parsed.cus) storeCu(fileId, cu, cuIdByKey)
            for (cu in parsed.cus) storeRanges(fileId, cu, cuIdByKey[cu.offset]!!)
            conn.commit()
        } catch (e: Exception) {
            conn.rollback(); throw e
        } finally {
            conn.autoCommit = true
        }
    }

    private fun storeCu(fileId: Long, cu: CompilationUnit, cuIds: MutableMap<Long, Long>) {
        val id = conn.prepareStatement(
            """INSERT INTO compilation_units(debug_file_id,offset_value,length_value,version,dwarf_64,
               unit_type,kind,address_size,name,comp_dir,producer,dwo_id,split_missing)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", Statement.RETURN_GENERATED_KEYS).use { ps ->
            ps.setLong(1, fileId); ps.setString(2, hex(cu.offset)); ps.setString(3, hex(cu.length))
            ps.setInt(4, cu.version); ps.setInt(5, if (cu.is64BitDwarf) 1 else 0)
            ps.setInt(6, cu.unitType); ps.setString(7, cu.kind.name)
            ps.setInt(8, cu.addressSize); ps.setString(9, cu.name)
            ps.setString(10, cu.compDir); ps.setString(11, cu.producer)
            ps.setString(12, cu.dwoId?.let(::hex)); ps.setInt(13, if (cu.splitMissing) 1 else 0)
            ps.executeUpdate()
            ps.generatedKeys.use { if (it.next()) it.getLong(1) else error("no cu id") }
        }
        cuIds[cu.offset] = id

        for (seq: LineSequence in cu.lineProgram?.sequences ?: emptyList()) {
            val seqId = conn.prepareStatement(
                """INSERT INTO line_sequences(cu_id,start_value,end_value,segment,row_count,table_version)
                   VALUES (?,?,?,?,?,?)""", Statement.RETURN_GENERATED_KEYS).use { ps ->
                ps.setLong(1, id); ps.setString(2, hex(seq.startAddress))
                ps.setString(3, hex(seq.endAddress)); ps.setInt(4, seq.segment)
                ps.setInt(5, seq.rows.size); ps.setInt(6, cu.lineProgram!!.version)
                ps.executeUpdate()
                ps.generatedKeys.use { if (it.next()) it.getLong(1) else error("no seq id") }
            }
            for (row in seq.rows) {
                conn.prepareStatement(
                    """INSERT INTO line_rows(sequence_id,ord,address_value,file_path,line_no,column_no,
                       is_stmt,end_sequence,isa,discriminator) VALUES (?,?,?,?,?,?,?,?,?,?)""").use { ps ->
                    ps.setLong(1, seqId); ps.setInt(2, row.order)
                    ps.setString(3, hex(row.address)); ps.setString(4, row.file.fullPath)
                    ps.setInt(5, row.line); ps.setInt(6, row.column)
                    ps.setInt(7, if (row.isStmt) 1 else 0); ps.setInt(8, if (row.endSequence) 1 else 0)
                    ps.setInt(9, row.isa); ps.setInt(10, row.discriminator)
                    ps.executeUpdate()
                }
            }
        }
    }

    private fun storeRanges(fileId: Long, cu: CompilationUnit, cuRowId: Long) {
        for (range in cu.ranges) {
            conn.prepareStatement(
                """INSERT INTO address_ranges(debug_file_id,cu_id,die_offset,segment,start_value,end_value,
                   zero_length,kind,explicit_priority) VALUES (?,?,?,?,?,?,?,?,?)""").use { ps ->
                ps.setLong(1, fileId); ps.setLong(2, cuRowId)
                ps.setString(3, range.die?.offset?.let(::hex))
                ps.setInt(4, range.segment); ps.setString(5, hex(range.start))
                ps.setString(6, hex(range.end)); ps.setInt(7, if (range.zeroLength) 1 else 0)
                ps.setString(8, range.kind.name); ps.setInt(9, range.explicitPriority)
                ps.executeUpdate()
            }
        }
    }

    fun listDebugFiles(): List<StoredDebugFile> {
        val out = mutableListOf<StoredDebugFile>()
        conn.createStatement().executeQuery(
            "SELECT id,name,sha256,version_no,imported_at FROM debug_files ORDER BY id"
        ).use { rs -> while (rs.next()) out += loadStored(rs) }
        return out
    }

    fun getDebugFile(id: Long): StoredDebugFile? {
        conn.prepareStatement("SELECT id,name,sha256,version_no,imported_at FROM debug_files WHERE id=?"
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs -> return if (rs.next()) loadStored(rs) else null }
        }
    }

    private fun loadStored(rs: ResultSet): StoredDebugFile {
        val id = rs.getLong("id")
        val bytes = loadRawBytes(id) ?: ByteArray(0)
        val parsed = DebugFileParser.parse(bytes)
        return StoredDebugFile(id, rs.getString("name"), rs.getString("sha256"),
            rs.getInt("version_no"), parsed, rs.getLong("imported_at"))
    }

    // Raw bytes live in a sidecar content store keyed by debug file id; the DB
    // keeps fingerprints + parsed artifacts so crashes stay resolvable even if
    // the sidecar is archived.
    private fun contentPath(id: Long) = "$dbPath.content/$id.bin"

    fun storeRawBytes(id: Long, bytes: ByteArray) {
        val f = java.io.File(contentPath(id))
        f.parentFile.mkdirs()
        f.writeBytes(bytes)
    }

    private fun loadRawBytes(id: Long): ByteArray? = java.io.File(contentPath(id)).let {
        if (it.exists()) it.readBytes() else null
    }

    fun sectionsOf(fileId: Long): List<Triple<String, Long, String>> =
        conn.prepareStatement("SELECT name,size,summary FROM debug_sections WHERE debug_file_id=? ORDER BY name"
        ).use { ps ->
            ps.setLong(1, fileId)
            val out = mutableListOf<Triple<String, Long, String>>()
            ps.executeQuery().use { rs ->
                while (rs.next()) out += Triple(rs.getString(1), rs.getLong(2), rs.getString(3))
            }
            out
        }

    // ---- snapshots ---------------------------------------------------------

    fun createSnapshot(name: String, fixed: Boolean, loads: List<Triple<String, Long, Long>>): Long {
        val now = System.currentTimeMillis()
        val id = conn.prepareStatement(
            "INSERT INTO load_snapshots(name,created_at,fixed) VALUES (?,?,?)",
            Statement.RETURN_GENERATED_KEYS).use { ps ->
            ps.setString(1, name); ps.setLong(2, now); ps.setInt(3, if (fixed) 1 else 0)
            ps.executeUpdate(); ps.generatedKeys.use { if (it.next()) it.getLong(1) else error("no snapshot id") }
        }
        loads.forEachIndexed { index, (moduleName, debugFileId, base) ->
            conn.prepareStatement(
                """INSERT INTO module_loads(snapshot_id,module_name,debug_file_id,base_address,generation)
                   VALUES (?,?,?,?,?)""").use { ps ->
                ps.setLong(1, id); ps.setString(2, moduleName); ps.setLong(3, debugFileId)
                ps.setString(4, hex(base)); ps.setInt(5, index + 1)
                ps.executeUpdate()
            }
        }
        return id
    }

    fun listSnapshots(): List<StoredSnapshot> {
        val ids = mutableListOf<Long>()
        conn.createStatement().executeQuery("SELECT id FROM load_snapshots ORDER BY id").use { rs ->
            while (rs.next()) ids += rs.getLong(1)
        }
        return ids.map { getSnapshot(it)!! }
    }

    fun getSnapshot(id: Long): StoredSnapshot? {
        conn.prepareStatement("SELECT name,created_at,fixed FROM load_snapshots WHERE id=?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                if (!rs.next()) return null
                val loads = mutableListOf<StoredModuleLoad>()
                conn.prepareStatement(
                    "SELECT id,module_name,debug_file_id,base_address,generation FROM module_loads WHERE snapshot_id=? ORDER BY generation"
                ).use { q ->
                    q.setLong(1, id)
                    q.executeQuery().use { lrs ->
                        while (lrs.next()) loads += StoredModuleLoad(lrs.getLong(1),
                            lrs.getString(2), lrs.getLong(3), parseHex(lrs.getString(4)), lrs.getInt(5))
                    }
                }
                return StoredSnapshot(id, rs.getString(1), rs.getInt(3) == 1, rs.getLong(2), loads)
            }
        }
    }

    // ---- crashes -----------------------------------------------------------

    fun saveCrash(snapshotId: Long?, title: String, rawInput: String, json: String): Long {
        val id = conn.prepareStatement(
            "INSERT INTO crashes(snapshot_id,title,created_at,raw_input,resolution_json) VALUES (?,?,?,?,?)",
            Statement.RETURN_GENERATED_KEYS).use { ps ->
            if (snapshotId == null) ps.setNull(1, java.sql.Types.INTEGER) else ps.setLong(1, snapshotId)
            ps.setString(2, title); ps.setLong(3, System.currentTimeMillis())
            ps.setString(4, rawInput); ps.setString(5, json)
            ps.executeUpdate(); ps.generatedKeys.use { if (it.next()) it.getLong(1) else error("no crash id") }
        }
        return id
    }

    fun listCrashes(): List<StoredCrash> {
        val out = mutableListOf<StoredCrash>()
        conn.createStatement().executeQuery(
            "SELECT id,snapshot_id,title,created_at,raw_input,resolution_json FROM crashes ORDER BY id"
        ).use { rs ->
            while (rs.next()) {
                val snap = rs.getLong("snapshot_id")
                out += StoredCrash(rs.getLong(1), if (rs.wasNull()) null else snap,
                    rs.getString(3), rs.getLong(4), rs.getString(5), rs.getString(6))
            }
        }
        return out
    }

    companion object {
        fun hex(v: Long): String = "0x" + java.lang.Long.toUnsignedString(v, 16)
        fun parseHex(s: String): Long = java.lang.Long.parseUnsignedLong(
            s.removePrefix("0x").removePrefix("0X"), 16)
    }
}
