package compass.db

import compass.dwarf.DwarfIndex
import compass.resolve.ModuleSnapshot
import kotlinx.serialization.json.Json
import java.sql.ResultSet

data class DebugVersionRow(
    val id: Long,
    val fileName: String,
    val buildId: String?,
    val sha256: String,
    val elfClass: String,
    val endian: String,
    val machine: Int,
    val dwarfVersions: String,
    val cuCount: Int,
    val sectionCount: Int,
    val hasDwo: Boolean,
    val warnings: String,
    val importedAt: Long
)

data class SessionRow(val id: Long, val title: String, val createdAt: Long)

data class SessionModuleRow(
    val id: Long,
    val sessionId: Long,
    val versionId: Long,
    val moduleName: String,
    val buildId: String?,
    val loadBias: Long,
    val generation: Int,
    val segment: Int
)

class Repository(private val db: Database) {
    private val json = Json { ignoreUnknownKeys = true }

    fun insertVersion(
        fileName: String,
        buildId: String?,
        sha256: String,
        elfClass: String,
        endian: String,
        machine: Int,
        dwarfVersions: List<Int>,
        cuCount: Int,
        sectionCount: Int,
        hasDwo: Boolean,
        warnings: List<String>
    ): Long {
        val now = System.currentTimeMillis()
        db.conn.prepareStatement(
            """INSERT INTO debug_file_versions
               (file_name, build_id, sha256, elf_class, endian, machine, dwarf_versions,
                cu_count, section_count, has_dwo, warnings, imported_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"""
        ).use { ps ->
            ps.setString(1, fileName); ps.setString(2, buildId); ps.setString(3, sha256)
            ps.setString(4, elfClass); ps.setString(5, endian); ps.setInt(6, machine)
            ps.setString(7, dwarfVersions.joinToString(",")); ps.setInt(8, cuCount)
            ps.setInt(9, sectionCount); ps.setInt(10, if (hasDwo) 1 else 0)
            ps.setString(11, json.encodeToString(warnings)); ps.setLong(12, now)
            ps.executeUpdate()
            val rs = ps.generatedKeys
            rs.next(); return rs.getLong(1)
        }
    }

    fun findVersionBySha(sha: String): DebugVersionRow? =
        db.conn.prepareStatement("SELECT * FROM debug_file_versions WHERE sha256=? ORDER BY id").use { ps ->
            ps.setString(1, sha); ps.executeQuery().use { rs -> if (rs.next()) rs.toVersion() else null }
        }

    fun listVersions(): List<DebugVersionRow> =
        db.conn.createStatement().use { st ->
            st.executeQuery("SELECT * FROM debug_file_versions ORDER BY id").mapRows { it.toVersion() }
        }

    fun createSession(title: String): Long {
        db.conn.prepareStatement("INSERT INTO crash_sessions(title, created_at) VALUES(?,?)")
            .use { ps ->
                ps.setString(1, title.ifEmpty { "崩溃记录 ${System.currentTimeMillis()}" })
                ps.setLong(2, System.currentTimeMillis())
                ps.executeUpdate()
                ps.generatedKeys.next(); return ps.generatedKeys.getLong(1)
            }
    }

    fun listSessions(): List<SessionRow> =
        db.conn.createStatement().use { st ->
            st.executeQuery("SELECT * FROM crash_sessions ORDER BY id").mapRows {
                SessionRow(it.getLong(1), it.getString(2), it.getLong(3))
            }
        }

    fun addModule(
        sessionId: Long, versionId: Long, moduleName: String, buildId: String?,
        loadBias: Long, generation: Int, segment: Int
    ): Long {
        db.conn.prepareStatement(
            """INSERT OR REPLACE INTO session_modules
               (session_id, version_id, module_name, build_id, load_bias, generation, segment)
               VALUES (?,?,?,?,?,?,?)"""
        ).use { ps ->
            ps.setLong(1, sessionId); ps.setLong(2, versionId); ps.setString(3, moduleName)
            ps.setString(4, buildId); ps.setLong(5, loadBias); ps.setInt(6, generation)
            ps.setInt(7, segment)
            ps.executeUpdate()
            ps.generatedKeys.next(); return ps.generatedKeys.getLong(1)
        }
    }

    fun listModules(sessionId: Long): List<SessionModuleRow> =
        db.conn.prepareStatement(
            "SELECT * FROM session_modules WHERE session_id=? ORDER BY module_name, generation"
        ).use { ps ->
            ps.setLong(1, sessionId)
            ps.executeQuery().mapRows {
                SessionModuleRow(
                    it.getLong(1), it.getLong(2), it.getLong(3), it.getString(4),
                    it.getString(5), it.getLong(6), it.getInt(7), it.getInt(8)
                )
            }
        }

    fun saveQuery(sessionId: Long, runtime: Long, ordinal: Int, resultJson: String) {
        db.conn.prepareStatement(
            """INSERT INTO address_queries(session_id, runtime_address, ordinal, result_json, queried_at)
               VALUES (?,?,?,?,?)"""
        ).use { ps ->
            ps.setLong(1, sessionId); ps.setLong(2, runtime); ps.setInt(3, ordinal)
            ps.setString(4, resultJson); ps.setLong(5, System.currentTimeMillis())
            ps.executeUpdate()
        }
    }

    private fun <T> ResultSet.mapRows(fn: (ResultSet) -> T): List<T> {
        val out = ArrayList<T>()
        while (next()) out.add(fn(this))
        return out
    }

    private fun ResultSet.toVersion() = DebugVersionRow(
        getLong("id"), getString("file_name"), getString("build_id"), getString("sha256"),
        getString("elf_class"), getString("endian"), getInt("machine"),
        getString("dwarf_versions"), getInt("cu_count"), getInt("section_count"),
        getInt("has_dwo") == 1, getString("warnings"), getLong("imported_at")
    )

    fun storeBlobQuiet(versionId: Long, bytes: ByteArray) {
        db.conn.prepareStatement("INSERT OR REPLACE INTO debug_blobs(version_id, bytes) VALUES(?,?)")
            .use { ps -> ps.setLong(1, versionId); ps.setBytes(2, bytes); ps.executeUpdate() }
    }

    fun loadBlobQuiet(versionId: Long): ByteArray? =
        db.conn.prepareStatement("SELECT bytes FROM debug_blobs WHERE version_id=?").use { ps ->
            ps.setLong(1, versionId)
            ps.executeQuery().use { if (it.next()) it.getBytes(1) else null }
        }
}
