package com.compass.store

import com.compass.dwarf.*
import org.sqlite.SQLiteException
import java.sql.Connection

data class VersionRow(val id: Long, val label: String, val createdAt: Long, val note: String?)
data class CrashRow(val id: Long, val versionId: Long, val label: String, val createdAt: Long)
data class ModuleLoad(val id: Long, val crashId: Long, val generation: Int, val moduleName: String,
                      val fileSha: String?, val runtimeBase: Long, val linkBase: Long, val bias: Long,
                      val createdAt: Long)

/**
 * In-memory parsed state per version, backed by raw bytes in SQLite. New
 * imports append a version; crashes pin the version they were created with.
 */
class VersionBundle(
    val versionId: Long,
    val files: List<ImportedFile>,
    val merged: ParsedDebug,
    val dwoBundles: List<ParsedDebug>
)

data class ImportedFile(val fileId: Long, val filename: String, val role: String,
                        val elf: ElfFile, val parsed: ParsedDebug, val bytes: ByteArray,
                        val summary: ByteSummary)

class Repository(private val db: Database) {
    private val conn: Connection get() = db.conn
    val bundles = linkedMapOf<Long, VersionBundle>()

    @Synchronized
    fun versions(): List<VersionRow> {
        conn.createStatement().use { st ->
            st.executeQuery("SELECT id, label, created_at, note FROM versions ORDER BY id").use { rs ->
                val out = mutableListOf<VersionRow>()
                while (rs.next()) out += VersionRow(rs.getLong(1), rs.getString(2), rs.getLong(3), rs.getString(4))
                return out
            }
        }
    }

    @Synchronized
    fun createVersion(label: String, note: String? = null): Long {
        val now = System.currentTimeMillis()
        conn.prepareStatement("INSERT INTO versions(label, created_at, note) VALUES(?,?,?)")
            .use { ps -> ps.setString(1, label); ps.setLong(2, now); ps.setString(3, note); ps.executeUpdate() }
        return conn.createStatement().executeQuery("SELECT last_insert_rowid()").use { it.getLong(1) }
    }

    @Synchronized
    fun importFile(versionId: Long, filename: String, bytes: ByteArray, role: String): ImportedFile {
        val elf = ElfFile(bytes)
        val parsed = Dwarf.parse(elf)
        val summary = ByteDigest.summary(bytes)
        val now = System.currentTimeMillis()
        val fileId = conn.prepareStatement(
            """INSERT INTO debug_files(version_id, filename, role, size, sha256, head16, tail16,
               elf_class, machine, data, imported_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)"""
        ).use { ps ->
            ps.setLong(1, versionId); ps.setString(2, filename); ps.setString(3, role)
            ps.setLong(4, summary.size.toLong()); ps.setString(5, summary.sha256)
            ps.setString(6, summary.head16); ps.setString(7, summary.tail16)
            ps.setString(8, if (elf.is64) "ELF64" else "ELF32")
            ps.setInt(9, elf.machine)
            ps.setBytes(10, bytes); ps.setLong(11, now)
            ps.executeUpdate()
            conn.createStatement().executeQuery("SELECT last_insert_rowid()").use { it.getLong(1) }
        }
        conn.prepareStatement(
            """INSERT INTO sections(file_id, name, type, addr, file_offset, size, addralign)
               VALUES(?,?,?,?,?,?,?)"""
        ).use { ps ->
            for (s in elf.sections) {
                ps.setLong(1, fileId); ps.setString(2, s.name); ps.setInt(3, s.type)
                ps.setString(4, "0x${s.addr.toULong().toString(16)}")
                ps.setString(5, "0x${s.fileOffset.toULong().toString(16)}")
                ps.setString(6, "0x${s.size.toULong().toString(16)}")
                ps.setString(7, "0x${s.addralign.toULong().toString(16)}")
                ps.addBatch()
            }
            ps.executeBatch()
        }
        persistCus(fileId, parsed)
        rebuildBundle(versionId)
        return ImportedFile(fileId, filename, role, elf, parsed, bytes, summary)
    }

    private fun persistCus(fileId: Long, parsed: ParsedDebug) {
        conn.prepareStatement(
            """INSERT INTO cus(file_id, cu_offset, version, unit_type, is_split, dwo_id, name,
               comp_dir, low_pc, ranges_json, dies_json, line_json, issues_json, dwo_resolved)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
        ).use { ps ->
            for (cu in parsed.cus) {
                ps.setLong(1, fileId)
                ps.setString(2, "0x${cu.offset.toULong().toString(16)}")
                ps.setInt(3, cu.version); ps.setInt(4, cu.unitType)
                ps.setInt(5, if (cu.isSplit) 1 else 0)
                ps.setString(6, cu.dwoId?.let { "0x${it.toULong().toString(16)}" })
                ps.setString(7, cu.name); ps.setString(8, cu.compDir)
                ps.setString(9, cu.lowPc?.let { "0x${it.toULong().toString(16)}" })
                ps.setString(10, JsonCodec.ranges(cu.ranges))
                ps.setString(11, JsonCodec.dies(cu.dies))
                ps.setString(12, cu.lineTable?.let { JsonCodec.lineTable(it) })
                ps.setString(13, JsonCodec.issues(cu.issues))
                ps.setInt(14, if (cu.dwoResolved) 1 else 0)
                ps.addBatch()
            }
            ps.executeBatch()
        }
    }

    /** Re-merge main + dwo files for a version after any import. */
    private fun rebuildBundle(versionId: Long) {
        val files = loadImported(versionId)
        val mains = files.filter { it.role != "dwo" }
        val dwos = files.filter { it.role == "dwo" }
        val main = mains.firstOrNull() ?: return
        val merged = DwoMerger.merge(main.parsed, dwos.map { it.parsed })
        bundles[versionId] = VersionBundle(versionId, files, merged, dwos.map { it.parsed })
    }

    private fun loadImported(versionId: Long): List<ImportedFile> {
        val out = mutableListOf<ImportedFile>()
        conn.prepareStatement(
            """SELECT id, filename, role, data, size, sha256, head16, tail16 FROM debug_files
               WHERE version_id=? ORDER BY id"""
        ).use { ps ->
            ps.setLong(1, versionId)
            ps.executeQuery().use { rs ->
                while (rs.next()) {
                    val bytes = rs.getBytes(4)
                    val elf = ElfFile(bytes)
                    val parsed = Dwarf.parse(elf)
                    val summary = ByteSummary(rs.getInt(5), rs.getString(6), rs.getString(7), rs.getString(8))
                    out += ImportedFile(rs.getLong(1), rs.getString(2), rs.getString(3), elf, parsed, bytes, summary)
                }
            }
        }
        return out
    }

    @Synchronized
    fun warmAll() {
        val ids = versions().map { it.id }
        for (id in ids) if (!bundles.containsKey(id)) rebuildBundle(id)
    }

    fun bundle(versionId: Long): VersionBundle? = bundles[versionId]

    @Synchronized
    fun createCrash(versionId: Long, label: String): Long {
        require(bundles.containsKey(versionId)) { "version $versionId 尚未导入可执行文件" }
        val now = System.currentTimeMillis()
        conn.prepareStatement("INSERT INTO crashes(version_id, label, created_at) VALUES(?,?,?)")
            .use { ps -> ps.setLong(1, versionId); ps.setString(2, label); ps.setLong(3, now); ps.executeUpdate() }
        return conn.createStatement().executeQuery("SELECT last_insert_rowid()").use { it.getLong(1) }
    }

    @Synchronized
    fun crashes(versionId: Long? = null): List<CrashRow> {
        val out = mutableListOf<CrashRow>()
        val (sql, useFilter) = "SELECT id, version_id, label, created_at FROM crashes ORDER BY id" to false
        conn.createStatement().use { st ->
            st.executeQuery(sql).use { rs ->
                while (rs.next()) {
                    val row = CrashRow(rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getLong(4))
                    if (versionId == null || row.versionId == versionId) out += row
                }
            }
        }
        return out
    }

    /**
     * Add a module load snapshot. Each call within a crash with a new runtime
     * base forms a new "generation" (dlopen/dlclose/reload may move the module).
     */
    @Synchronized
    fun addModuleLoad(crashId: Long, moduleName: String, fileSha: String?,
                      runtimeBaseRaw: String, explicitBias: String? = null): ModuleLoad {
        val crashVersion = conn.prepareStatement("SELECT version_id FROM crashes WHERE id=?").use { ps ->
            ps.setLong(1, crashId); ps.executeQuery().use { if (it.next()) it.getLong(1) else error("crash $crashId not found") }
        }
        val bundle = bundles[crashVersion] ?: error("version not loaded")
        val target = bundle.files.firstOrNull { it.summary.sha256 == fileSha }
            ?: bundle.files.first { it.role != "dwo" }
        val linkBase = target.elf.linkBase()
        val runtimeBase = parseAddr(runtimeBaseRaw)
        val bias = if (explicitBias != null) parseAddr(explicitBias) else runtimeBase - linkBase
        val gen = nextGeneration(crashId)
        val now = System.currentTimeMillis()
        conn.prepareStatement(
            """INSERT INTO module_loads(crash_id, generation, module_name, file_sha, runtime_base,
               link_base, bias, created_at) VALUES(?,?,?,?,?,?,?,?)"""
        ).use { ps ->
            ps.setLong(1, crashId); ps.setInt(2, gen); ps.setString(3, moduleName)
            ps.setString(4, target.summary.sha256)
            ps.setString(5, hex(runtimeBase)); ps.setString(6, hex(linkBase)); ps.setString(7, hex(bias))
            ps.setLong(8, now); ps.executeUpdate()
        }
        val id = conn.createStatement().executeQuery("SELECT last_insert_rowid()").use { it.getLong(1) }
        return ModuleLoad(id, crashId, gen, moduleName, target.summary.sha256, runtimeBase, linkBase, bias, now)
    }

    @Synchronized
    fun loads(crashId: Long): List<ModuleLoad> {
        val out = mutableListOf<ModuleLoad>()
        conn.prepareStatement(
            """SELECT id, crash_id, generation, module_name, file_sha, runtime_base, link_base,
               bias, created_at FROM module_loads WHERE crash_id=? ORDER BY generation"""
        ).use { ps ->
            ps.setLong(1, crashId); ps.executeQuery().use { rs ->
                while (rs.next()) out += ModuleLoad(rs.getLong(1), rs.getLong(2), rs.getInt(3),
                    rs.getString(4), rs.getString(5), parseAddr(rs.getString(6)),
                    parseAddr(rs.getString(7)), parseAddr(rs.getString(8)), rs.getLong(9))
            }
        }
        return out
    }

    private fun nextGeneration(crashId: Long): Int =
        conn.prepareStatement("SELECT COALESCE(MAX(generation),0)+1 FROM module_loads WHERE crash_id=?").use { ps ->
            ps.setLong(1, crashId); ps.executeQuery().use { it.getInt(1) }
        }

    @Synchronized
    fun recordQuery(crashId: Long?, versionId: Long?, generation: Int?, runtimeAddr: Long?,
                    relativeAddr: Long, bias: Long, resultJson: String) {
        val now = System.currentTimeMillis()
        conn.prepareStatement(
            """INSERT INTO query_history(crash_id, version_id, generation, runtime_addr, relative_addr,
               bias, result_json, created_at) VALUES(?,?,?,?,?,?,?,?)"""
        ).use { ps ->
            if (crashId != null) ps.setLong(1, crashId) else ps.setNull(1, java.sql.Types.INTEGER)
            if (versionId != null) ps.setLong(2, versionId) else ps.setNull(2, java.sql.Types.INTEGER)
            if (generation != null) ps.setInt(3, generation) else ps.setNull(3, java.sql.Types.INTEGER)
            ps.setString(4, runtimeAddr?.let { hex(it) })
            ps.setString(5, hex(relativeAddr)); ps.setString(6, hex(bias))
            ps.setString(7, resultJson); ps.setLong(8, now); ps.executeUpdate()
        }
    }

    companion object {
        fun parseAddr(s: String): Long {
            val t = s.trim().removePrefix("0x").removePrefix("0X")
            return java.lang.Long.parseUnsignedLong(t, 16)
        }
        fun hex(v: Long) = "0x${v.toULong().toString(16)}"
    }
}
