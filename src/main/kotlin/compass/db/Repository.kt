package compass.db

import compass.dwarf.CompilationUnit
import compass.dwarf.LineProgram
import compass.dwarf.ModuleSnapshot
import compass.dwarf.ParsedDebugInfo
import compass.dwarf.QueryResult
import compass.dwarf.Resolver
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.concurrent.ConcurrentHashMap

@Serializable
data class SectionJson(val name: String, val fileOffset: Long, val size: Long, val vaddr: Long, val present: Boolean, val sha256Short: String? = null)

@Serializable
data class ModuleVersionRow(
    val id: Long, val moduleId: Long, val moduleName: String, val version: Int,
    val filename: String?, val sha256: String, val size: Long,
    val elfClass: Int?, val machine: Int?, val importedAt: Long,
    val sections: List<SectionJson>, val warnings: List<String>
)

@Serializable
data class SnapshotRow(
    val id: Long, val moduleVersionId: Long, val generation: Int,
    val loadBias: Long, val note: String?
)

@Serializable
data class CrashRow(
    val id: Long, val title: String, val createdAt: Long,
    val addresses: List<String>, val snapshotId: Long?
)

class Repository(private val db: Database, private val dataDir: Path) {
    private val json = Json { ignoreUnknownKeys = true }
    private val cache = ConcurrentHashMap<Long, ParsedDebugInfo>()

    init { Files.createDirectories(dataDir.resolve("raw")) }

    fun listModules(): List<Pair<Long, String>> {
        db.conn.createStatement().use { s ->
            s.executeQuery("SELECT id, name FROM modules ORDER BY id").use { rs ->
                val out = ArrayList<Pair<Long, String>>()
                while (rs.next()) out.add(rs.getLong(1) to rs.getString(2))
                return out
            }
        }
    }

    /**
     * 导入新调试文件：同模块产生新版本，绝不修改旧版本；
     * 若内容 sha256 与某版本完全一致则直接复用（幂等）。
     */
    fun importFile(moduleName: String, filename: String?, bytes: ByteArray): ModuleVersionRow {
        val parsed = compass.dwarf.DebugInfoParser.parse(bytes)
        val elfClass = runCatching { compass.elf.ElfParser.parse(bytes).elfClass }.getOrNull()
        val machine = runCatching { compass.elf.ElfParser.parse(bytes).machine }.getOrNull()
        val sha = compass.elf.ElfParser.parse(bytes).sha256

        val moduleId = findOrCreateModule(moduleName)
        // 幂等：同内容已导入
        db.conn.prepareStatement(
            "SELECT id, version FROM module_versions WHERE module_id=? AND sha256=?"
        ).use { ps ->
            ps.setLong(1, moduleId); ps.setString(2, sha)
            ps.executeQuery().use { rs ->
                if (rs.next()) {
                    cache.putIfAbsent(rs.getLong(1), parsed)
                    return getVersion(rs.getLong(1))!!
                }
            }
        }
        val nextVersion = db.conn.prepareStatement(
            "SELECT COALESCE(MAX(version),0)+1 FROM module_versions WHERE module_id=?"
        ).use { ps ->
            ps.setLong(1, moduleId)
            ps.executeQuery().use { if (it.next()) it.getInt(1) else 1 }
        }
        val rawPath = dataDir.resolve("raw").resolve("m${moduleId}_v$nextVersion.bin")
        Files.write(rawPath, bytes)
        val id = db.conn.prepareStatement(
            """INSERT INTO module_versions
              (module_id, version, filename, sha256, size, elf_class, machine, imported_at, raw_path, raw_sections_json, warnings_json)
              VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            java.sql.Statement.RETURN_GENERATED_KEYS
        ).use { ps ->
            ps.setLong(1, moduleId); ps.setInt(2, nextVersion); ps.setString(3, filename)
            ps.setString(4, sha); ps.setLong(5, bytes.size.toLong())
            ps.setObject(6, elfClass); ps.setObject(7, machine)
            ps.setLong(8, System.currentTimeMillis()); ps.setString(9, rawPath.toString())
            ps.setString(10, json.encodeToString(parsed.sections.map {
                SectionJson(it.name, it.fileOffset, it.size, it.vaddr, it.present, it.sha256Short)
            }))
            ps.setString(11, json.encodeToString(parsed.warnings))
            ps.executeUpdate()
            ps.generatedKeys.use { if (it.next()) it.getLong(1) else error("no id") }
        }
        cache[id] = parsed
        return getVersion(id)!!
    }

    private fun findOrCreateModule(name: String): Long {
        db.conn.prepareStatement("SELECT id FROM modules WHERE name=?").use { ps ->
            ps.setString(1, name)
            ps.executeQuery().use { if (it.next()) return it.getLong(1) }
        }
        return db.conn.prepareStatement("INSERT INTO modules(name, created_at) VALUES(?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS).use { ps ->
            ps.setString(1, name); ps.setLong(2, System.currentTimeMillis())
            ps.executeUpdate()
            ps.generatedKeys.use { if (it.next()) it.getLong(1) else error("no module id") }
        }
    }

    fun listVersions(moduleId: Long? = null): List<ModuleVersionRow> {
        var sql = "SELECT id FROM module_versions"
        if (moduleId != null) sql += " WHERE module_id=$moduleId"
        sql += " ORDER BY id"
        db.conn.createStatement().use { s ->
            s.executeQuery(sql).use { rs ->
                val ids = ArrayList<Long>()
                while (rs.next()) ids.add(rs.getLong(1))
                return ids.mapNotNull { getVersion(it) }
            }
        }
    }

    fun getVersion(id: Long): ModuleVersionRow? {
        db.conn.prepareStatement(
            """SELECT mv.id, mv.module_id, m.name, mv.version, mv.filename, mv.sha256, mv.size,
                      mv.elf_class, mv.machine, mv.imported_at, mv.raw_sections_json, mv.warnings_json
               FROM module_versions mv JOIN modules m ON m.id=mv.module_id WHERE mv.id=?"""
        ).use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { rs ->
                if (!rs.next()) return null
                return ModuleVersionRow(
                    rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getInt(4),
                    rs.getString(5), rs.getString(6), rs.getLong(7),
                    rs.getObject(8) as? Int, rs.getObject(9) as? Int, rs.getLong(10),
                    json.decodeFromString(rs.getString(11)),
                    json.decodeFromString(rs.getString(12))
                )
            }
        }
    }

    fun parsed(versionId: Long): ParsedDebugInfo = cache.getOrPut(versionId) {
        val path = db.conn.prepareStatement("SELECT raw_path FROM module_versions WHERE id=?").use { ps ->
            ps.setLong(1, versionId)
            ps.executeQuery().use { rs2 -> if (rs2.next()) Path.of(rs2.getString(1)) else error("版本不存在 $versionId") }
        }
        compass.dwarf.DebugInfoParser.parse(Files.readAllBytes(path))
    }

    fun createSnapshot(versionId: Long, generation: Int?, loadBias: Long, note: String?): SnapshotRow {
        val gen = generation ?: (db.conn.prepareStatement(
            "SELECT COALESCE(MAX(generation),0)+1 FROM snapshots WHERE module_version_id=?"
        ).use { ps ->
            ps.setLong(1, versionId)
            ps.executeQuery().use { if (it.next()) it.getInt(1) else 1 }
        })
        val id = db.conn.prepareStatement(
            "INSERT INTO snapshots(module_version_id, generation, load_bias, note, created_at) VALUES(?,?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS
        ).use { ps ->
            ps.setLong(1, versionId); ps.setInt(2, gen)
            ps.setLong(3, loadBias); ps.setString(4, note)
            ps.setLong(5, System.currentTimeMillis())
            ps.executeUpdate()
            ps.generatedKeys.use { if (it.next()) it.getLong(1) else error("no snapshot id") }
        }
        return SnapshotRow(id, versionId, gen, loadBias, note)
    }

    fun listSnapshots(versionId: Long? = null): List<SnapshotRow> {
        var sql = "SELECT id, module_version_id, generation, load_bias, note FROM snapshots"
        if (versionId != null) sql += " WHERE module_version_id=$versionId"
        sql += " ORDER BY id"
        db.conn.createStatement().use { s ->
            s.executeQuery(sql).use { rs ->
                val out = ArrayList<SnapshotRow>()
                while (rs.next()) out.add(SnapshotRow(rs.getLong(1), rs.getLong(2), rs.getInt(3), rs.getLong(4), rs.getString(5)))
                return out
            }
        }
    }

    fun saveCrash(title: String, addresses: List<String>, snapshotId: Long?): Long {
        return db.conn.prepareStatement(
            "INSERT INTO crashes(title, created_at, addresses_json, snapshot_id) VALUES(?,?,?,?)",
            java.sql.Statement.RETURN_GENERATED_KEYS
        ).use { ps ->
            ps.setString(1, title); ps.setLong(2, System.currentTimeMillis())
            ps.setString(3, json.encodeToString(addresses)); ps.setObject(4, snapshotId)
            ps.executeUpdate()
            ps.generatedKeys.use { if (it.next()) it.getLong(1) else error("no crash id") }
        }
    }

    fun listCrashes(): List<CrashRow> {
        db.conn.createStatement().use { s ->
            s.executeQuery("SELECT id, title, created_at, addresses_json, snapshot_id FROM crashes ORDER BY id DESC").use { rs ->
                val out = ArrayList<CrashRow>()
                while (rs.next()) out.add(
                    CrashRow(rs.getLong(1), rs.getString(2), rs.getLong(3),
                        json.decodeFromString(rs.getString(4)), rs.getObject(5) as? Long)
                )
                return out
            }
        }
    }

    /**
     * 查询：地址先按快照的 load bias 转成相对地址，再在对应版本上解析。
     * 快照一旦创建即固定，版本升级不影响旧崩溃记录。
     */
    fun query(snapshot: SnapshotRow, runtimeAddress: Long): QueryResult {
        val parsed = parsed(snapshot.moduleVersionId)
        val snap = ModuleSnapshot(snapshot.id, snapshot.moduleVersionId, snapshot.generation, snapshot.loadBias, snapshot.note)
        return Resolver(parsed).query(runtimeAddress, snap)
    }

    fun cuDetails(versionId: Long): List<Map<String, Any?>> =
        parsed(versionId).cus.map { cu ->
            mapOf(
                "offset" to "0x${cu.offset.toString(16)}",
                "version" to cu.dwarfVersion,
                "unitType" to cu.unitType,
                "is64Bit" to cu.is64Bit,
                "addressSize" to cu.addressSize,
                "name" to cu.name,
                "compDir" to cu.compDir,
                "dwoName" to cu.dwoName,
                "dwoId" to cu.dwoId?.let { "0x${it.toString(16)}" },
                "degraded" to cu.degraded,
                "split" to cu.split,
                "dieCount" to cu.dies.size,
                "stmtList" to cu.stmtListOffset?.let { "0x${it.toString(16)}" },
                "warnings" to cu.warnings
            )
        }

    fun inlineTrees(versionId: Long): List<Map<String, Any?>> =
        parsed(versionId).cus.map { cu -> treeFor(cu) }

    private fun treeFor(cu: CompilationUnit): Map<String, Any?> {
        fun die(offset: Long): Map<String, Any?>? {
            val d = cu.dies[offset] ?: return null
            return mapOf(
                "offset" to "0x${offset.toString(16)}",
                "tag" to when (d.tag) {
                    0x11 -> "DW_TAG_compile_unit"; 0x4a -> "DW_TAG_skeleton_unit"
                    0x2e -> "DW_TAG_subprogram"; 0x1d -> "DW_TAG_inlined_subroutine"
                    else -> "tag_0x${d.tag.toString(16)}"
                },
                "name" to d.name,
                "ranges" to d.ranges.map { mapOf("low" to "0x${it.low.toString(16)}", "high" to "0x${it.high.toString(16)}", "empty" to it.isEmpty) },
                "callLine" to d.callLine,
                "children" to d.childrenOffsets.mapNotNull { die(it) }
            )
        }
        return mapOf(
            "cu" to (cu.name ?: "0x${cu.offset.toString(16)}"),
            "degraded" to cu.degraded,
            "tree" to die(cu.rootOffset)
        )
    }

    fun linePrograms(versionId: Long): List<Map<String, Any?>> =
        parsed(versionId).programs.map { p -> programToMap(p) }

    fun lineProgram(versionId: Long, cuOffset: Long): Map<String, Any?>? {
        val p = parsed(versionId).programs.firstOrNull { it.cuOffset == cuOffset }
            ?: parsed(versionId).programs.firstOrNull { it.cuOffset == parseHex(cuOffset) }
        return p?.let { programToMap(it, includeRows = true) }
    }

    private fun parseHex(v: Long): Long = v

    private fun programToMap(p: LineProgram, includeRows: Boolean = false): Map<String, Any?> = mapOf(
        "cuOffset" to "0x${p.cuOffset.toString(16)}",
        "headerOffset" to "0x${p.headerOffset.toString(16)}",
        "tableVersion" to p.table.dwarfVersion,
        "files" to p.files.map { mapOf("id" to it.id, "name" to it.displayPath, "dirIndex" to it.dirIndex) },
        "directories" to p.directories,
        "sequenceCount" to p.rows.count { it.endSequence },
        "warnings" to p.warnings,
        "rows" to if (includeRows) p.rows.mapIndexed { i, r ->
            mapOf(
                "seq" to r.hseq,
                "address" to "0x${r.address.toString(16)}",
                "segment" to r.segment,
                "file" to p.fileName(r.fileIndex),
                "line" to r.line,
                "column" to r.column,
                "stmt" to r.isStmt,
                "endSequence" to r.endSequence,
                "prologueEnd" to r.prologueEnd,
                "epilogueBegin" to r.epilogueBegin,
                "discriminator" to r.discriminator,
                "event" to p.events.getOrNull(i)
            )
        } else emptyList<Map<String, Any?>>()
    )
}
