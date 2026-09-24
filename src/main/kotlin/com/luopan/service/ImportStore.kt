package com.luopan.service

import com.luopan.dwarf.DwarfFile
import com.luopan.dwarf.DwarfFileParser
import java.sql.Connection
import java.security.MessageDigest

class ImportedFile(
    val versionId: Long,
    val moduleKey: String,
    val fileName: String,
    val sha256: String,
    val buildId: String?,
    val importedAt: Long,
    val dwarf: DwarfFile,
)

/**
 * 导入与版本存储。
 * 关键不变量：导入新版本只新增 debug_versions 行；旧崩溃记录通过 version_id 固定快照，
 * 重新查询旧崩溃时仍使用创建时选定的版本与 load bias。
 */
class ImportStore(private val conn: Connection) {
    private data class Stored(
        val id: Long, val moduleKey: String, val fileName: String,
        val sha: String, val buildId: String?, val at: Long, val blob: ByteArray,
    )

    @Volatile private var cache: List<ImportedFile>? = null

    fun import(moduleKey: String, fileName: String, data: ByteArray): ImportedFile {
        val dwarf = DwarfFileParser.parse(data)
        val sha = dwarf.elf.digest.sha256
        val existing = conn.prepareStatement(
            "SELECT id FROM debug_versions WHERE module_key=? AND sha256=?"
        ).use { ps ->
            ps.setString(1, moduleKey); ps.setString(2, sha)
            ps.executeQuery().use { if (it.next()) it.getLong(1) else null }
        }
        val id = if (existing != null) existing else {
            conn.prepareStatement(
                """
                INSERT INTO debug_versions
                (module_key, file_name, imported_at, sha256, file_size, build_id, dwarf_summary, blob)
                VALUES (?,?,?,?,?,?,?,?)
                """.trimIndent()
            ).use { ps ->
                ps.setString(1, moduleKey)
                ps.setString(2, fileName)
                ps.setLong(3, System.currentTimeMillis())
                ps.setString(4, sha)
                ps.setLong(5, data.size.toLong())
                ps.setString(6, dwarf.elf.buildId)
                ps.setString(7, summarize(dwarf))
                ps.setBytes(8, data)
                ps.executeUpdate()
                val gk = ps.generatedKeys
                if (gk.next()) gk.getLong(1) else error("no generated id")
            }
        }
        cache = null
        return ImportedFile(id, moduleKey, fileName, sha, dwarf.elf.buildId,
            System.currentTimeMillis(), dwarf)
    }

    fun allFiles(): List<ImportedFile> = files()

    fun filesForModule(moduleKey: String, versionId: Long?): List<ImportedFile> {
        val all = files().filter { it.moduleKey == moduleKey }
        if (versionId != null) return all.filter { it.versionId == versionId }
        // 不传版本：同一 sha 去重，取每个模块最新版本（崩溃记录会显式固定 versionId）
        return all.sortedByDescending { it.versionId }.distinctBy { it.sha256 }
    }

    fun files(): List<ImportedFile> {
        cache?.let { return it }
        val rows = conn.createStatement().executeQuery(
            """SELECT id, module_key, file_name, sha256, build_id, imported_at, blob
               FROM debug_versions ORDER BY id ASC"""
        ).use { rs ->
            val out = ArrayList<Stored>()
            while (rs.next()) out.add(Stored(
                rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4),
                rs.getString(5), rs.getLong(6), rs.getBytes(7),
            ))
            out
        }
        val loaded = rows.map { r ->
            val dwarf = DwarfFileParser.parse(r.blob)
            ImportedFile(r.id, r.moduleKey, r.fileName, r.sha, r.buildId, r.at, dwarf)
        }
        cache = loaded
        return loaded
    }

    fun versions(moduleKey: String): List<Map<String, Any?>> {
        return conn.prepareStatement(
            """SELECT id, file_name, imported_at, sha256, file_size, build_id, dwarf_summary
               FROM debug_versions WHERE module_key=? ORDER BY id ASC"""
        ).use { ps ->
            ps.setString(1, moduleKey)
            ps.executeQuery().use { rs ->
                val out = ArrayList<Map<String, Any?>>()
                while (rs.next()) out.add(mapOf(
                    "id" to rs.getLong(1),
                    "fileName" to rs.getString(2),
                    "importedAt" to rs.getLong(3),
                    "sha256" to rs.getString(4),
                    "size" to rs.getLong(5),
                    "buildId" to rs.getString(6),
                    "summary" to rs.getString(7),
                ))
                out
            }
        }
    }

    fun moduleKeys(): List<String> =
        conn.createStatement().executeQuery(
            "SELECT DISTINCT module_key FROM debug_versions ORDER BY module_key"
        ).use { rs ->
            val out = ArrayList<String>()
            while (rs.next()) out.add(rs.getString(1))
            out
        }

    private fun summarize(d: DwarfFile): String {
        val errors = d.diagnostics.count { it.severity == "ERROR" }
        return "cus=${d.units.size},splitCus=${d.splitUnits.size},funcs=${d.functions.size}," +
            "sequences=${d.line.sequences.size + d.splitLine.sequences.size},relocs=${d.relocationsApplied}," +
            "errors=$errors"
    }
}
