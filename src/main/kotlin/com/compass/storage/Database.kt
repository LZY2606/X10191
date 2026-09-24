package com.compass.storage

import com.compass.dwarf.AddressExplanation
import com.compass.dwarf.DebugDocument
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.nio.file.Files
import java.nio.file.Path
import java.sql.Connection
import java.sql.DriverManager
import java.time.Instant

@Serializable
data class SnapshotModule(
    val name: String,
    val versionId: Long,
    val runtimeBase: Long = 0,
    val fileBase: Long = 0,
    val loadBias: Long = runtimeBase - fileBase,
    val generation: String? = null
)

@Serializable
data class StoredVersion(
    val id: Long,
    val createdAt: String,
    val filename: String,
    val buildId: String?,
    val elfType: Int,
    val programBase: Long?,
    val byteSha256: String,
    val document: DebugDocument
)

@Serializable
data class StoredCrash(
    val id: Long,
    val createdAt: String,
    val label: String,
    val addressText: String,
    val modules: List<SnapshotModule>,
    val results: List<AddressExplanation>
)

@Serializable
data class CreateCrashRequest(
    val label: String = "未命名崩溃",
    val addressText: String,
    val modules: List<SnapshotModule> = emptyList()
)

class Database(path: Path) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val connection: Connection

    init {
        Files.createDirectories(path.toAbsolutePath().parent)
        connection = DriverManager.getConnection("jdbc:sqlite:$path")
        connection.createStatement().use { statement ->
            statement.executeUpdate("""
                create table if not exists versions (
                  id integer primary key autoincrement,
                  created_at text not null,
                  filename text not null,
                  build_id text,
                  elf_type integer not null,
                  program_base integer,
                  byte_sha256 text not null,
                  document_json text not null
                )
            """)
            statement.executeUpdate("""
                create table if not exists crashes (
                  id integer primary key autoincrement,
                  created_at text not null,
                  label text not null,
                  address_text text not null,
                  modules_json text not null,
                  results_json text not null
                )
            """)
        }
    }

    fun insertVersion(filename: String, byteSha256: String, document: DebugDocument): StoredVersion {
        val now = Instant.now().toString()
        val statement = connection.prepareStatement("""
            insert into versions(created_at, filename, build_id, elf_type, program_base, byte_sha256, document_json)
            values (?, ?, ?, ?, ?, ?, ?)
        """, java.sql.Statement.RETURN_GENERATED_KEYS)
        statement.setString(1, now)
        statement.setString(2, filename)
        statement.setString(3, document.elf.buildId)
        statement.setInt(4, document.elf.type)
        statement.setObject(5, document.elf.programBase)
        statement.setString(6, byteSha256)
        statement.setString(7, json.encodeToString(DebugDocument.serializer(), document))
        statement.executeUpdate()
        val id = statement.generatedKeys.use { if (it.next()) it.getLong(1) else error("No version id") }
        return StoredVersion(id, now, filename, document.elf.buildId, document.elf.type, document.elf.programBase, byteSha256, document)
    }

    fun listVersions(): List<StoredVersion> {
        connection.prepareStatement("""
            select id, created_at, filename, build_id, elf_type, program_base, byte_sha256, document_json
            from versions order by id desc
        """).executeQuery().use { rows ->
            val out = mutableListOf<StoredVersion>()
            while (rows.next()) out += readVersion(rows)
            return out
        }
    }

    fun getVersion(id: Long): StoredVersion? {
        connection.prepareStatement("""
            select id, created_at, filename, build_id, elf_type, program_base, byte_sha256, document_json
            from versions where id = ?
        """).use { statement ->
            statement.setLong(1, id)
            statement.executeQuery().use { rows -> if (rows.next()) return readVersion(rows) }
        }
        return null
    }

    fun insertCrash(label: String, addressText: String, modules: List<SnapshotModule>, results: List<AddressExplanation>): StoredCrash {
        val now = Instant.now().toString()
        connection.prepareStatement("""
            insert into crashes(created_at, label, address_text, modules_json, results_json)
            values (?, ?, ?, ?, ?)
        """, java.sql.Statement.RETURN_GENERATED_KEYS).use { statement ->
            statement.setString(1, now); statement.setString(2, label); statement.setString(3, addressText)
            statement.setString(4, json.encodeToString(kotlinx.serialization.builtins.ListSerializer(SnapshotModule.serializer()), modules))
            statement.setString(5, json.encodeToString(kotlinx.serialization.builtins.ListSerializer(AddressExplanation.serializer()), results))
            statement.executeUpdate()
            val id = statement.generatedKeys.use { if (it.next()) it.getLong(1) else error("No crash id") }
            return StoredCrash(id, now, label, addressText, modules, results)
        }
    }

    fun listCrashes(): List<StoredCrash> {
        connection.createStatement().executeQuery("select id, created_at, label, address_text, modules_json, results_json from crashes order by id desc").use { rows ->
            val out = mutableListOf<StoredCrash>()
            while (rows.next()) out += readCrash(rows)
            return out
        }
    }

    fun getCrash(id: Long): StoredCrash? {
        connection.prepareStatement("select id, created_at, label, address_text, modules_json, results_json from crashes where id=?").use { statement ->
            statement.setLong(1, id)
            statement.executeQuery().use { rows -> if (rows.next()) return readCrash(rows) }
        }
        return null
    }

    private fun readVersion(rows: java.sql.ResultSet): StoredVersion = StoredVersion(
        rows.getLong("id"), rows.getString("created_at"), rows.getString("filename"),
        rows.getString("build_id"), rows.getInt("elf_type"), rows.getObject("program_base") as? Long,
        rows.getString("byte_sha256"), json.decodeFromString(DebugDocument.serializer(), rows.getString("document_json"))
    )

    private fun readCrash(rows: java.sql.ResultSet): StoredCrash = StoredCrash(
        rows.getLong("id"), rows.getString("created_at"), rows.getString("label"),
        rows.getString("address_text"),
        json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(SnapshotModule.serializer()), rows.getString("modules_json")),
        json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(AddressExplanation.serializer()), rows.getString("results_json"))
    )
}
