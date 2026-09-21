package compass.store

import compass.dwarf.ByteDigest
import compass.dwarf.DebugModule
import compass.dwarf.SectionInfo
import compass.elf.ElfFile
import java.sql.Connection
import java.sql.DriverManager
import java.sql.Statement

data class StoredVersion(
    val id: Long,
    val label: String,
    val fileName: String,
    val sha256: String,
    val createdAt: String,
    val dwarfVersions: String,
)

data class Snapshot(
    val id: Long,
    val versionId: Long,
    val generation: Int,
    val loadBias: ULong,
    val moduleBase: ULong?,
    val note: String,
    val createdAt: String,
)

class Database(path: String) {
    val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path")

    init {
        Class.forName("org.sqlite.JDBC")
        conn.createStatement().use { st ->
            Schema.DDL.split(";").filter { it.isNotBlank() }.forEach { st.execute(it) }
        }
    }

    fun listVersions(): List<StoredVersion> =
        conn.createStatement().use { st ->
            st.executeQuery(
                "SELECT id,label,file_name,sha256,created_at,dwarf_versions FROM debug_versions ORDER BY id"
            ).use { rs ->
                buildList {
                    while (rs.next()) add(
                        StoredVersion(
                            rs.getLong(1), rs.getString(2), rs.getString(3),
                            rs.getString(4), rs.getString(5), rs.getString(6) ?: "",
                        )
                    )
                }
            }
        }

    fun versionRawBytes(id: Long): ByteArray? =
        conn.prepareStatement("SELECT raw_bytes FROM debug_versions WHERE id=?").use { ps ->
            ps.setLong(1, id)
            ps.executeQuery().use { if (it.next()) it.getBytes(1) else null }
        }

    fun insertVersion(
        label: String,
        fileName: String,
        bytes: ByteArray,
        digest: ByteDigest,
        elf: ElfFile,
        module: DebugModule,
    ): Long {
        val dwarfVersions = (module.units.map { it.version } + module.dwoUnits.map { it.version })
            .distinct().sorted().joinToString(",")
        val klass = if (elf.elf64) "ELF64" else "ELF32"
        val endian = if (elf.littleEndian) "little" else "big"
        val warnings = encodeJsonStringList(module.warnings)
        conn.prepareStatement(
            """INSERT INTO debug_versions
              (label,file_name,file_size,sha256,crc32,elf_class,endian,machine,dwarf_versions,is_split,warnings,raw_bytes)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            Statement.RETURN_GENERATED_KEYS,
        ).use { ps ->
            ps.setString(1, label)
            ps.setString(2, fileName)
            ps.setLong(3, bytes.size.toLong())
            ps.setString(4, digest.sha256)
            ps.setLong(5, digest.crc32)
            ps.setString(6, klass)
            ps.setString(7, endian)
            ps.setInt(8, elf.machine)
            ps.setString(9, dwarfVersions)
            ps.setInt(10, if (module.dwoUnits.isNotEmpty()) 1 else 0)
            ps.setString(11, warnings)
            ps.setBytes(12, bytes)
            ps.executeUpdate()
            ps.generatedKeys.use { rs ->
                require(rs.next()) { "no version id generated" }
                val id = rs.getLong(1)
                insertSectionSummaries(id, module.data.sectionInfos)
                return id
            }
        }
    }

    private fun insertSectionSummaries(versionId: Long, sections: List<SectionInfo>) {
        conn.prepareStatement(
            "INSERT INTO section_summaries(version_id,name,size,addr,allocated,sha256,error) VALUES (?,?,?,?,?,?,?)"
        ).use { ps ->
            for (s in sections) {
                ps.setLong(1, versionId)
                ps.setString(2, s.name)
                ps.setLong(3, s.size)
                ps.setString(4, s.addr.toString(16))
                ps.setInt(5, if (s.allocated) 1 else 0)
                ps.setString(6, s.digest?.sha256)
                ps.setString(7, s.error)
                ps.addBatch()
            }
            ps.executeBatch()
        }
    }

    fun sectionSummaries(versionId: Long): List<SectionSummaryRow> =
        conn.prepareStatement(
            "SELECT name,size,addr,allocated,sha256,error FROM section_summaries WHERE version_id=? ORDER BY id"
        ).use { ps ->
            ps.setLong(1, versionId)
            ps.executeQuery().use { rs ->
                buildList {
                    while (rs.next()) add(
                        SectionSummaryRow(
                            rs.getString(1), rs.getLong(2), rs.getString(3),
                            rs.getInt(4) == 1, rs.getString(5), rs.getString(6),
                        )
                    )
                }
            }
        }

    fun createSnapshot(versionId: Long, generation: Int, loadBias: ULong, moduleBase: ULong?, note: String): Long {
        conn.prepareStatement(
            "INSERT INTO load_snapshots(version_id,generation,load_bias,module_base,note) VALUES (?,?,?,?,?)",
            Statement.RETURN_GENERATED_KEYS,
        ).use { ps ->
            ps.setLong(1, versionId)
            ps.setInt(2, generation)
            ps.setString(3, loadBias.toString(16))
            ps.setString(4, moduleBase?.toString(16))
            ps.setString(5, note)
            ps.executeUpdate()
            ps.generatedKeys.use { rs ->
                require(rs.next())
                return rs.getLong(1)
            }
        }
    }

    fun listSnapshots(versionId: Long? = null): List<Snapshot> {
        val sql = buildString {
            append("SELECT id,version_id,generation,load_bias,module_base,note,created_at FROM load_snapshots")
            if (versionId != null) append(" WHERE version_id=?")
            append(" ORDER BY id")
        }
        return conn.prepareStatement(sql).use { ps ->
            if (versionId != null) ps.setLong(1, versionId)
            ps.executeQuery().use { rs ->
                buildList {
                    while (rs.next()) add(
                        Snapshot(
                            rs.getLong(1), rs.getLong(2), rs.getInt(3),
                            (rs.getString(4) ?: "0").toULong(16),
                            rs.getString(5)?.let { if (it.isBlank()) null else it.toULong(16) },
                            rs.getString(6) ?: "", rs.getString(7),
                        )
                    )
                }
            }
        }
    }

    fun saveBatch(snapshotId: Long, versionId: Long, rawInput: String, resultsJson: String): Long {
        conn.prepareStatement(
            "INSERT INTO batch_jobs(snapshot_id,version_id,raw_input,results_json) VALUES (?,?,?,?)",
            Statement.RETURN_GENERATED_KEYS,
        ).use { ps ->
            ps.setLong(1, snapshotId); ps.setLong(2, versionId)
            ps.setString(3, rawInput); ps.setString(4, resultsJson)
            ps.executeUpdate()
            ps.generatedKeys.use { require(it.next()); return it.getLong(1) }
        }
    }
}

data class SectionSummaryRow(
    val name: String,
    val size: Long,
    val addr: String,
    val allocated: Boolean,
    val sha256: String?,
    val error: String?,
)

fun encodeJsonStringList(items: List<String>): String =
    items.joinToString(",", prefix = "[", postfix = "]") { w ->
        val sb = StringBuilder("\"")
        for (ch in w) when (ch) {
            '\\' -> sb.append("\\\\")
            '"' -> sb.append("\\\"")
            '\n' -> sb.append("\\n")
            else -> sb.append(ch)
        }
        sb.append('"').toString()
    }
