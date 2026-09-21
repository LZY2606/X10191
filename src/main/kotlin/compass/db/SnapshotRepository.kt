package compass.db

import compass.dwarf.AddressAnswer
import compass.dwarf.DebugVersion
import compass.dwarf.ModuleLoad
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

data class SnapshotMeta(val id: Long, val name: String, val createdAt: Long, val note: String?)
data class CrashMeta(val id: Long, val snapshotId: Long, val title: String, val createdAt: Long)
data class StoredQuery(val ordinal: Int, val address: Long, val answer: AddressAnswer)

class SnapshotRepository(private val db: Database) {
    private val json = Json { prettyPrint = true; encodeDefaults = true }

    fun createSnapshot(name: String, note: String?): Long {
        db.conn.prepareStatement(
            "INSERT INTO load_snapshot(name,created_at,note) VALUES(?,?,?)")
            .use { ps ->
                ps.setString(1, name); ps.setLong(2, System.currentTimeMillis())
                ps.setString(3, note); ps.executeUpdate()
            }
        return db.conn.createStatement().executeQuery("SELECT last_insert_rowid()").use { it.getLong(1) }
    }

    fun addLoad(snapshotId: Long, version: DebugVersion, baseAddress: Long,
                generation: Long, label: String, loadedAt: Long = System.currentTimeMillis()): Long {
        // load bias relative to the ELF's lowest-loadable vaddr (normally 0 for ET_EXEC,
        // for ET_DYN compute from first PT_LOAD vaddr).
        val firstLoad = version.image.elf.segments.filter { compass.elf.ElfFile.PT_LOAD == it.type }
            .minByOrNull { it.vaddr }?.vaddr ?: 0L
        val bias = baseAddress - firstLoad
        db.conn.prepareStatement("""
            INSERT INTO module_load(snapshot_id,version_id,generation,base_address,bias,loaded_at,label)
            VALUES(?,?,?,?,?,?,?)
        """.trimIndent()).use { ps ->
            ps.setLong(1, snapshotId); ps.setLong(2, version.versionId); ps.setLong(3, generation)
            ps.setLong(4, baseAddress); ps.setLong(5, bias); ps.setLong(6, loadedAt)
            ps.setString(7, label); ps.executeUpdate()
        }
        return db.conn.createStatement().executeQuery("SELECT last_insert_rowid()").use { it.getLong(1) }
    }

    fun listSnapshots(): List<SnapshotMeta> = db.conn.createStatement()
        .executeQuery("SELECT id,name,created_at,note FROM load_snapshot ORDER BY id").use { rs ->
            val out = mutableListOf<SnapshotMeta>()
            while (rs.next()) out.add(SnapshotMeta(rs.getLong(1), rs.getString(2), rs.getLong(3), rs.getString(4)))
            out
        }

    fun loadsFor(snapshotId: Long): List<ModuleLoad> =
        db.conn.prepareStatement("""
            SELECT id,version_id,generation,base_address,bias,loaded_at,label
            FROM module_load WHERE snapshot_id=? ORDER BY generation,id
        """.trimIndent()).use { ps ->
            ps.setLong(1, snapshotId); ps.executeQuery().use { rs ->
                val out = mutableListOf<ModuleLoad>()
                while (rs.next()) out.add(ModuleLoad(
                    rs.getLong(1), rs.getLong(2), rs.getLong(3), rs.getLong(4),
                    rs.getLong(5), rs.getLong(6), rs.getString(7)))
                out
            }
        }

    fun saveCrash(snapshotId: Long, title: String, queries: List<StoredQuery>): Long {
        val frozen = buildString {
            append("{\"snapshotId\":").append(snapshotId)
            append(",\"createdAt\":").append(System.currentTimeMillis())
            append(",\"queries\":[")
            queries.forEachIndexed { i, q ->
                if (i > 0) append(',')
                append("{\"ordinal\":").append(q.ordinal)
                append(",\"address\":\"0x").append(q.address.toString(16)).append("\"}")
            }
            append("]}")
        }
        db.conn.prepareStatement(
            "INSERT INTO crash_record(snapshot_id,created_at,title,frozen_json) VALUES(?,?,?,?)")
            .use { ps ->
                ps.setLong(1, snapshotId); ps.setLong(2, System.currentTimeMillis())
                ps.setString(3, title); ps.setString(4, frozen); ps.executeUpdate()
            }
        val crashId = db.conn.createStatement().executeQuery("SELECT last_insert_rowid()").use { it.getLong(1) }
        db.conn.prepareStatement(
            "INSERT INTO crash_query(crash_id,ordinal,address,answer_json) VALUES(?,?,?,?)").use { ps ->
            for (q in queries) {
                ps.setLong(1, crashId); ps.setInt(2, q.ordinal)
                ps.setLong(3, q.address)
                ps.setString(4, json.encodeToString(q.answer))
                ps.executeUpdate()
            }
        }
        return crashId
    }

    fun listCrashes(): List<CrashMeta> = db.conn.createStatement()
        .executeQuery("SELECT id,snapshot_id,title,created_at FROM crash_record ORDER BY id").use { rs ->
            val out = mutableListOf<CrashMeta>()
            while (rs.next()) out.add(CrashMeta(rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getLong(4)))
            out
        }
}
