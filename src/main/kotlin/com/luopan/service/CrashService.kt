package com.luopan.service

import java.sql.Connection

class CrashAddressInput(val label: String?, val address: Long, val segment: Long = 0)

class CrashRecord(
    val id: Long, val moduleKey: String, val title: String, val createdAt: Long,
    val versionId: Long?, val actualBase: Long, val preferredBase: Long,
    val addresses: List<Triple<Int, String?, Long>>,
)

class CrashService(private val conn: Connection) {

    fun create(
        moduleKey: String,
        title: String,
        versionId: Long?,
        actualBase: Long,
        preferredBase: Long,
        addresses: List<CrashAddressInput>,
    ): Long {
        val crashId = conn.prepareStatement(
            """INSERT INTO crashes(module_key,title,created_at,version_id,actual_base,preferred_base)
               VALUES (?,?,?,?,?,?)""".trimIndent()
        ).use { ps ->
            ps.setString(1, moduleKey); ps.setString(2, title)
            ps.setLong(3, System.currentTimeMillis())
            if (versionId == null) ps.setNull(4, java.sql.Types.INTEGER) else ps.setLong(4, versionId)
            ps.setLong(5, actualBase); ps.setLong(6, preferredBase)
            ps.executeUpdate()
            ps.generatedKeys.use { if (it.next()) it.getLong(1) else error("no crash id") }
        }
        conn.prepareStatement(
            "INSERT INTO crash_addresses(crash_id,seq,label,address,segment) VALUES (?,?,?,?,?)"
        ).use { ps ->
            addresses.forEachIndexed { idx, a ->
                ps.setLong(1, crashId); ps.setInt(2, idx)
                ps.setString(3, a.label); ps.setLong(4, a.address); ps.setLong(5, a.segment)
                ps.addBatch()
            }
            ps.executeBatch()
        }
        // 记录一个加载代次（同一模块可多次加载，相同相对地址在不同代次的 bias 可能不同）
        val gen = nextGeneration(moduleKey)
        conn.prepareStatement(
            """INSERT INTO load_generations(module_key,version_id,generation,actual_base,preferred_base,recorded_at)
               VALUES (?,?,?,?,?,?)""".trimIndent()
        ).use { ps ->
            ps.setString(1, moduleKey)
            if (versionId == null) ps.setNull(2, java.sql.Types.INTEGER) else ps.setLong(2, versionId)
            ps.setInt(3, gen); ps.setLong(4, actualBase); ps.setLong(5, preferredBase)
            ps.setLong(6, System.currentTimeMillis())
            ps.executeUpdate()
        }
        return crashId
    }

    fun list(): List<CrashRecord> {
        val ids = conn.createStatement().executeQuery(
            "SELECT id,module_key,title,created_at,version_id,actual_base,preferred_base FROM crashes ORDER BY id"
        ).use { rs ->
            val out = ArrayList<CrashRecord>()
            while (rs.next()) {
                val id = rs.getLong(1)
                val addrs = conn.prepareStatement(
                    "SELECT seq,label,address FROM crash_addresses WHERE crash_id=? ORDER BY seq"
                ).use { p ->
                    p.setLong(1, id)
                    p.executeQuery().use { a ->
                        val l = ArrayList<Triple<Int, String?, Long>>()
                        while (a.next()) l.add(Triple(a.getInt(1), a.getString(2), a.getLong(3)))
                        l
                    }
                }
                val vid = rs.getObject(5)?.let { (it as Number).toLong() }
                out.add(CrashRecord(id, rs.getString(2), rs.getString(3), rs.getLong(4),
                    vid, rs.getLong(6), rs.getLong(7), addrs))
            }
            out
        }
        return ids
    }

    fun generations(moduleKey: String): List<Map<String, Any?>> =
        conn.prepareStatement(
            """SELECT generation,version_id,actual_base,preferred_base,recorded_at
               FROM load_generations WHERE module_key=? ORDER BY generation"""
        ).use { ps ->
            ps.setString(1, moduleKey)
            ps.executeQuery().use { rs ->
                val out = ArrayList<Map<String, Any?>>()
                while (rs.next()) {
                    val bias = rs.getLong(4) - rs.getLong(5)
                    out.add(mapOf(
                        "generation" to rs.getInt(1),
                        "versionId" to (rs.getObject(2)?.let { (it as Number).toLong() }),
                        "actualBase" to rs.getLong(3),
                        "preferredBase" to rs.getLong(4),
                        "loadBias" to bias,
                        "recordedAt" to rs.getLong(6),
                    ))
                }
                out
            }
        }

    private fun nextGeneration(moduleKey: String): Int =
        conn.prepareStatement(
            "SELECT COALESCE(MAX(generation),0)+1 FROM load_generations WHERE module_key=?"
        ).use { ps ->
            ps.setString(1, moduleKey)
            ps.executeQuery().use { if (it.next()) it.getInt(1) else 1 }
        }
}
