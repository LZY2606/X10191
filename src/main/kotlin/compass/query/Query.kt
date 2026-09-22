package compass.query

import compass.db.Db
import kotlinx.serialization.Serializable

@Serializable
data class InlineFrame(
    val name: String,
    val callFile: String?,
    val callLine: Long?,
    val depth: Int,
)

@Serializable
data class AddressCandidate(
    val rank: Int,
    val moduleName: String,
    val moduleVersion: Long,
    val generation: Int,
    val loadBase: String,
    val loadBias: String,
    val runtimeAddress: String,
    val relativeAddress: String,
    val file: String,
    val line: Int,
    val column: Int,
    val cuName: String?,
    val cuOffset: String,
    val dwarfVersion: Int,
    val unitType: Int,
    val sequence: Int,
    val rowSpan: String,
    val inlineDepth: Int,
    val inlineChain: List<InlineFrame>,
    val lineTableVersion: Int?,
    val rnglistsVersion: Int?,
    val isStmt: Boolean,
    val discriminator: Long,
    val priority: Int,
    val contentKey: String,
    val trust: List<String>,
)

@Serializable
data class AddressResult(
    val address: String,
    val candidates: List<AddressCandidate>,
    val notes: List<String>,
)

@Serializable
data class QueryResponse(
    val snapshotId: Long,
    val snapshotName: String,
    val results: List<AddressResult>,
)

data class SnapshotModule(
    val moduleVersionId: Long,
    val moduleName: String,
    val versionNo: Long,
    val loadBase: Long,
    val generation: Int,
    val preferredBase: Long,
) {
    val loadBias: Long get() = loadBase - preferredBase
}

class QueryEngine(private val db: Db) {

    fun snapshotModules(snapshotId: Long): List<SnapshotModule> {
        val out = mutableListOf<SnapshotModule>()
        db.conn.prepareStatement(
            """SELECT sm.module_version_id, mv.name, mv.version_no, sm.load_base, sm.generation, mv.preferred_base
               FROM snapshot_modules sm JOIN module_versions mv ON mv.id=sm.module_version_id
               WHERE sm.snapshot_id=? ORDER BY sm.generation, mv.name, mv.version_no"""
        ).use { ps ->
            ps.setLong(1, snapshotId)
            ps.executeQuery().use { rs ->
                while (rs.next()) out += SnapshotModule(
                    rs.getLong(1), rs.getString(2), rs.getLong(3), rs.getLong(4), rs.getInt(5), rs.getLong(6),
                )
            }
        }
        return out
    }

    fun snapshotName(snapshotId: Long): String = db.conn.prepareStatement(
        "SELECT name FROM snapshots WHERE id=?"
    ).use { ps ->
        ps.setLong(1, snapshotId)
        ps.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else "snapshot#$snapshotId" }
    }

    private data class RawCandidate(
        val mod: SnapshotModule,
        val rel: Long,
        val rowId: Long, val cuId: Long,
        val address: Long, val endAddress: Long,
        val file: String, val line: Int, val col: Int,
        val isStmt: Boolean, val discriminator: Long, val sequence: Int,
        val cuName: String?, val cuOffset: Long, val dwarfVersion: Int, val unitType: Int,
        val lineVersion: Int?, val rnglistsVersion: Int?,
        val dwoMissing: Boolean, val truncated: Boolean, val issues: String, val contentKey: String,
        val inlineChain: List<InlineFrame>,
    )

    /** Explicit trust priority: lower wins. Full units beat dwo-missing beat truncated. */
    private fun priorityOf(dwoMissing: Boolean, truncated: Boolean, unitType: Int): Int = when {
        truncated -> 3
        dwoMissing -> 2
        unitType == 5 -> 1 // skeleton
        else -> 0
    }

    fun query(snapshotId: Long, addresses: List<Long>): QueryResponse {
        val mods = snapshotModules(snapshotId)
        val results = addresses.map { addr -> queryOne(addr, mods) }
        return QueryResponse(snapshotId, snapshotName(snapshotId), results)
    }

    fun queryOne(runtimeAddr: Long, mods: List<SnapshotModule>): AddressResult {
        val raw = mutableListOf<RawCandidate>()
        val notes = mutableListOf<String>()
        for (mod in mods) {
            val rel = runtimeAddr - mod.loadBias
            if (rel < 0) continue
            // line row candidates (zero-length rows and end_sequence markers never match)
            db.conn.prepareStatement(
                """SELECT lr.id, lr.cu_id, lr.address, lr.end_address, lr.file, lr.line, lr.col,
                          lr.is_stmt, lr.discriminator, lr.seq,
                          cu.name, cu.cu_offset, cu.version, cu.unit_type, cu.line_version, cu.rnglists_version,
                          cu.dwo_missing, cu.truncated, cu.issues, cu.content_key
                   FROM line_rows lr JOIN compile_units cu ON cu.id=lr.cu_id
                   WHERE cu.module_version_id=? AND cu.truncated=0 AND lr.address<=? AND lr.end_address>?"""
            ).use { ps ->
                ps.setLong(1, mod.moduleVersionId)
                ps.setLong(2, rel)
                ps.setLong(3, rel)
                ps.executeQuery().use { rs ->
                    while (rs.next()) {
                        val cuId = rs.getLong(2)
                        raw += RawCandidate(
                            mod, rel,
                            rs.getLong(1), cuId,
                            rs.getLong(3), rs.getLong(4),
                            rs.getString(5), rs.getInt(6), rs.getInt(7),
                            rs.getInt(8) != 0, rs.getLong(9), rs.getInt(10),
                            rs.getString(11), rs.getLong(12), rs.getInt(13), rs.getInt(14),
                            if (rs.getObject(15) == null) null else rs.getInt(15),
                            if (rs.getObject(16) == null) null else rs.getInt(16),
                            rs.getInt(17) != 0, rs.getInt(18) != 0, rs.getString(19) ?: "", rs.getString(20),
                            inlineChainFor(cuId, rel),
                        )
                    }
                }
            }
        }
        if (raw.isEmpty()) notes += "no candidate: address not covered by any line row in pinned snapshot modules"

        // stable ranking: narrowest span, deepest inline, explicit priority, then content keys
        val sorted = raw.sortedWith(
            compareBy(
                { it.endAddress - it.address },
                { -it.inlineChain.size },
                { priorityOf(it.dwoMissing, it.truncated, it.unitType) },
                { it.contentKey },
                { it.file },
                { it.line },
                { it.mod.moduleName },
                { it.mod.generation },
            )
        )
        val candidates = sorted.mapIndexed { i, c ->
            val trust = mutableListOf<String>()
            if (c.dwoMissing) trust += "split DWARF: dwo file missing; line info from skeleton may be incomplete"
            if (c.truncated) trust += "compilation unit truncated (parse limits or unknown form)"
            if (c.issues.isNotBlank()) trust += c.issues
            AddressCandidate(
                rank = i + 1,
                moduleName = c.mod.moduleName,
                moduleVersion = c.mod.versionNo,
                generation = c.mod.generation,
                loadBase = "0x${c.mod.loadBase.toString(16)}",
                loadBias = "0x${c.mod.loadBias.toString(16)}",
                runtimeAddress = "0x${runtimeAddr.toString(16)}",
                relativeAddress = "0x${c.rel.toString(16)}",
                file = c.file, line = c.line, column = c.col,
                cuName = c.cuName,
                cuOffset = "0x${c.cuOffset.toString(16)}",
                dwarfVersion = c.dwarfVersion,
                unitType = c.unitType,
                sequence = c.sequence,
                rowSpan = "0x${(c.endAddress - c.address).toString(16)}",
                inlineDepth = c.inlineChain.size,
                inlineChain = c.inlineChain,
                lineTableVersion = c.lineVersion,
                rnglistsVersion = c.rnglistsVersion,
                isStmt = c.isStmt,
                discriminator = c.discriminator,
                priority = priorityOf(c.dwoMissing, c.truncated, c.unitType),
                contentKey = c.contentKey,
                trust = trust,
            )
        }
        return AddressResult("0x${runtimeAddr.toString(16)}", candidates, notes)
    }

    private fun inlineChainFor(cuId: Long, rel: Long): List<InlineFrame> {
        val out = mutableListOf<InlineFrame>()
        db.conn.prepareStatement(
            """SELECT DISTINCT i.name, i.call_file, i.call_line, i.depth
               FROM inlines i JOIN inline_ranges ir ON ir.inline_id=i.id
               WHERE i.cu_id=? AND ir.begin<=? AND ir.end>? ORDER BY i.depth"""
        ).use { ps ->
            ps.setLong(1, cuId); ps.setLong(2, rel); ps.setLong(3, rel)
            ps.executeQuery().use { rs ->
                while (rs.next()) out += InlineFrame(
                    rs.getString(1), rs.getString(2),
                    if (rs.getObject(3) == null) null else rs.getLong(3), rs.getInt(4),
                )
            }
        }
        return out
    }
}
