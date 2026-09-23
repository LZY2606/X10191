package compass.db

data class InlineFrame(
    val name: String,
    val callFile: String?,
    val callLine: Long?,
    val depth: Int,
    val rangeWidth: Long,
)

data class Candidate(
    val fileId: Long,
    val fileSha: String,
    val fileName: String,
    val priority: Int,
    val cuName: String,
    val cuOffset: Long,
    val dwarfVersion: Int,
    val lineVersion: Int?,
    val sequence: Int,
    val sourceFile: String,
    val line: Long,
    val column: Long,
    val functionName: String?,
    val functionRangeWidth: Long?,
    val inlineChain: List<InlineFrame>,
    val trusted: Boolean,
    val trustNotes: List<String>,
)

data class AddressInterpretation(
    val module: String,
    val runtimeAddress: Long,
    val loadBase: Long,
    val linkBase: Long,
    val loadBias: Long,
    val generation: Int?,
    val relativeAddress: Long,
    val candidates: List<Candidate>,
    val notes: List<String>,
)

class QueryEngine(private val db: Database) {

    /**
     * Resolves [runtimeAddress] of [module] under load snapshot [snapshotId]
     * against debug-file version [fileId] (null = all versions).
     * Every legal candidate is kept; ordering is a pure function of content
     * (range width, inline depth, explicit priority, content hashes), never of
     * row ids, so it is invariant under import order.
     */
    fun lookup(module: String, runtimeAddress: Long, snapshotId: Long?, fileId: Long? = null): AddressInterpretation {
        var base = 0L
        var generation: Int? = null
        val notes = mutableListOf<String>()
        if (snapshotId != null) {
            var found = false
            db.query("SELECT base_address,generation,module FROM load_snapshot WHERE id=?", snapshotId) { rs ->
                base = rs.getLong(1); generation = rs.getInt(2); found = true
            }
            if (!found) notes.add("snapshot $snapshotId not found; treating load base as 0")
        }

        // resolve link base from the (single) queried file, or note ambiguity
        var linkBase = 0L
        val fileFilter = if (fileId != null) "AND f.id=$fileId" else ""
        val linkBases = LinkedHashSet<Long>()
        db.query("SELECT DISTINCT link_base FROM debug_file f WHERE 1=1 $fileFilter") { rs -> linkBases.add(rs.getLong(1)) }
        if (linkBases.size == 1) linkBase = linkBases.first()
        else if (linkBases.size > 1) notes.add("multiple link bases across versions: $linkBases; using per-file bias in candidates")

        val loadBias = base - linkBase
        val relative = runtimeAddress - loadBias

        val candidates = mutableListOf<Candidate>()

        // ---- line row candidates: row covers [addr, nextRow.addr) inside one sequence ----
        data class Row(val cuId: Long, val seq: Int, val idx: Int, val addr: Long, val file: String, val line: Long, val col: Long, val endSeq: Boolean)
        val rowsByCuSeq = LinkedHashMap<Pair<Long, Int>, MutableList<Row>>()
        db.query(
            """SELECT r.cu_id,r.seq,r.row_index,r.address,r.file,r.line,r.col,r.end_seq
               FROM line_row r JOIN compile_unit c ON c.id=r.cu_id JOIN debug_file f ON f.id=c.file_id
               WHERE 1=1 $fileFilter ORDER BY r.cu_id,r.seq,r.row_index"""
        ) { rs ->
            val row = Row(rs.getLong(1), rs.getInt(2), rs.getInt(3), rs.getLong(4), rs.getString(5), rs.getLong(6), rs.getLong(7), rs.getInt(8) != 0)
            rowsByCuSeq.getOrPut(row.cuId to row.seq) { mutableListOf() }.add(row)
        }
        // cuId -> covering line row
        val lineHits = HashMap<Long, Row>()
        for ((key, rows) in rowsByCuSeq) {
            for (i in rows.indices) {
                val row = rows[i]
                if (row.endSeq) continue
                val next = rows.getOrNull(i + 1)
                val end = next?.addr ?: continue
                if (end <= row.addr) continue // zero-length / empty range: no coverage
                if (relative >= row.addr && relative < end) {
                    lineHits[row.cuId] = row
                }
            }
        }

        // ---- function candidates ----
        data class Fn(val id: Long, val cuId: Long, val name: String, val dieOff: Long, val width: Long)
        val fns = mutableListOf<Fn>()
        db.conn.prepareStatement(
            """SELECT fn.id,fn.cu_id,fn.name,fn.die_offset,MIN(fr.end-fr.start)
               FROM func_range fr JOIN function fn ON fn.id=fr.function_id
               JOIN compile_unit c ON c.id=fn.cu_id
               WHERE fr.start <= ? AND fr.end > ? AND fr.end > fr.start ${if (fileId != null) "AND c.file_id=$fileId" else ""}
               GROUP BY fn.id"""
        ).use { ps ->
            ps.setLong(1, relative); ps.setLong(2, relative)
            ps.executeQuery().use { rs ->
                while (rs.next()) fns.add(Fn(rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getLong(4), rs.getLong(5)))
            }
        }

        // CU metadata
        data class CuMeta(val fileId: Long, val sha: String, val fileName: String, val priority: Int, val cuName: String, val cuOff: Long, val version: Int, val lineVersion: Int?, val warnings: List<String>)
        val cuMeta = HashMap<Long, CuMeta>()
        db.query(
            """SELECT c.id,c.file_id,f.sha256,f.name,f.priority,c.name,c.cu_offset,c.version,c.line_version,c.warnings
               FROM compile_unit c JOIN debug_file f ON f.id=c.file_id WHERE 1=1 $fileFilter"""
        ) { rs ->
            val lv = rs.getInt(9)
            cuMeta[rs.getLong(1)] = CuMeta(
                rs.getLong(2), rs.getString(3), rs.getString(4), rs.getInt(5),
                rs.getString(6), rs.getLong(7), rs.getInt(8),
                if (rs.wasNull()) null else lv,
                rs.getString(10).split("\n").filter { it.isNotBlank() }
            )
        }

        // inline chains for functions
        fun inlineChain(fnId: Long): List<InlineFrame> {
            val out = mutableListOf<InlineFrame>()
            db.conn.prepareStatement(
                """SELECT i.name,i.call_file,i.call_line,i.depth,MIN(ir.end-ir.start)
                   FROM inline_range ir JOIN inline_site i ON i.id=ir.inline_id
                   WHERE i.function_id=? AND ir.start <= ? AND ir.end > ? AND ir.end > ir.start
                   GROUP BY i.id ORDER BY i.depth"""
            ).use { ps ->
                ps.setLong(1, fnId); ps.setLong(2, relative); ps.setLong(3, relative)
                ps.executeQuery().use { rs ->
                    while (rs.next()) out.add(
                        InlineFrame(rs.getString(1), rs.getString(2), if (rs.wasNull()) null else rs.getLong(3), rs.getInt(4), rs.getLong(5))
                    )
                }
            }
            return out
        }

        // combine: one candidate per (CU with line hit) x (function covering, or none)
        val byCuFns = fns.groupBy { it.cuId }
        val cuIds = (lineHits.keys + byCuFns.keys).toSet()
        for (cuId in cuIds) {
            val meta = cuMeta[cuId] ?: continue
            val lineRow = lineHits[cuId]
            val cuFns = byCuFns[cuId] ?: emptyList()
            val trustNotes = meta.warnings.toMutableList()
            if (lineRow == null) trustNotes.add("no line row covers this address in the CU line program")
            val trusted = trustNotes.isEmpty()
            if (cuFns.isEmpty()) {
                if (lineRow != null) candidates.add(
                    Candidate(
                        meta.fileId, meta.sha, meta.fileName, meta.priority, meta.cuName, meta.cuOff, meta.version,
                        meta.lineVersion, lineRow.seq, lineRow.file, lineRow.line, lineRow.col,
                        null, null, emptyList(), trusted, trustNotes
                    )
                )
            } else {
                for (fn in cuFns) {
                    val chain = inlineChain(fn.id)
                    candidates.add(
                        Candidate(
                            meta.fileId, meta.sha, meta.fileName, meta.priority, meta.cuName, meta.cuOff, meta.version,
                            meta.lineVersion, lineRow?.seq ?: -1,
                            lineRow?.file ?: "<no-line>", lineRow?.line ?: 0, lineRow?.col ?: 0,
                            fn.name, fn.width, chain, trusted, trustNotes
                        )
                    )
                }
            }
        }

        // stable, content-based ordering: narrowest range, deepest inline, explicit priority, then content keys
        candidates.sortWith(
            compareBy(
                { it.functionRangeWidth ?: Long.MAX_VALUE },
                { -(it.inlineChain.maxOfOrNull { f -> f.depth } ?: -1) },
                { it.priority },
                { it.fileSha },
                { it.cuOffset },
                { it.sequence },
                { it.sourceFile },
                { it.line },
                { it.functionName ?: "" },
            )
        )

        if (candidates.isEmpty()) notes.add("no line row or function range covers relative address 0x${relative.toString(16)}")

        return AddressInterpretation(
            module, runtimeAddress, base, linkBase, loadBias, generation, relative, candidates, notes
        )
    }
}
