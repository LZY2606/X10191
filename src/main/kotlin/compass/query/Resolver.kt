package compass.query

import kotlinx.serialization.Serializable

@Serializable
data class InlineFrame(
    val function: String?,
    val file: String?,
    val line: Long?,
    val column: Long?,
    val dieOffset: Long,
)

@Serializable
data class Candidate(
    val module: String,
    val generation: Int,
    val loadBias: String,
    val relativeAddress: String,
    val file: String?,
    val line: Long?,
    val column: Long?,
    val function: String?,
    val cuName: String?,
    val cuVersion: Int,
    val cuIndex: Int,
    val sequence: Int?,
    val rangeStart: String,
    val rangeEnd: String,
    val rangeWidth: Long,
    val inlineDepth: Int,
    val inlineChain: List<InlineFrame>,
    val tableVersion: String,
    val priority: Int,
    val trustworthy: Boolean,
    val notes: List<String>,
)

@Serializable
data class AddressInterpretation(
    val rawAddress: String,
    val candidates: List<Candidate>,
    val unmatched: Boolean,
    val notes: List<String>,
)

private data class ScopeRow(
    val id: Long, val cuId: Long, val dieOffset: Long, val tag: Long, val name: String?,
    val depth: Long, val parentId: Long?, val callFile: String?, val callLine: Long?, val callColumn: Long?,
)

private data class CuRow(
    val id: Long, val cuIndex: Long, val offset: Long, val version: Long, val name: String?,
    val degraded: Boolean, val notes: String, val dwoName: String?,
)

/**
 * Turns a runtime address into ranked source interpretations.
 * All legal candidates are kept; ordering is stable and content-based so it
 * does not depend on import order.
 */
class Resolver(private val store: Store) {

    fun interpret(snapshotId: Long, rawAddress: Long): AddressInterpretation {
        val modules = store.queryList(
            """SELECT m.id, m.file_id, m.load_bias, m.priority, m.generation, f.name, f.sha256
               FROM snapshot_module m JOIN debug_file f ON f.id = m.file_id
               WHERE m.snapshot_id=? ORDER BY m.generation""", snapshotId
        ) { rs ->
            ModuleRow(
                rs.getLong(2), rs.getLong(3), rs.getInt(4), rs.getInt(5), rs.getString(6), rs.getString(7)
            )
        }
        val notes = ArrayList<String>()
        val candidates = ArrayList<ScoredCandidate>()
        for (m in modules) {
            val rel = rawAddress - m.loadBias
            if (rel < 0) {
                notes.add("module ${m.name} (gen ${m.generation}): address below load bias, skipped")
                continue
            }
            candidates.addAll(candidatesFor(m, rel))
        }
        val ranked = candidates.sortedWith(
            compareBy(
                { it.rangeWidth },
                { -it.inlineDepth },
                { it.priority },
                { it.sha },
                { it.cuOffset },
                { it.sequence ?: Int.MAX_VALUE },
                { it.dieOffset },
            )
        )
        if (ranked.isEmpty()) notes.add("no debug range contains this address in any module of the snapshot")
        store.insert(
            "INSERT INTO query_log(snapshot_id, raw_address, result_json) VALUES(?,?,?)",
            snapshotId, rawAddress, "<stored>"
        )
        return AddressInterpretation(
            "0x${rawAddress.toString(16)}",
            ranked.map { it.candidate },
            ranked.isEmpty(),
            notes,
        )
    }

    private data class ModuleRow(
        val fileId: Long, val loadBias: Long, val priority: Int, val generation: Int,
        val name: String, val sha: String,
    )

    private class ScoredCandidate(
        val candidate: Candidate,
        val rangeWidth: Long,
        val inlineDepth: Int,
        val priority: Int,
        val sha: String,
        val cuOffset: Long,
        val sequence: Int?,
        val dieOffset: Long,
    )

    private fun candidatesFor(m: ModuleRow, rel: Long): List<ScoredCandidate> {
        val out = ArrayList<ScoredCandidate>()
        // 1. Line-table match: sequences containing rel.
        val seqs = store.queryList(
            """SELECT s.id, s.cu_id, s.seq_index, s.start, s.end FROM line_sequence s
               WHERE s.file_id=? AND s.start<=? AND s.end>?""", m.fileId, rel
        ) { rs -> SeqRow(rs.getLong(1), rs.getLong(2), rs.getInt(3), rs.getLong(4), rs.getLong(5)) }
        val lineMatchByCu = HashMap<Long, Pair<SeqRow, LineRowHit>>()
        for (s in seqs) {
            val rows = store.queryList(
                """SELECT address, file, line, col, is_stmt, end_seq FROM line_row
                   WHERE sequence_id=? AND address<=? ORDER BY address DESC, id DESC LIMIT 1""", s.id, rel
            ) { rs ->
                LineRowHit(rs.getLong(1), rs.getString(2), rs.getLong(3), rs.getLong(4), rs.getInt(5) == 1, rs.getInt(6) == 1)
            }
            val hit = rows.firstOrNull()
            if (hit != null && !hit.endSeq) lineMatchByCu[s.cuId] = s to hit
        }
        // 2. Scope matches.
        val scopeHits = store.queryList(
            """SELECT sc.id, sc.cu_id, sc.die_offset, sc.tag, sc.name, sc.depth, sc.parent_id,
                      sc.call_file, sc.call_line, sc.call_column, sr.start, sr.end
               FROM scope sc JOIN scope_range sr ON sr.scope_id = sc.id
               WHERE sc.file_id=? AND sr.start<=? AND sr.end>?""", m.fileId, rel
        ) { rs ->
            ScopeHit(
                ScopeRow(rs.getLong(1), rs.getLong(2), rs.getLong(3), rs.getLong(4), rs.getString(5),
                    rs.getLong(6), rs.getObject(7)?.let { (it as Number).toLong() },
                    rs.getString(8), rs.getObject(9)?.let { n -> (n as Number).toLong() },
                    rs.getObject(10)?.let { n -> (n as Number).toLong() }),
                rs.getLong(11), rs.getLong(12)
            )
        }
        val cuCache = HashMap<Long, CuRow>()
        fun cu(id: Long): CuRow? = cuCache.getOrPut(id) {
            store.queryList("SELECT id,cu_index,offset,version,name,degraded,notes,dwo_name FROM cu WHERE id=?", id) { rs ->
                CuRow(rs.getLong(1), rs.getLong(2), rs.getLong(3), rs.getLong(4), rs.getString(5),
                    rs.getInt(6) == 1, rs.getString(7) ?: "", rs.getString(8))
            }.firstOrNull() ?: return@getOrPut CuRow(id, -1, 0, 0, null, true, "missing cu row", null)
        }
        val scopeById = HashMap<Long, ScopeRow>()
        fun loadScope(id: Long): ScopeRow? = scopeById.getOrPut(id) {
            store.queryList(
                "SELECT id,cu_id,die_offset,tag,name,depth,parent_id,call_file,call_line,call_column FROM scope WHERE id=?", id
            ) { rs ->
                ScopeRow(rs.getLong(1), rs.getLong(2), rs.getLong(3), rs.getLong(4), rs.getString(5),
                    rs.getLong(6), rs.getObject(7)?.let { (it as Number).toLong() },
                    rs.getString(8), rs.getObject(9)?.let { n -> (n as Number).toLong() },
                    rs.getObject(10)?.let { n -> (n as Number).toLong() })
            }.firstOrNull() ?: return@getOrPut ScopeRow(id, -1, 0, 0, null, 0, null, null, null, null)
        }

        // Group scope hits by their enclosing top-level subprogram so overlapping
        // functions each yield their own candidate.
        val byFunction = LinkedHashMap<Long, MutableList<ScopeHit>>()
        for (hit in scopeHits) {
            var cur: ScopeRow? = hit.scope
            var guard = 0
            var top: ScopeRow = hit.scope
            while (cur != null && guard++ < 256) {
                top = cur
                if (cur.tag == 0x2eL) break // DW_TAG_subprogram
                cur = cur.parentId?.let { loadScope(it) }
            }
            byFunction.getOrPut(top.id) { ArrayList() }.add(hit)
        }

        for ((_, hits) in byFunction) {
            // Innermost = narrowest range, then deepest DIE.
            val innermost = hits.minWith(compareBy({ it.end - it.start }, { -it.scope.depth }))
            val functionScope = hits.firstOrNull { it.scope.tag == 0x2eL }?.scope
                ?: innermost.scope
            // Inline chain: inlined_subroutine scopes containing rel, outermost first.
            val inlines = hits.filter { it.scope.tag == 0x1dL }
                .sortedBy { it.scope.depth }
            val chain = inlines.map {
                InlineFrame(it.scope.name, it.scope.callFile, it.scope.callLine, it.scope.callColumn, it.scope.dieOffset)
            }
            val cuRow = cu(innermost.scope.cuId)
            val lm = lineMatchByCu[innermost.scope.cuId]
            val fnName = functionScope.name
            val tableVersion = buildString {
                append("DWARF").append(cuRow?.version ?: 0)
                if (lm != null) append(" + line v").append(cuRow?.version ?: 0)
            }
            val trust = cuRow != null && !cuRow.degraded && cuRow.dwoName == null
            val cNotes = ArrayList<String>()
            if (cuRow?.degraded == true) cNotes.add("CU parsed with degradation: ${cuRow.notes}")
            if (cuRow?.dwoName != null) cNotes.add("split DWARF skeleton (dwo=${cuRow.dwoName}); conclusions may be incomplete")
            val candidate = Candidate(
                module = m.name,
                generation = m.generation,
                loadBias = "0x${m.loadBias.toString(16)}",
                relativeAddress = "0x${rel.toString(16)}",
                file = lm?.second?.file,
                line = lm?.second?.line,
                column = lm?.second?.col,
                function = fnName,
                cuName = cuRow?.name,
                cuVersion = (cuRow?.version ?: 0).toInt(),
                cuIndex = (cuRow?.cuIndex ?: -1).toInt(),
                sequence = lm?.first?.seqIndex,
                rangeStart = "0x${innermost.start.toString(16)}",
                rangeEnd = "0x${innermost.end.toString(16)}",
                rangeWidth = innermost.end - innermost.start,
                inlineDepth = chain.size,
                inlineChain = chain,
                tableVersion = tableVersion,
                priority = m.priority,
                trustworthy = trust,
                notes = cNotes,
            )
            out.add(
                ScoredCandidate(
                    candidate, innermost.end - innermost.start, chain.size, m.priority,
                    m.sha, cuRow?.offset ?: 0, lm?.first?.seqIndex, innermost.scope.dieOffset
                )
            )
        }

        // Line-only candidates for CUs with a line match but no scope match.
        val coveredCus = byFunction.values.flatten().map { it.scope.cuId }.toSet()
        for ((cuId, lm) in lineMatchByCu) {
            if (cuId in coveredCus) continue
            val cuRow = cu(cuId)
            val width = lm.first.end - lm.first.start
            val trust = cuRow != null && !cuRow.degraded && cuRow.dwoName == null
            val cNotes = ArrayList<String>()
            cNotes.add("line-table-only match (no containing subprogram scope)")
            if (cuRow?.degraded == true) cNotes.add("CU parsed with degradation: ${cuRow.notes}")
            if (cuRow?.dwoName != null) cNotes.add("split DWARF skeleton (dwo=${cuRow.dwoName}); conclusions may be incomplete")
            val candidate = Candidate(
                module = m.name, generation = m.generation,
                loadBias = "0x${m.loadBias.toString(16)}",
                relativeAddress = "0x${rel.toString(16)}",
                file = lm.second.file, line = lm.second.line, column = lm.second.col,
                function = null, cuName = cuRow?.name,
                cuVersion = (cuRow?.version ?: 0).toInt(), cuIndex = (cuRow?.cuIndex ?: -1).toInt(),
                sequence = lm.first.seqIndex,
                rangeStart = "0x${lm.first.start.toString(16)}", rangeEnd = "0x${lm.first.end.toString(16)}",
                rangeWidth = width, inlineDepth = 0, inlineChain = emptyList(),
                tableVersion = "DWARF${cuRow?.version ?: 0} line-only",
                priority = m.priority + 1,
                trustworthy = trust, notes = cNotes,
            )
            out.add(
                ScoredCandidate(candidate, width, 0, m.priority + 1, m.sha, cuRow?.offset ?: 0, lm.first.seqIndex, Long.MAX_VALUE)
            )
        }
        return out
    }

    private data class SeqRow(val id: Long, val cuId: Long, val seqIndex: Int, val start: Long, val end: Long)
    private data class LineRowHit(val address: Long, val file: String?, val line: Long, val col: Long, val isStmt: Boolean, val endSeq: Boolean)
    private data class ScopeHit(val scope: ScopeRow, val start: Long, val end: Long)
}
