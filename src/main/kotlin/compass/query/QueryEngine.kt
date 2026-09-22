package compass.query

import compass.db.Database
import compass.dwarf.Limits
import compass.dwarf.Tag

data class InlineFrame(
    val name: String?,
    val callFile: String?,
    val callLine: Long?,
    val callColumn: Long?,
    val depth: Int,
)

data class Candidate(
    val file: String,
    val line: Long,
    val column: Long,
    val cuName: String?,
    val cuOffset: Long,
    val cuVersion: Int,
    val sequence: Int,
    val address: Long,
    val endAddress: Long,
    val width: Long,
    val zeroLength: Boolean,
    val endSequence: Boolean,
    val function: String?,
    val inlineChain: List<InlineFrame>,
    val inlineDepth: Int,
    val tableVersions: Map<String, String>,
    val trust: String,
    val reasons: List<String>,
)

data class LookupResult(
    val input: Long,
    val loadBias: Long,
    val generation: Long,
    val relative: Long,
    val candidates: List<Candidate>,
    val issues: List<String>,
)

class QueryEngine(private val db: Database) {

    private fun hex(v: Long) = "0x" + java.lang.Long.toHexString(v)

    private fun num(rs: java.sql.ResultSet, col: Int): Long? = (rs.getObject(col) as? Number)?.toLong()

    fun lookup(fileId: Long, base: Long, generation: Long, runtimeAddr: Long): LookupResult {
        val rel = runtimeAddr - base
        val issues = ArrayList<String>()

        val tableVersions = db.query("SELECT key, value FROM meta WHERE file_id=? AND key LIKE 'table.%'", listOf(fileId)) {
            it.getString(1).removePrefix("table.") to it.getString(2)
        }.toMap()

        data class CuRow(val id: Long, val idx: Int, val offset: Long, val version: Int, val name: String?, val status: String, val unitType: Int, val dwo: String?)
        val cus = db.query("SELECT id, idx, offset, version, name, status, unit_type, dwo_name FROM cu WHERE file_id=?", listOf(fileId)) {
            CuRow(it.getLong(1), it.getInt(2), it.getLong(3), it.getInt(4), it.getString(5), it.getString(6), it.getInt(7), it.getString(8))
        }
        val cuById = cus.associateBy { it.id }
        val cuFiles = cus.associate { cu ->
            cu.id to db.query("SELECT value FROM meta WHERE file_id=? AND key=?", listOf(fileId, "cufiles.${cu.idx}")) {
                it.getString(1).split("\n")
            }.firstOrNull().orEmpty()
        }

        // Line-row candidates: normal half-open match, plus exact hit on zero-length rows.
        val rows = db.query("""
            SELECT cu_id, seq, address, end_address, file, line, col, end_seq FROM line_row
            WHERE file_id=? AND ((address<=? AND ?<end_address) OR (address=end_address AND address=?))
            """, listOf(fileId, rel, rel, rel)) {
            arrayOf(it.getLong(1), it.getInt(2), it.getLong(3), it.getLong(4), it.getString(5), it.getLong(6), it.getLong(7), it.getInt(8))
        }

        // DIE candidates (functions + inlined subroutines) covering rel.
        data class DieHit(val dieId: Long, val cuId: Long, val offset: Long, val depth: Int, val tag: Long,
                          val name: String?, val callFile: Long?, val callLine: Long?, val callCol: Long?,
                          val absOrigin: Long?, val begin: Long, val end: Long)
        val dieHits = db.query("""
            SELECT d.id, d.cu_id, d.offset, d.depth, d.tag, d.name, d.call_file, d.call_line, d.call_column,
                   d.abstract_origin, r.begin, r.end
            FROM die d JOIN die_range r ON r.die_id=d.id
            WHERE d.file_id=? AND d.tag IN (?, ?) AND ((r.begin<=? AND ?<r.end) OR (r.begin=r.end AND r.begin=?))
            """, listOf(fileId, Tag.SUBPROGRAM, Tag.INLINED_SUBROUTINE, rel, rel, rel)) {
            DieHit(it.getLong(1), it.getLong(2), it.getLong(3), it.getInt(4), it.getLong(5), it.getString(6),
                num(it, 7), num(it, 8), num(it, 9), num(it, 10), it.getLong(11), it.getLong(12))
        }

        fun resolveName(cuId: Long, dieOffset: Long?, direct: String?): String? {
            if (direct != null) return direct
            var off = dieOffset ?: return null
            val cu = cuById[cuId] ?: return null
            var hops = 0
            while (hops++ < Limits.MAX_REF_JUMPS) {
                val abs = cu.offset + off
                val found = db.query("SELECT name, abstract_origin FROM die WHERE file_id=? AND cu_id=? AND offset=?",
                    listOf(fileId, cuId, abs)) {
                    it.getString(1) to num(it, 2)
                }.firstOrNull() ?: run {
                    issues.add("reference to DIE offset ${hex(abs)} out of bounds; inline name unresolved")
                    return null
                }
                if (found.first != null) return found.first
                off = found.second ?: return null
            }
            issues.add("abstract_origin chain exceeded ${Limits.MAX_REF_JUMPS} hops; possible reference loop")
            return null
        }

        val candidates = ArrayList<Candidate>()
        for (row in rows) {
            val cuId = row[0] as Long
            val cu = cuById[cuId]
            val seq = row[1] as Int
            val addr = row[2] as Long
            val end = row[3] as Long
            val width = end - addr
            val zeroLen = addr == end
            val endSeq = (row[7] as Int) != 0

            val cuDies = dieHits.filter { it.cuId == cuId }
            val inlines = cuDies.filter { it.tag == Tag.INLINED_SUBROUTINE }.sortedBy { it.depth }
            val fn = cuDies.filter { it.tag == Tag.SUBPROGRAM }.minByOrNull { it.end - it.begin }
            val files = cuFiles[cuId].orEmpty()
            val v5 = (cu?.version ?: 4) >= 5
            fun callFileName(idx: Long?): String? {
                if (idx == null) return null
                val i = if (v5) idx.toInt() else idx.toInt() - 1
                return files.getOrNull(i)
            }
            val chain = inlines.map { d ->
                InlineFrame(
                    name = resolveName(d.cuId, d.absOrigin, d.name),
                    callFile = callFileName(d.callFile),
                    callLine = d.callLine,
                    callColumn = d.callCol,
                    depth = d.depth,
                )
            }
            val trust = when (cu?.status) {
                "ok" -> "high"
                "degraded" -> "degraded"
                else -> "low"
            }
            val reasons = ArrayList<String>()
            reasons.add("range width ${hex(width)}" + if (zeroLen) " (zero-length: exact-address match only)" else "")
            if (chain.isNotEmpty()) reasons.add("inline depth ${chain.size}")
            reasons.add("priority: CU@${hex(cu?.offset ?: 0)} seq=$seq")
            if (cu?.status == "degraded") {
                reasons.add("CU is split/skeleton (dwo=${cu.dwo ?: "unknown"}): line info from main file only; ELF addresses still trustworthy")
            }
            candidates.add(Candidate(
                file = row[4] as String, line = row[5] as Long, column = row[6] as Long,
                cuName = cu?.name, cuOffset = cu?.offset ?: 0, cuVersion = cu?.version ?: -1,
                sequence = seq, address = addr, endAddress = end, width = width,
                zeroLength = zeroLen, endSequence = endSeq,
                function = fn?.let { resolveName(it.cuId, it.absOrigin, it.name) },
                inlineChain = chain, inlineDepth = chain.size,
                tableVersions = tableVersions, trust = trust, reasons = reasons,
            ))
        }

        // Stable, import-order-independent interpretation:
        // narrowest range first, then deeper inline chains, then explicit content-derived priority.
        candidates.sortWith(compareBy({ it.width }, { -it.inlineDepth }, { it.cuOffset }, { it.sequence }, { it.address }, { it.line }, { it.column }, { it.file }))

        return LookupResult(runtimeAddr, base, generation, rel, candidates, issues)
    }
}
