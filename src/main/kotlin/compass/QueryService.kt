package compass

data class CandidateLine(
    val versionId: Long, val cuOrdinal: Int, val cuName: String?, val cuVersion: Int, val sequenceOrdinal: Int,
    val relativeAddress: Long, val loadBias: Long, val runtimeAddress: Long, val segment: Int,
    val file: String?, val line: Int, val column: Int, val discriminator: Int, val isStatement: Boolean,
    val endSequence: Boolean, val inlineDepth: Int, val rangeWidth: Long, val explicitPriority: Int,
    val confidence: String, val inlineChain: List<InlineFrame>, val trust: List<String>, val splitStatus: String
)

data class InlineFrame(val depth: Int, val name: String, val tag: String, val start: Long, val end: Long, val callFile: String?, val callLine: Int?, val rangeSource: String)
data class AddressExplanation(val input: String, val runtimeAddress: Long?, val relativeAddress: Long?, val loadBias: Long?, val snapshotId: Long?, val candidates: List<CandidateLine>, val message: String?)

class QueryService(private val db: CompassDatabase) {
    fun createSnapshot(label: String, versionId: Long, moduleBase: Long, relativeBase: Long, segment: Int?): Long {
        val bias = moduleBase - relativeBase
        db.connection.prepareStatement("insert into snapshots(label,version_id,module_base,relative_base,load_bias,segment,created_at) values(?,?,?,?,?,?,?)", java.sql.Statement.RETURN_GENERATED_KEYS).use { stmt ->
            stmt.setString(1, label); stmt.setLong(2, versionId); stmt.setString(3, moduleBase.toString()); stmt.setString(4, relativeBase.toString()); stmt.setString(5, bias.toString()); if (segment == null) stmt.setNull(6, java.sql.Types.INTEGER) else stmt.setInt(6, segment); stmt.setString(7, java.time.Instant.now().toString()); stmt.executeUpdate(); return stmt.generatedKeys.getLong(1)
        }
    }

    fun versions(): List<VersionRecord> = db.connection.prepareStatement("select * from versions order by id").use { q -> q.executeQuery().let { rs -> generateSequence { if (rs.next()) VersionRecord(rs.getLong(1), rs.getString(2), rs.getInt(3), rs.getInt(4), rs.getInt(5), rs.getString(6), rs.getString(7), rs.getInt(8), rs.getInt(9)) else null }.toList() } }

    fun snapshots(): List<SnapshotRecord> = db.connection.prepareStatement("select * from snapshots order by id").use { q -> q.executeQuery().let { rs -> generateSequence { if (rs.next()) SnapshotRecord(rs.getLong(1), rs.getString(2), rs.getLong(3), rs.getString(4).toLong(), rs.getString(5).toLong(), rs.getString(6).toLong(), if (rs.getObject(7) == null) null else rs.getInt(7), rs.getString(8)) else null }.toList() } }

    fun queryAddress(snapshotId: Long, runtimeAddress: Long): AddressExplanation {
        val snapshot = snapshots().firstOrNull { it.id == snapshotId } ?: return AddressExplanation(runtimeAddress.toString(16), runtimeAddress, null, null, null, emptyList(), "snapshot not found")
        val relative = runtimeAddress - snapshot.loadBias
        val candidates = findCandidates(snapshot.versionId, relative, snapshot.segment, runtimeAddress, snapshot.loadBias)
        return AddressExplanation(runtimeAddress.toString(16), runtimeAddress, relative, snapshot.loadBias, snapshotId, candidates, if (candidates.isEmpty()) "no legal range or line sequence contains the relative address" else null)
    }

    fun queryRelative(versionId: Long, relativeAddress: Long, moduleBase: Long = 0L, relativeBase: Long = 0L, segment: Int? = null): AddressExplanation {
        val bias = moduleBase - relativeBase
        val runtime = relativeAddress + bias
        val candidates = findCandidates(versionId, relativeAddress, segment, runtime, bias)
        return AddressExplanation(relativeAddress.toString(16), runtime, relativeAddress, bias, null, candidates, if (candidates.isEmpty()) "no legal range or line sequence contains the relative address" else null)
    }

    fun batch(snapshotId: Long, text: String): List<AddressExplanation> {
        val addresses = parseAddresses(text)
        val results = addresses.map { queryAddress(snapshotId, it) }
        val id = db.connection.prepareStatement("insert into batches(snapshot_id,raw_text,created_at) values(?,?,?)", java.sql.Statement.RETURN_GENERATED_KEYS).use { stmt ->
            stmt.setLong(1, snapshotId); stmt.setString(2, text); stmt.setString(3, java.time.Instant.now().toString()); stmt.executeUpdate(); stmt.generatedKeys.getLong(1)
        }
        db.connection.prepareStatement("insert into frames(batch_id,ordinal,input_address,relative_address,result_json) values(?,?,?,?,?)").use { stmt ->
            results.forEachIndexed { index, result -> stmt.setLong(1, id); stmt.setInt(2, index); stmt.setString(3, result.input); stmt.setString(4, result.relativeAddress?.toString()); stmt.setString(5, serializeJson(result)); stmt.addBatch() }
            stmt.executeBatch()
        }
        return results
    }

    private fun findCandidates(versionId: Long, relative: Long, segment: Int?, runtime: Long, bias: Long): List<CandidateLine> {
        val units = loadUnits(versionId)
        val result = mutableListOf<CandidateLine>()
        for (unit in units) {
            val rows = loadLineRows(unit.id, relative, segment)
            val allDies = loadDies(unit.id)
            val byId = allDies.associateBy { it.dieId }
            val matches = allDies.filter { die -> die.ranges.any { it.contains(relative, segment) } }
            for (row in rows) {
                val deepest = matches.filter { die -> die.ranges.any { range -> range.contains(row.address, segment) || row.endSequence && range.contains(row.address, segment) } }
                    .maxWithOrNull(compareBy({ it.depth }, { explicitPriority(it) }, { -it.ranges.minOf { range -> rangeWidth(range, row.address) } }, { -it.dieId }))
                val covering = (deepest?.let { chainFor(it, byId) } ?: emptyList())
                val matchingRanges = (deepest?.ranges?.filter { it.contains(row.address, segment) } ?: unitRangeFallback(unit, relative, segment))
                val width = matchingRanges.minOfOrNull { rangeWidth(it, relative) } ?: Long.MAX_VALUE
                val trust = trustNotes(unit, deepest, matchingRanges)
                result += CandidateLine(
                    versionId = versionId, cuOrdinal = unit.ordinal, cuName = unit.name, cuVersion = unit.version,
                    sequenceOrdinal = row.sequenceOrdinal, relativeAddress = relative, loadBias = bias, runtimeAddress = runtime,
                    segment = row.segment, file = row.fileName, line = row.line, column = row.column, discriminator = row.discriminator,
                    isStatement = row.isStatement, endSequence = row.endSequence, inlineDepth = covering.size - 1,
                    rangeWidth = if (width == Long.MAX_VALUE) -1 else width, explicitPriority = deepest?.let { explicitPriority(it) } ?: 0,
                    confidence = if (unit.splitStatus == "skeleton-missing-dwo" || matchingRanges.isEmpty()) "partial" else "high",
                    inlineChain = covering.mapIndexed { depth, die -> dieToFrame(die, byId, depth) }, trust = trust, splitStatus = unit.splitStatus
                )
            }
        }
        return result.sortedWith(compareBy({ it.rangeWidth }, { -it.inlineDepth }, { -it.explicitPriority }, { it.cuOrdinal }, { it.sequenceOrdinal }, { it.line }, { it.column }, { it.file ?: "" }))
    }

    private data class UnitRow(val id: Long, val ordinal: Int, val version: Int, val name: String?, val splitStatus: String)
    private data class DieRow(val dieId: Long, val offset: Long, val tag: Int, val tagName: String, val depth: Int, val parentOffset: Long?, val name: String?, val linkageName: String?, val callFileName: String?, val callLine: Int?, val ranges: List<RangeEdge>)
    private data class LineRowRecord(val sequenceId: Long, val sequenceOrdinal: Int, val address: Long, val segment: Int, val fileName: String?, val line: Int, val column: Int, val discriminator: Int, val isStatement: Boolean, val endSequence: Boolean)

    private fun loadUnits(versionId: Long): List<UnitRow> = db.connection.prepareStatement("select id,ordinal,version_no,name,split_status from cus where version_id=? order by ordinal").use { q -> q.setLong(1, versionId); q.executeQuery().let { rs -> generateSequence { if (rs.next()) UnitRow(rs.getLong(1), rs.getInt(2), rs.getInt(3), rs.getString(4), rs.getString(5)) else null }.toList() } }

    private fun loadDies(cuId: Long): List<DieRow> {
        val rangeMap = mutableMapOf<Long, MutableList<RangeEdge>>()
        db.connection.prepareStatement("select d.id,r.start_address,r.end_address,r.segment from dies d join die_ranges r on r.die_id=d.id where d.cu_id=?").use { q -> q.setLong(1, cuId); q.executeQuery().let { rs -> while (rs.next()) rangeMap.getOrPut(rs.getLong(1)) { mutableListOf() }.add(RangeEdge(rs.getString(2).toLong(), rs.getString(3).toLong(), rs.getInt(4))) } }
        return db.connection.prepareStatement("select d.id,d.dwarf_offset,d.tag,d.tag_name,d.depth,d.parent_offset,d.name,d.linkage_name,sf.path,d.call_line from dies d left join source_files sf on sf.cu_id=d.cu_id and sf.ordinal=d.call_file where d.cu_id=? order by d.ordinal").use { q ->
            q.setLong(1, cuId); q.executeQuery().let { rs -> generateSequence { if (rs.next()) DieRow(rs.getLong(1), rs.getString(2).toLong(), rs.getInt(3), rs.getString(4), rs.getInt(5), if (rs.getObject(6) == null) null else rs.getString(6).toLong(), rs.getString(7), rs.getString(8), rs.getString(9), if (rs.getObject(10) == null) null else rs.getInt(10), rangeMap[rs.getLong(1)].orEmpty()) else null }.toList() }
        }
    }

    private fun loadLineRows(cuId: Long, relative: Long, segment: Int?): List<LineRowRecord> {
        val rows = mutableListOf<LineRowRecord>()
        db.connection.prepareStatement("""
            select s.id,s.ordinal,r.address,r.segment,r.file_name,r.line_no,r.column_no,r.discriminator,r.is_stmt,r.end_sequence,r.ordinal row_ordinal
            from line_sequences s join line_rows r on r.sequence_id=s.id
            where s.cu_id=? order by s.ordinal,r.ordinal
        """).use { q ->
            q.setLong(1, cuId); val rs = q.executeQuery(); var currentSequence = -1L; var pending = mutableListOf<LineRowRecord>()
            fun flush(sequenceId: Long, sequenceOrdinal: Int, list: MutableList<LineRowRecord>) {
                val chosen = chooseRowsForAddress(list, relative, segment)
                rows += chosen
            }
            while (rs.next()) {
                val sequenceId = rs.getLong(1); val sequenceOrdinal = rs.getInt(2)
                if (currentSequence != -1L && sequenceId != currentSequence) { flush(currentSequence, rs.getInt(2) - 1, pending); pending = mutableListOf() }
                currentSequence = sequenceId
                pending += LineRowRecord(sequenceId, sequenceOrdinal, rs.getString(3).toLong(), rs.getInt(4), rs.getString(5), rs.getInt(6), rs.getInt(7), rs.getInt(8), rs.getInt(9) == 1, rs.getInt(10) == 1)
            }
            if (currentSequence != -1L) flush(currentSequence, pending.firstOrNull()?.sequenceOrdinal ?: 0, pending)
        }
        return rows
    }

    private fun chooseRowsForAddress(rows: List<LineRowRecord>, target: Long, segment: Int?): List<LineRowRecord> {
        val inSegment = rows.filter { segment == null || it.segment == segment }
        val matching = inSegment.filter { row -> val next = nextAddress(inSegment, row); row.address == target || (!row.endSequence && next != null && target >= row.address && target < next) }
        if (matching.isNotEmpty()) return matching
        val end = inSegment.lastOrNull { it.endSequence && it.address == target }
        return listOfNotNull(end)
    }

    private fun nextAddress(rows: List<LineRowRecord>, row: LineRowRecord): Long? = rows.dropWhile { it !== row }.drop(1).firstOrNull()?.address

    private fun rangeWidth(range: RangeEdge, address: Long): Long = if (range.start == range.end) 0L else range.end - range.start
    private fun explicitPriority(die: DieRow): Int = when (die.tag) {
        DwarfConstants.DW_TAG_inlined_subroutine -> 30
        DwarfConstants.DW_TAG_subprogram -> 20
        else -> 10
    }

    private fun chainFor(deepest: DieRow, byId: Map<Long, DieRow>): List<DieRow> {
        val chain = mutableListOf<DieRow>()
        var current: DieRow? = deepest
        val seen = mutableSetOf<Long>()
        while (current != null && seen.add(current.dieId) && chain.size < 256) {
            chain += current
            current = current.parentOffset?.let { parentOffset -> byId.values.firstOrNull { it.offset == parentOffset } }
        }
        return chain.reversed()
    }

    private fun dieToFrame(die: DieRow, byId: Map<Long, DieRow>, depth: Int): InlineFrame {
        val range = die.ranges.minByOrNull { it.end - it.start }
        return InlineFrame(depth, die.linkageName ?: die.name ?: die.tagName, die.tagName, range?.start ?: 0, range?.end ?: 0, die.callFileName, die.callLine, range?.source ?: "no-range")
    }

    private fun unitRangeFallback(unit: UnitRow, address: Long, segment: Int?): List<RangeEdge> = emptyList()
    private fun trustNotes(unit: UnitRow, die: DieRow?, ranges: List<RangeEdge>): List<String> {
        val notes = mutableListOf("ELF section bytes and line/DIE offsets were checked against section bounds")
        if (die == null) notes += "line table is usable even though no function DIE range covers this address"
        if (ranges.any { it.start == it.end }) notes += "a zero-length range matched only by exact address equality"
        if (unit.splitStatus == "skeleton-missing-dwo") notes += "skeleton line tables and non-split DIEs remain usable; inline DIEs inside the missing .dwo are unavailable"
        if (ranges.any { it.source == "rnglists" }) notes += "DWARF 5 range list offsets were resolved from the containing rnglist header"
        return notes
    }

    private fun parseAddresses(text: String): List<Long> = Regex("(?i)(?:0x)?[0-9a-f]{2,16}").findAll(text).map { match ->
        val value = match.value.removePrefix("0x").removePrefix("0X"); if (match.value.startsWith("0x", true)) value.toLong(16) else value.toLongOrNull() ?: value.toLong(16)
    }.toList()

    private fun serializeJson(value: Any): String = jacksonObjectMapperSafe().writeValueAsString(value)
    private fun jacksonObjectMapperSafe() = com.fasterxml.jackson.module.kotlin.jacksonObjectMapper()
}
