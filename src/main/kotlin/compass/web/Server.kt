package compass.web

import compass.query.AddressInterpretation
import compass.query.Importer
import compass.query.Resolver
import compass.query.Store
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.request.receiveChannel
import io.ktor.server.request.receiveMultipart
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.readRemaining
import kotlinx.io.readByteArray
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class FileSummary(
    val id: Long, val name: String, val sha256: String, val size: Long,
    val importedAt: String, val notes: String, val cus: Int, val sequences: Int, val scopes: Int,
)

@Serializable
data class SectionView(
    val name: String, val type: Long, val flags: Long, val addr: String,
    val offset: Long, val size: Long, val sha256: String,
)

@Serializable
data class CuView(
    val id: Long, val cuIndex: Int, val offset: String, val version: Int, val unitType: Int,
    val addressSize: Int, val name: String?, val compDir: String?, val producer: String?,
    val dwoName: String?, val lowPc: String?, val degraded: Boolean, val notes: String,
)

@Serializable
data class FileDetail(val file: FileSummary, val sections: List<SectionView>, val cus: List<CuView>)

@Serializable
data class SequenceView(val id: Long, val cuId: Long, val seqIndex: Int, val start: String, val end: String, val rows: List<RowView>)

@Serializable
data class RowView(
    val address: String, val file: String?, val line: Long, val col: Long,
    val isStmt: Boolean, val endSeq: Boolean, val basicBlock: Boolean,
    val prologueEnd: Boolean, val epilogueBegin: Boolean, val discriminator: Long,
)

@Serializable
data class ScopeView(
    val id: Long, val cuId: Long, val dieOffset: String, val tag: String, val name: String?,
    val depth: Int, val parentId: Long?, val callFile: String?, val callLine: Long?,
    val callColumn: Long?, val ranges: List<List<String>>,
)

@Serializable
data class SnapshotModuleView(
    val id: Long, val fileId: Long, val fileName: String, val loadBias: String,
    val priority: Int, val generation: Int,
)

@Serializable
data class SnapshotView(val id: Long, val label: String, val createdAt: String, val modules: List<SnapshotModuleView>)

@Serializable
data class SnapshotRequest(val label: String, val modules: List<SnapshotModuleRequest>)

@Serializable
data class SnapshotModuleRequest(val fileId: Long, val loadBias: String, val priority: Int = 0)

@Serializable
data class QueryRequest(val snapshotId: Long, val addresses: List<String>)

@Serializable
data class QueryResponse(val snapshotId: Long, val results: List<AddressInterpretation>)

@Serializable
data class ImportResponse(
    val fileId: Long, val name: String, val sha256: String, val sections: Int,
    val cus: Int, val sequences: Int, val lineRows: Int, val scopes: Int, val notes: List<String>,
)

@Serializable
data class ErrorResponse(val error: String)

fun parseAddress(text: String): Long {
    val t = text.trim()
    return when {
        t.startsWith("0x") || t.startsWith("0X") -> t.substring(2).toULong(16).toLong()
        t.startsWith("#") -> t.substring(1).toULong(16).toLong()
        else -> t.toULong().toLong()
    }
}

class Server(private val store: Store) {
    private val importer = Importer(store)
    private val resolver = Resolver(store)
    private val json = Json { prettyPrint = false; encodeDefaults = true }

    fun configure(app: Application) {
        app.install(ContentNegotiation) { json(json) }
        app.routing {
            get("/") {
                val html = Server::class.java.getResource("/web/index.html")!!.readText()
                call.respondText(html, ContentType.Text.Html)
            }
            get("/api/files") {
                call.respond(listFiles())
            }
            post("/api/import") {
                try {
                    var name = call.request.queryParameters["name"]
                    var bytes: ByteArray? = null
                    val contentType = call.request.headers["Content-Type"] ?: ""
                    if (contentType.startsWith("multipart/")) {
                        val mp = call.receiveMultipart()
                        while (true) {
                            val part = mp.readPart() ?: break
                            when (part) {
                                is io.ktor.http.content.PartData.FileItem -> {
                                    if (name == null) name = part.originalFileName
                                    bytes = part.provider().readRemaining().readByteArray()
                                }
                                is io.ktor.http.content.PartData.FormItem -> {
                                    if (part.name == "name") name = part.value
                                }
                                else -> {}
                            }
                            part.dispose()
                        }
                    } else {
                        bytes = call.receiveChannel().readRemaining().readByteArray()
                    }
                    val data = bytes
                    if (data == null || data.isEmpty()) {
                        call.respond(HttpStatusCode.BadRequest, ErrorResponse("empty upload"))
                        return@post
                    }
                    val result = importer.import(name ?: "unnamed", data)
                    call.respond(
                        ImportResponse(
                            result.fileId, result.name, result.sha256, result.sections,
                            result.cus, result.sequences, result.lineRows, result.scopes, result.notes,
                        )
                    )
                } catch (e: Exception) {
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("import failed: ${e.message}"))
                }
            }
            get("/api/files/{id}") {
                val id = call.parameters["id"]?.toLongOrNull()
                if (id == null) { call.respond(HttpStatusCode.BadRequest, ErrorResponse("bad id")); return@get }
                val detail = fileDetail(id)
                if (detail == null) call.respond(HttpStatusCode.NotFound, ErrorResponse("no such file"))
                else call.respond(detail)
            }
            get("/api/files/{id}/lines") {
                val id = call.parameters["id"]?.toLongOrNull()
                if (id == null) { call.respond(HttpStatusCode.BadRequest, ErrorResponse("bad id")); return@get }
                call.respond(lineView(id))
            }
            get("/api/files/{id}/scopes") {
                val id = call.parameters["id"]?.toLongOrNull()
                if (id == null) { call.respond(HttpStatusCode.BadRequest, ErrorResponse("bad id")); return@get }
                call.respond(scopeView(id))
            }
            get("/api/snapshots") { call.respond(listSnapshots()) }
            post("/api/snapshots") {
                try {
                    val text = call.receiveChannel().readRemaining().readByteArray().decodeToString()
                    val req = json.decodeFromString<SnapshotRequest>(text)
                    val id = store.tx {
                        val sid = store.insert("INSERT INTO snapshot(label) VALUES(?)", req.label)
                        req.modules.forEachIndexed { i, m ->
                            store.insert(
                                "INSERT INTO snapshot_module(snapshot_id,file_id,load_bias,priority,generation) VALUES(?,?,?,?,?)",
                                sid, m.fileId, parseAddress(m.loadBias), m.priority.toLong(), (i + 1).toLong()
                            )
                        }
                        sid
                    }
                    call.respond(mapOf("snapshotId" to id.toString()))
                } catch (e: Exception) {
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("snapshot failed: ${e.message}"))
                }
            }
            post("/api/query") {
                try {
                    val text = call.receiveChannel().readRemaining().readByteArray().decodeToString()
                    val req = json.decodeFromString<QueryRequest>(text)
                    val results = req.addresses.map { resolver.interpret(req.snapshotId, parseAddress(it)) }
                    call.respond(QueryResponse(req.snapshotId, results))
                } catch (e: Exception) {
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("query failed: ${e.message}"))
                }
            }
            get("/api/queries") {
                val sid = call.request.queryParameters["snapshot_id"]?.toLongOrNull()
                val out = ArrayList<Map<String, String>>()
                if (sid != null) {
                    store.query(
                        "SELECT id, raw_address, created_at FROM query_log WHERE snapshot_id=? ORDER BY id", sid
                    ) { rs ->
                        out.add(
                            mapOf(
                                "id" to rs.getLong(1).toString(),
                                "rawAddress" to "0x${rs.getLong(2).toString(16)}",
                                "createdAt" to rs.getString(3),
                            )
                        )
                    }
                }
                call.respond(out)
            }
        }
    }

    private fun listFiles(): List<FileSummary> = store.queryList(
        """SELECT f.id, f.name, f.sha256, f.size, f.imported_at, f.notes,
                  (SELECT COUNT(*) FROM cu c WHERE c.file_id=f.id),
                  (SELECT COUNT(*) FROM line_sequence s WHERE s.file_id=f.id),
                  (SELECT COUNT(*) FROM scope sc WHERE sc.file_id=f.id)
           FROM debug_file f ORDER BY f.id"""
    ) { rs ->
        FileSummary(
            rs.getLong(1), rs.getString(2), rs.getString(3), rs.getLong(4),
            rs.getString(5), rs.getString(6) ?: "", rs.getInt(7), rs.getInt(8), rs.getInt(9)
        )
    }

    private fun fileDetail(id: Long): FileDetail? {
        val summary = listFiles().firstOrNull { it.id == id } ?: return null
        val sections = store.queryList(
            "SELECT name,type,flags,addr,offset,size,sha256 FROM section WHERE file_id=? ORDER BY offset", id
        ) { rs ->
            SectionView(
                rs.getString(1), rs.getLong(2), rs.getLong(3), "0x${rs.getLong(4).toString(16)}",
                rs.getLong(5), rs.getLong(6), rs.getString(7)
            )
        }
        val cus = store.queryList(
            """SELECT id,cu_index,offset,version,unit_type,address_size,name,comp_dir,producer,dwo_name,low_pc,degraded,notes
               FROM cu WHERE file_id=? ORDER BY cu_index""", id
        ) { rs ->
            CuView(
                rs.getLong(1), rs.getInt(2), "0x${rs.getLong(3).toString(16)}", rs.getInt(4), rs.getInt(5),
                rs.getInt(6), rs.getString(7), rs.getString(8), rs.getString(9), rs.getString(10),
                rs.getObject(11)?.let { "0x${(it as Number).toLong().toString(16)}" },
                rs.getInt(12) == 1, rs.getString(13) ?: ""
            )
        }
        return FileDetail(summary, sections, cus)
    }

    private fun lineView(fileId: Long): List<SequenceView> {
        val seqs = store.queryList(
            "SELECT id,cu_id,seq_index,start,end FROM line_sequence WHERE file_id=? ORDER BY cu_id, seq_index", fileId
        ) { rs -> mutableListOf(rs.getLong(1), rs.getLong(2), rs.getLong(3), rs.getLong(4), rs.getLong(5)) }
        return seqs.map { s ->
            val rows = store.queryList(
                """SELECT address,file,line,col,is_stmt,end_seq,basic_block,prologue_end,epilogue_begin,discriminator
                   FROM line_row WHERE sequence_id=? ORDER BY address, id""", s[0]
            ) { rs ->
                RowView(
                    "0x${rs.getLong(1).toString(16)}", rs.getString(2), rs.getLong(3), rs.getLong(4),
                    rs.getInt(5) == 1, rs.getInt(6) == 1, rs.getInt(7) == 1,
                    rs.getInt(8) == 1, rs.getInt(9) == 1, rs.getLong(10)
                )
            }
            SequenceView(s[0], s[1], s[2].toInt(), "0x${s[3].toString(16)}", "0x${s[4].toString(16)}", rows)
        }
    }

    private fun scopeView(fileId: Long): List<ScopeView> {
        val scopes = store.queryList(
            "SELECT id,cu_id,die_offset,tag,name,depth,parent_id,call_file,call_line,call_column FROM scope WHERE file_id=? ORDER BY cu_id, die_offset", fileId
        ) { rs ->
            ScopeView(
                rs.getLong(1), rs.getLong(2), "0x${rs.getLong(3).toString(16)}",
                compass.dwarf.Tag.name(rs.getLong(4).toInt()), rs.getString(5), rs.getInt(6),
                rs.getObject(7)?.let { (it as Number).toLong() }, rs.getString(8),
                rs.getObject(9)?.let { (it as Number).toLong() },
                rs.getObject(10)?.let { (it as Number).toLong() }, emptyList()
            )
        }
        val ranges = HashMap<Long, MutableList<List<String>>>()
        store.query(
            """SELECT sr.scope_id, sr.start, sr.end FROM scope_range sr
               JOIN scope sc ON sc.id=sr.scope_id WHERE sc.file_id=? ORDER BY sr.start""", fileId
        ) { rs ->
            ranges.getOrPut(rs.getLong(1)) { ArrayList() }
                .add(listOf("0x${rs.getLong(2).toString(16)}", "0x${rs.getLong(3).toString(16)}"))
        }
        return scopes.map { it.copy(ranges = ranges[it.id] ?: emptyList()) }
    }

    private fun listSnapshots(): List<SnapshotView> {
        val snaps = store.queryList("SELECT id,label,created_at FROM snapshot ORDER BY id") { rs ->
            Triple(rs.getLong(1), rs.getString(2), rs.getString(3))
        }
        return snaps.map { (id, label, created) ->
            val mods = store.queryList(
                """SELECT m.id, m.file_id, f.name, m.load_bias, m.priority, m.generation
                   FROM snapshot_module m JOIN debug_file f ON f.id=m.file_id
                   WHERE m.snapshot_id=? ORDER BY m.generation""", id
            ) { rs ->
                SnapshotModuleView(
                    rs.getLong(1), rs.getLong(2), rs.getString(3),
                    "0x${rs.getLong(4).toString(16)}", rs.getInt(5), rs.getInt(6)
                )
            }
            SnapshotView(id, label, created, mods)
        }
    }
}
