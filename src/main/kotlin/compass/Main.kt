package compass

import com.fasterxml.jackson.databind.SerializationFeature
import io.ktor.http.*
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.routing.*
import java.nio.file.Files

fun main(args: Array<String>) {
    val host = args.drop(1).getOrNull(args.indexOf("--host")) ?: "127.0.0.1"
    val port = (args.drop(1).getOrNull(args.indexOf("--port")) ?: "5251").toInt()
    Files.createDirectories(CompassDatabase.defaultPath().parent)
    embeddedServer(Netty, port = port, host = host) { compassModule() }.start(wait = true)
}

fun Application.compassModule() {
    val db = CompassDatabase(CompassDatabase.defaultPath())
    val query = QueryService(db)
    install(ContentNegotiation) { jackson { enable(SerializationFeature.INDENT_OUTPUT) } }
    install(StatusPages) { exception<BadFileException> { call, cause -> call.respond(HttpStatusCode.BadRequest, mapOf("error" to cause.message)) } }
    routing {
        get("/") { call.respondText(indexHtml(), ContentType.Text.Html) }
        get("/api/health") { call.respond(mapOf("ok" to true, "name" to "行址罗盘")) }
        get("/api/versions") { call.respond(query.versions()) }
        get("/api/snapshots") { call.respond(query.snapshots()) }
        get("/api/versions/{id}/sections") {
            val id = call.parameters["id"]!!.toLong()
            call.respond(db.connection.prepareStatement("select * from sections where version_id=? order by ordinal").apply { setLong(1, id) }.executeQuery().let { rs ->
                val result = mutableListOf<Map<String, Any?>>(); while (rs.next()) result += mapOf("ordinal" to rs.getInt(2), "name" to rs.getString(3), "type" to rs.getString(4), "flags" to rs.getString(5), "address" to rs.getString(6), "offset" to rs.getString(7), "size" to rs.getString(8), "sha256" to rs.getString(13)); result
            })
        }
        get("/api/versions/{id}/warnings") {
            val id = call.parameters["id"]!!.toLong()
            call.respond(db.connection.prepareStatement("select stage,severity,offset,message from warnings where version_id=? order by id").apply { setLong(1, id) }.executeQuery().let { rs ->
                val result = mutableListOf<Map<String, Any?>>(); while (rs.next()) result += mapOf("stage" to rs.getString(1), "severity" to rs.getString(2), "offset" to rs.getString(3), "message" to rs.getString(4)); result
            })
        }
        get("/api/versions/{id}/ranges") {
            val id = call.parameters["id"]!!.toLong()
            call.respond(db.connection.prepareStatement("""select c.ordinal,c.name,c.version_no,c.split_status,d.name,d.tag_name,r.start_address,r.end_address,r.segment,r.source from cus c join dies d on d.cu_id=c.id join die_ranges r on r.die_id=d.id where c.version_id=? order by c.ordinal, cast(r.start_address as integer), cast(r.end_address as integer)""").apply { setLong(1, id) }.executeQuery().let { rs ->
                val result = mutableListOf<Map<String, Any?>>(); while (rs.next()) result += mapOf("cu" to rs.getInt(1), "cuName" to rs.getString(2), "dwarf" to rs.getInt(3), "splitStatus" to rs.getString(4), "function" to rs.getString(5), "tag" to rs.getString(6), "start" to rs.getString(7), "end" to rs.getString(8), "segment" to rs.getInt(9), "source" to rs.getString(10)); result
            })
        }
        get("/api/versions/{id}/lines") {
            val id = call.parameters["id"]!!.toLong()
            call.respond(db.connection.prepareStatement("""select c.ordinal,c.version_no,s.ordinal,r.address,r.file_name,r.line_no,r.column_no,r.is_stmt,r.end_sequence,r.discriminator from cus c join line_sequences s on s.cu_id=c.id join line_rows r on r.sequence_id=s.id where c.version_id=? order by c.ordinal,s.ordinal,r.ordinal""").apply { setLong(1, id) }.executeQuery().let { rs ->
                val result = mutableListOf<Map<String, Any?>>(); while (rs.next()) result += mapOf("cu" to rs.getInt(1), "dwarf" to rs.getInt(2), "sequence" to rs.getInt(3), "address" to rs.getString(4), "file" to rs.getString(5), "line" to rs.getInt(6), "column" to rs.getInt(7), "stmt" to (rs.getInt(8) == 1), "endSequence" to (rs.getInt(9) == 1), "discriminator" to rs.getInt(10)); result
            })
        }
        post("/api/import") {
            val upload = call.receiveMultipart().readAllParts().filterIsInstance<io.ktor.http.content.PartData.FileItem>().firstOrNull()
            val bytes = upload?.provider()?.readAllBytes() ?: throw BadFileException("multipart file is required")
            val parsed = runCatching {
                val elf = ElfParser.parse(bytes)
                ParsedFile(elf, DwarfInfoParser.parse(elf), sha256Hex(bytes))
            }.getOrElse { throw BadFileException(it.message ?: "cannot parse ELF/DWARF") }
            val id = db.saveParsed(upload.originalFileName, parsed)
            call.respond(mapOf("versionId" to id, "warnings" to parsed.dwarf.warnings))
        }
        post("/api/snapshots") {
            val request = call.receive<SnapshotRequest>()
            val id = query.createSnapshot(request.label.ifBlank { "snapshot" }, request.versionId, parseNumber(request.moduleBase), parseNumber(request.relativeBase), request.segment)
            call.respond(mapOf("snapshotId" to id, "loadBias" to (parseNumber(request.moduleBase) - parseNumber(request.relativeBase))))
        }
        get("/api/query") {
            val versionId = call.request.queryParameters["versionId"]?.toLong()
            val address = parseNumber(call.request.queryParameters["address"] ?: throw BadFileException("address required"))
            call.respond(if (versionId != null) query.queryRelative(versionId, address) else query.queryAddress(call.request.queryParameters["snapshotId"]!!.toLong(), address))
        }
        post("/api/batch") {
            val request = call.receive<BatchRequest>()
            call.respond(mapOf("results" to query.batch(request.snapshotId, request.text)))
        }
    }
}

data class SnapshotRequest(val label: String = "", val versionId: Long, val moduleBase: String = "0", val relativeBase: String = "0", val segment: Int? = null)
data class BatchRequest(val snapshotId: Long, val text: String = "")
class BadFileException(message: String) : Exception(message)

private fun parseNumber(value: String): Long {
    val normalized = value.trim().removePrefix("0x").removePrefix("0X")
    return if (value.trim().startsWith("0x", true)) normalized.toLong(16) else normalized.toLong()
}
