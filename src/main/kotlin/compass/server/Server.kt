package compass.server

import compass.resolve.ResolveResult
import compass.storage.CrashFrame
import compass.storage.CrashRecord
import compass.storage.Database
import compass.storage.Repository
import compass.util.U64
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.call
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.request.receiveText
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.http.content.streamProvider
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.plugins.statuspages.exception
import io.ktor.server.application.install
import io.ktor.server.request.receiveMultipart
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class ResolveRequest(val addresses: List<String> = emptyList(), val segment: Int = 0)

@Serializable
data class SnapshotEntryRequest(
    val moduleVersionId: Long,
    val loadBias: String,
    val baseAddress: String? = null,
    val generation: Int? = null
)

@Serializable
data class CrashRequest(
    val label: String,
    val snapshotId: Long? = null,
    val addresses: List<String> = emptyList(),
    val segment: Int = 0
)

fun Application.webModule(service: AppService) {
    install(ContentNegotiation) {
        json(Json { prettyPrint = false; encodeDefaults = true; ignoreUnknownKeys = true })
    }
    install(StatusPages) {
        exception(Throwable::class) { call: ApplicationCall, cause: Throwable ->
            val code = if (cause is ImportException) HttpStatusCode.BadRequest else HttpStatusCode.InternalServerError
            call.respond(code, mapOf("error" to (cause.message ?: cause.javaClass.simpleName)))
        }
    }
    routing {
        get("/health") { call.respond(mapOf("status" to "ok", "app" to "行址罗盘")) }

        get("/api/modules") {
            call.respond(mapOf("versions" to service.listModuleVersions()))
        }
        get("/api/modules/{versionId}") {
            val id = call.parameters["versionId"]!!.toLong()
            val d = service.moduleDetail(id)
            call.respond(mapOf(
                "record" to d.record,
                "elf" to d.bundle.elf,
                "sections" to d.bundle.sections,
                "cus" to d.bundle.cus,
                "linePrograms" to d.bundle.linePrograms,
                "issues" to d.bundle.issues,
                "splitLinks" to d.bundle.splitLinks,
                "contentSha256" to d.bundle.contentSha256
            ))
        }
        get("/api/modules/{versionId}/sections/{name}") {
            val id = call.parameters["versionId"]!!.toLong()
            val name = call.parameters["name"]!!
            val bytes = service.rawSection(id, name)
                ?: return@get call.respondText("section not found", status = HttpStatusCode.NotFound)
            call.respondBytes(bytes, ContentType.Application.OctetStream)
        }
        post("/api/modules/import") {
            val multipart = call.receiveMultipart()
            var fileName = "module.elf"
            var main: ByteArray? = null
            val companions = ArrayList<ByteArray>()
            multipart.forEachPart { part ->
                if (part is PartData.FileItem) {
                    val bytes = part.streamProvider().readBytes()
                    when (part.name) {
                        "file" -> { main = bytes; fileName = part.originalFileName ?: fileName }
                        "companion" -> companions += bytes
                    }
                }
                part.dispose.invoke()
            }
            if (main == null) {
                return@post call.respondText("missing 'file' part", status = HttpStatusCode.BadRequest)
            }
            call.respond(service.importElf(fileName, main, companions))
        }

        get("/api/snapshots") { call.respond(mapOf("snapshots" to service.listSnapshots())) }
        post("/api/snapshots") {
            val raw = call.receiveText().trim()
            val name = parseSnapshotName(raw).ifBlank { "snapshot-${System.currentTimeMillis()}" }
            call.respond(mapOf("id" to service.createSnapshot(name), "name" to name))
        }
        post("/api/snapshots/{id}/entries") {
            val id = call.parameters["id"]!!.toLong()
            val req = Json.decodeFromString(SnapshotEntryRequest.serializer(), call.receiveText())
            call.respond(service.addEntry(
                id, req.moduleVersionId,
                U64.parse(req.loadBias),
                req.baseAddress?.let { U64.parse(it) },
                req.generation
            ))
        }
        post("/api/snapshots/{id}/resolve") {
            val id = call.parameters["id"]!!.toLong()
            val req = Json.decodeFromString(ResolveRequest.serializer(), call.receiveText())
            val addrs = parseAddressList(req.addresses.joinToString("\n"))
            call.respond(mapOf("results" to service.resolve(id, addrs, req.segment)))
        }

        get("/api/crashes") { call.respond(mapOf("crashes" to service.listCrashes())) }
        post("/api/crashes") {
            val req = Json.decodeFromString(CrashRequest.serializer(), call.receiveText())
            val addrs = parseAddressList(req.addresses.joinToString("\n"))
            val rec = service.createCrash(req.label, req.snapshotId, addrs, req.segment)
            call.respond(crashJson(rec))
        }
        get("/api/crashes/{id}") {
            val id = call.parameters["id"]!!.toLong()
            val rec = service.getCrash(id)
                ?: return@get call.respondText("crash not found", status = HttpStatusCode.NotFound)
            call.respond(crashJson(rec))
        }

        get("/") {
            val html = AppService::class.java.getResourceAsStream("/web/index.html")?.readAllBytes()
                ?: return@get call.respondText("index.html missing", status = HttpStatusCode.InternalServerError)
            call.respondBytes(html, ContentType.Text.Html)
        }
        get("/app.js") {
            val js = AppService::class.java.getResourceAsStream("/web/app.js")?.readAllBytes()
                ?: return@get call.respondText("app.js missing", status = HttpStatusCode.InternalServerError)
            call.respondBytes(js, ContentType.parse("application/javascript"))
        }
        get("/styles.css") {
            val css = AppService::class.java.getResourceAsStream("/web/styles.css")?.readAllBytes()
                ?: return@get call.respondText("styles.css missing", status = HttpStatusCode.InternalServerError)
            call.respondBytes(css, ContentType.Text.CSS)
        }
    }
}

/** Accepts paste-friendly input: whitespace/comma-separated hex addresses, ignores # comments. */
fun parseSnapshotName(raw: String): String {
    if (raw.isBlank()) return ""
    return try {
        Json.decodeFromString(raw)
    } catch (e: Exception) {
        raw.trim('"')
    }
}

fun parseAddressList(raw: String): List<String> {
    return raw.lines()
        .flatMap { it.split(",", " ", "\t", ";") }
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }
}

private fun crashJson(rec: CrashRecord) = mapOf(
    "id" to rec.id, "label" to rec.label, "snapshotId" to rec.snapshotId,
    "createdAt" to rec.createdAt,
    "frames" to rec.frames.map { f ->
        mapOf("ord" to f.ord, "address" to f.address, "result" to f.result)
    }
)

fun startServer(dbPath: String, host: String, port: Int) {
    val db = Database(dbPath)
    val service = AppService(Repository(db))
    embeddedServer(Netty, host = host, port = port) { webModule(service) }.start(wait = true)
}
