package compass.web

import compass.db.Database
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

private fun indexHtml(): String =
    object {}.javaClass.getResourceAsStream("/web/index.html")?.bufferedReader()?.use { it.readText() }
        ?: error("找不到 web/index.html 资源")

class WebServer(host: String, port: Int, dbPath: String) {
    private val server = embeddedServer(Netty, port = port, host = host) {
        val db = Database(dbPath)
        val service = AppService(db)
        install(ContentNegotiation) { json(Json { prettyPrint = true; encodeDefaults = true }) }
        routing {
            get("/") {
                call.respondText(indexHtml(), ContentType.Text.Html)
            }
            get("/app.js") {
                val js = object {}.javaClass.getResourceAsStream("/web/app.js")!!.readBytes()
                call.respondBytes(js, ContentType("text", "javascript"))
            }
            get("/api/versions") {
                call.respond(service.versions.listMeta().map {
                    VersionDto(it.id, it.label, it.priority, it.sha256, it.buildId,
                        it.sizeBytes, it.tableVersion, it.hasSplit, it.importedAt)
                })
            }
            post("/api/import") {
                val req = call.receive<ImportRequest>()
                val id = service.importFile(req.path, req.label, req.priority ?: 100)
                call.respond(mapOf("versionId" to id))
            }
            post("/api/import-bytes/{label}") {
                val label = call.parameters["label"]!!
                val priority = call.request.queryParameters["priority"]?.toIntOrNull() ?: 100
                val bytes = call.receive<ByteArray>()
                val id = service.importBytes(label, bytes, priority)
                call.respond(mapOf("versionId" to id))
            }
            get("/api/versions/{id}/sections") {
                call.respond(service.sectionMap(call.parameters["id"]!!.toLong()))
            }
            get("/api/versions/{id}/ranges") {
                call.respond(service.addressRanges(call.parameters["id"]!!.toLong()))
            }
            get("/api/versions/{id}/sequences") {
                call.respond(service.sequences(call.parameters["id"]!!.toLong()))
            }
            get("/api/versions/{id}/sequences/{seq}/events") {
                call.respond(service.lineEvents(
                    call.parameters["id"]!!.toLong(), call.parameters["seq"]!!.toInt()))
            }
            get("/api/versions/{id}/inline") {
                call.respond(service.inlineTree(call.parameters["id"]!!.toLong()))
            }
            get("/api/versions/{id}/cus") {
                call.respond(service.cus(call.parameters["id"]!!.toLong()))
            }
            get("/api/versions/{id}/diagnostics") {
                call.respond(service.diagnostics(call.parameters["id"]!!.toLong()))
            }
            get("/api/snapshots") {
                call.respond(service.snapshots.listSnapshots())
            }
            post("/api/snapshots") {
                val req = call.receive<SnapshotRequest>()
                val id = service.snapshots.createSnapshot(req.name, req.note)
                call.respond(mapOf("snapshotId" to id))
            }
            get("/api/snapshots/{id}/loads") {
                call.respond(service.snapshots.loadsFor(call.parameters["id"]!!.toLong()))
            }
            post("/api/snapshots/{id}/loads") {
                val sid = call.parameters["id"]!!.toLong()
                val req = call.receive<LoadRequest>()
                val vs = service.versions.loadAll()
                val v = vs.firstOrNull { it.versionId == req.versionId }
                    ?: return@post call.respondText("版本 ${req.versionId} 不存在", status = HttpStatusCode.BadRequest)
                val lid = service.snapshots.addLoad(sid, v, req.baseAddress, req.generation,
                    req.label ?: "module#${req.versionId}")
                call.respond(mapOf("loadId" to lid))
            }
            post("/api/resolve") {
                val req = call.receive<ResolveRequest>()
                val addrs = req.addresses.map { parseAddress(it) }
                call.respond(service.resolveBatch(addrs, req.snapshotId))
            }
            post("/api/snapshots/{id}/crash") {
                val sid = call.parameters["id"]!!.toLong()
                val req = call.receive<CrashRequest>()
                val addrs = req.addresses.map { parseAddress(it) }
                val cid = service.resolveAndFreeze(sid, req.title, addrs)
                call.respond(mapOf("crashId" to cid))
            }
            get("/api/crashes") { call.respond(service.snapshots.listCrashes()) }
        }
    }

    private fun parseAddress(s: String): Long {
        val t = s.trim().removePrefix("0x").removePrefix("0X")
        return t.toLong(16)
    }

    fun start(wait: Boolean) {
        if (wait) server.start(wait = true) else server.start(wait = false)
    }
}

@Serializable
data class VersionDto(
    val id: Long, val label: String, val priority: Int, val sha256: String,
    val buildId: String?, val sizeBytes: Long, val tableVersion: String,
    val hasSplit: Boolean, val importedAt: Long
)

@Serializable
data class ImportRequest(val path: String, val label: String? = null, val priority: Int? = 100)

@Serializable
data class SnapshotRequest(val name: String, val note: String? = null)

@Serializable
data class LoadRequest(
    val versionId: Long, val baseAddress: Long, val generation: Long,
    val label: String? = null
)

@Serializable
data class ResolveRequest(val addresses: List<String>, val snapshotId: Long? = null)

@Serializable
data class CrashRequest(val title: String, val addresses: List<String>)
