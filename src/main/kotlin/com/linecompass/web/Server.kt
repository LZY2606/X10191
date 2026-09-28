package com.linecompass.web

import com.linecompass.compass.CompassService
import com.linecompass.db.Repository
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.request.receive
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.serialization.Serializable
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.http.content.resources
import io.ktor.http.content.static

@Serializable
data class ImportRequest(val name: String, val path: String? = null, val supersedes: Long? = null)

@Serializable
data class SnapshotModuleReq(val moduleName: String, val debugFileId: Long, val baseAddress: String)

@Serializable
data class SnapshotRequest(val name: String, val fixed: Boolean = true, val modules: List<SnapshotModuleReq>)

@Serializable
data class ResolveRequest(val tokens: List<String>, val snapshotId: Long? = null)

@Serializable
data class CrashRequest(
    val snapshotId: Long? = null,
    val title: String,
    val tokens: List<String>
)

data class CompassServer(val dbPath: String) {
    private val repo = Repository(dbPath)
    val service = CompassService(repo)

    fun start(host: String, port: Int) {
        embeddedServer(Netty, port = port, host = host) { compassModule() }.start(wait = true)
    }

    internal fun Application.compassModule() {
        install(ContentNegotiation) { json(CompassService.json) }
        install(StatusPages) {
            exception<Throwable> { call, cause ->
                call.respond(HttpStatusCode.BadRequest, mapOf(
                    "error" to (cause.message ?: cause::class.simpleName.orEmpty())))
            }
        }
        routing {
            get("/api/health") { call.respond(mapOf("ok" to true, "name" to "行址罗盘")) }

            get("/api/files") { call.respond(service.listFiles()) }
            post("/api/files/import") {
                val req = call.receive<ImportRequest>()
                val bytes = if (!req.path.isNullOrBlank()) java.io.File(req.path).readBytes()
                else run { val ch = call.receiveChannel(); io.ktor.utils.io.jvm.javaio.toInputStream(ch).use { it.readBytes() } }
                call.respond(service.importFile(req.name, bytes, req.supersedes))
            }
            get("/api/files/{id}") {
                val id = call.parameters["id"]!!.toLong()
                val f = service.fileDetail(id)
                if (f == null) call.respond(HttpStatusCode.NotFound, mapOf("error" to "no such file"))
                else call.respond(f)
            }
            get("/api/files/{id}/cus") { call.respond(service.cus(call.parameters["id"]!!.toLong())) }
            get("/api/files/{id}/ranges") { call.respond(service.ranges(call.parameters["id"]!!.toLong())) }
            get("/api/files/{id}/sequences") { call.respond(service.sequences(call.parameters["id"]!!.toLong())) }

            get("/api/snapshots") { call.respond(service.listSnapshots()) }
            post("/api/snapshots") {
                val req = call.receive<SnapshotRequest>()
                val mods = req.modules.map { Triple(it.moduleName, it.debugFileId,
                    com.linecompass.db.Repository.parseHex(it.baseAddress)) }
                call.respond(service.createSnapshot(req.name, req.fixed, mods))
            }

            post("/api/resolve") {
                val req = call.receive<ResolveRequest>()
                call.respond(mapOf("results" to service.resolveBatch(req.tokens, req.snapshotId)))
            }
            post("/api/crashes") {
                val req = call.receive<CrashRequest>()
                call.respond(service.saveCrash(req.snapshotId, req.title, req.tokens))
            }
            get("/api/crashes") { call.respond(service.listCrashes()) }

            static("/") { resources("static") }
            get("/") {
                val html = javaClass.getResourceAsStream("/static/index.html")?.bufferedReader()?.readText()
                    ?: error("index.html missing")
                call.respondText(html, ContentType.Text.Html)
            }
        }
    }
}
