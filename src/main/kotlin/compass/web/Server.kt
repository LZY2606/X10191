package compass.web

import compass.db.*
import compass.query.ModuleLoad
import io.ktor.http.*
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.nio.file.Path

private suspend fun io.ktor.server.application.ApplicationCall.respondResource(path: String, ct: ContentType) {
    val text = WebServer::class.java.getResourceAsStream(path)?.bufferedReader()?.use { it.readText() }
        ?: error("missing resource $path")
    respondText(text, ct)
}

class WebServer(private val service: AppService) {
    fun start(host: String, port: Int) {
        embeddedServer(Netty, host = host, port = port) {
            install(ContentNegotiation) { jackson() }
            routing {
                get("/") { call.respondResource("/web/index.html", ContentType.Text.Html) }
                get("/app.js") { call.respondResource("/web/app.js", ContentType.Application.JavaScript) }
                get("/app.css") { call.respondResource("/web/app.css", ContentType.parse("text/css")) }
                get("/api/versions") {
                    call.respond(service.versions())
                }
                post("/api/versions") {
                    val multipart = call.receiveMultipart()
                    var label = "导入 ${System.currentTimeMillis()}"
                    var main: Pair<String, ByteArray>? = null
                    val dwos = mutableListOf<Pair<String, ByteArray>>()
                    multipart.forEachPart { part ->
                        when (part) {
                            is io.ktor.http.content.PartData.FormItem ->
                                if (part.name == "label" && part.value.isNotBlank()) label = part.value
                            is io.ktor.http.content.PartData.FileItem -> {
                                val bytes = part.streamProvider().use { it.readBytes() }
                                val name = part.originalFileName ?: "unnamed"
                                if (part.name == "main") main = name to bytes
                                else dwos.add(name to bytes)
                            }
                            else -> {}
                        }
                        part.dispose()
                    }
                    val m = main
                    if (m == null) {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "缺少主调试文件 (main)"))
                    } else {
                        call.respond(service.importVersion(label, m.first, m.second, dwos))
                    }
                }
                get("/api/versions/{id}/model") {
                    val id = call.parameters["id"]!!.toLong()
                    call.respond(service.view(id))
                }
                get("/api/versions/{id}/sequences/{seq}/rows") {
                    val id = call.parameters["id"]!!.toLong()
                    val seq = call.parameters["seq"]!!
                    call.respond(service.lineRows(id, seq))
                }
                get("/api/snapshots") { call.respond(service.snapshots()) }
                post("/api/snapshots") {
                    val body = call.receive<Map<String, Any?>>()
                    val versionId = (body["versionId"] as Number).toLong()
                    val label = body["label"] as? String ?: "快照"
                    @Suppress("UNCHECKED_CAST")
                    val mods = (body["modules"] as List<Map<String, Any?>>).map { m ->
                        ModuleLoad(
                            m["moduleName"] as String,
                            (m["runtimeBase"] as? Number)?.toLong(),
                            (m["fileBase"] as? Number)?.toLong(),
                            m["note"] as? String,
                        )
                    }
                    call.respond(service.createSnapshot(versionId, label, mods))
                }
                get("/api/crashes") {
                    val sid = call.request.queryParameters["snapshotId"]?.toLongOrNull()
                    call.respond(service.crashes(sid))
                }
                post("/api/crashes") {
                    val body = call.receive<Map<String, Any?>>()
                    val snapshotId = (body["snapshotId"] as Number).toLong()
                    val versionId = (body["versionId"] as Number).toLong()
                    val address = body["addressHex"] as String
                    val label = body["label"] as? String
                    val id = service.addCrash(snapshotId, versionId, address, label)
                    call.respond(mapOf("id" to id))
                }
                post("/api/resolve") {
                    val body = call.receive<Map<String, Any?>>()
                    val versionId = (body["versionId"] as Number).toLong()
                    @Suppress("UNCHECKED_CAST")
                    val addresses = (body["addresses"] as List<String>)
                    @Suppress("UNCHECKED_CAST")
                    val mods = (body["modules"] as? List<Map<String, Any?>> ?: emptyList()).map { m ->
                        ModuleLoad(
                            m["moduleName"] as? String ?: "module",
                            (m["runtimeBase"] as? Number)?.toLong(),
                            (m["fileBase"] as? Number)?.toLong(),
                            m["note"] as? String,
                        )
                    }
                    call.respond(service.resolveBatch(versionId, addresses, mods))
                }
            }
        }.start(wait = true)
    }

}
