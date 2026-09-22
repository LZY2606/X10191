package compass.web

import compass.dwarf.*
import compass.elf.ElfFormatException
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.http.content.streamProvider
import io.ktor.server.http.content.staticResources
import kotlinx.serialization.json.Json

fun startServer(service: AppService, host: String, port: Int) {
    embeddedServer(Netty, host = host, port = port) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            get("/") {
                call.respondRedirect("/web/index.html")
            }
            get("/api/health") {
                call.respond(mapOf("ok" to true, "name" to "行址罗盘"))
            }
            post("/api/import") {
                val multipart = call.receiveMultipart()
                var bytes: ByteArray? = null
                var filename: String? = null
                multipart.forEachPart { part ->
                    if (part is PartData.FileItem) {
                        bytes = part.streamProvider().readBytes()
                        filename = part.originalFileName
                    }
                    part.dispose()
                }
                val data = bytes
                if (data == null) {
                    call.respond(HttpStatusCode.BadRequest, ImportErrorJson("missing file part"))
                    return@post
                }
                try {
                    val r = service.importBytes(data!!, filename)
                    call.respond(ImportResponseJson(r.id, r.deduped, r.versionLabel, r.sha256,
                        r.units, r.scopes, r.issues.map { Mappers.issue(it) }))
                } catch (e: ElfFormatException) {
                    call.respond(HttpStatusCode.BadRequest, ImportErrorJson(e.message ?: "bad ELF"))
                }
            }

            get("/api/files") {
                val all = service.registry.all()
                call.respond(all.map { f ->
                    mapOf(
                        "id" to f.id,
                        "path" to (f.elf.path ?: ""),
                        "sha256" to f.sha256,
                        "size" to f.elf.bytes.size,
                        "units" to f.units.size,
                        "scopes" to f.scopes.size,
                        "issues" to f.allIssues().size
                    )
                })
            }

            get("/api/files/{id}") {
                val id = call.parameters["id"]!!.toLong()
                val f = service.registry.file(id)
                    ?: return@get call.respond(HttpStatusCode.NotFound, ImportErrorJson("no such import"))
                val names = DwarfNames { _, off -> f.dieAtGlobalOffset(off)?.second }
                call.respond(FileDetailJson(
                    id = f.id, path = f.elf.path, sha256 = f.sha256,
                    size = f.elf.bytes.size.toLong(),
                    versionLabel = f.elf.path?.substringAfterLast('/') ?: "file#${f.id}",
                    sections = f.elf.sections.filter { it.name.isNotEmpty() }
                        .map { Mappers.section(it) },
                    units = f.units.map { u ->
                        Mappers.unit(u, f.scopes.count { it.unit === u })
                    },
                    scopes = f.scopes.map { Mappers.scope(it, names) },
                    issues = f.allIssues().map { Mappers.issue(it) },
                    loadSegments = f.elf.loadSegments.map {
                        compass.web.RangeJson(Mappers.hex(it.vaddr),
                            Mappers.hex(it.vaddr + it.memSize), 0, false)
                    },
                    preferredBase = f.elf.preferredBase()?.let { Mappers.hex(it) }
                ))
            }

            get("/api/files/{id}/lines") {
                val id = call.parameters["id"]!!.toLong()
                val stmtList = call.request.queryParameters["stmtList"]?.removePrefix("0x")?.toLong(16)
                val f = service.registry.file(id)
                    ?: return@get call.respond(HttpStatusCode.NotFound, ImportErrorJson("no such import"))
                val unit = f.units.firstOrNull { u ->
                    val v = (u.root.attr(DW.AT_stmt_list)?.value as? FormValue.SectionOffset)?.value
                    stmtList == null || v == stmtList
                } ?: return@get call.respond(HttpStatusCode.NotFound, ImportErrorJson("no line program"))
                val lp = try {
                    f.lineProgramFor(unit)
                } catch (e: Exception) {
                    return@get call.respond(HttpStatusCode.UnprocessableEntity,
                        ImportErrorJson(e.message ?: "line parse failed"))
                } ?: return@get call.respond(HttpStatusCode.NotFound, ImportErrorJson("no stmt_list"))
                call.respond(Mappers.lineProgram(lp))
            }

            post("/api/snapshots") {
                val req = call.receive<SnapshotRequestJson>()
                val mods = req.modules.map {
                    SnapshotModule(it.name, it.fileId, java.lang.Long.parseUnsignedLong(it.base.removePrefix("0x"), 16), it.generation)
                }
                val snap = service.snapshot(req.label, mods)
                call.respond(Mappers.snapshot(snap))
            }
            get("/api/snapshots") {
                call.respond(service.snapshots().map { Mappers.snapshot(it) })
            }

            post("/api/query") {
                val req = call.receive<BatchQueryRequestJson>()
                val snap = req.snapshotId?.let { service.snapshot(it) }
                val results = req.addresses.map {
                    Mappers.toJson(service.query(it, snap?.id))
                }
                call.respond(BatchQueryResponseJson(results))
            }
            get("/api/query") {
                val addr = call.request.queryParameters["q"]
                    ?: return@get call.respond(HttpStatusCode.BadRequest, ImportErrorJson("missing q"))
                val snapId = call.request.queryParameters["snapshot"]?.toLongOrNull()
                call.respond(Mappers.toJson(service.query(addr, snapId)))
            }

            staticResources("/web", "web")
        }
    }.start(wait = true)
}
