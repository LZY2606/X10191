package compass.web

import compass.db.*
import compass.dwarf.DwarfIndex
import compass.elf.ElfFile
import compass.resolve.AddressResolver
import compass.resolve.ModuleSnapshot
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.http.content.*
import io.ktor.server.http.content.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString

@Serializable data class ImportResp(val versionId: Long, val reused: Boolean, val buildId: String?, val cuCount: Int, val sections: Int)
@Serializable data class ModuleSpec(val versionId: Long, val moduleName: String, val loadBias: Long, val generation: Int = 1, val segment: Int = 0, val buildId: String? = null)
@Serializable data class BatchReq(val sessionId: Long, val addresses: List<String>, val modules: List<ModuleSpec>? = null)
@Serializable data class BatchResp(val sessionId: Long, val results: List<ModuleAddressView>)
@Serializable data class ModuleAddressView(val moduleName: String, val resolution: compass.resolve.AddressResolution)

class WebServer(
    private val dbPath: String,
    private val host: String,
    private val port: Int
) {
    private val db = Database(dbPath)
    private val repo = Repository(db)
    private val versions = VersionManager(repo).also { it.init() }

    fun start() {
        embeddedServer(Netty, port = port, host = host) {
            install(ContentNegotiation) { json(Json { prettyPrint = false; encodeDefaults = true }) }
            install(StatusPages) {
                exception<Throwable> { call, cause ->
                    call.respond(HttpStatusCode.BadRequest, mapOf("error" to (cause.message ?: cause::class.simpleName)))
                }
            }
            routing {
                get("/") {
                    call.respondText(this::class.java.getResourceAsStream("/static/index.html")!!
                        .bufferedReader().readText(), ContentType.Text.Html)
                }
                staticResources("/static", "static")

                route("/api") {
                    post("/import") {
                        val multipart = call.receiveMultipart()
                        var fileName = "uploaded.elf"
                        var bytes: ByteArray? = null
                        multipart.forEachPart { part ->
                            if (part is PartData.FileItem) {
                                fileName = part.originalFileName ?: fileName
                                bytes = part.streamProvider().readBytes()
                            }
                            part.dispose()
                        }
                        val raw = bytes ?: error("no file part")
                        val res = versions.importFile(fileName, raw)
                        call.respond(ImportResp(res.versionId, res.reused, res.buildId,
                            res.index.cus.size, res.index.sections.size))
                    }

                    get("/versions") {
                        call.respond(repo.listVersions())
                    }

                    get("/versions/{id}") {
                        val id = call.parameters["id"]!!.toLong()
                        val idx = versions.indexFor(id) ?: return@get call.respondText("version not loaded", status = HttpStatusCode.NotFound)
                        call.respond(versionDetail(id, idx))
                    }

                    post("/sessions") {
                        @Serializable data class Req(val title: String = "")
                        val req = call.receive<Req>()
                        call.respond(mapOf("id" to repo.createSession(req.title)))
                    }
                    get("/sessions") { call.respond(repo.listSessions()) }

                    post("/sessions/{id}/modules") {
                        val sid = call.parameters["id"]!!.toLong()
                        val spec = call.receive<ModuleSpec>()
                        if (versions.indexFor(spec.versionId) == null) error("version ${spec.versionId} not loaded")
                        repo.addModule(sid, spec.versionId, spec.moduleName, spec.buildId,
                            spec.loadBias, spec.generation, spec.segment)
                        call.respond(mapOf("ok" to true))
                    }
                    get("/sessions/{id}/modules") {
                        call.respond(repo.listModules(call.parameters["id"]!!.toLong()))
                    }

                    post("/resolve/batch") {
                        val req = call.receive<BatchReq>()
                        val addrs = req.addresses.mapNotNull { parseAddress(it) }
                        val modules = resolveModules(req.sessionId, req.modules)
                        val views = addrs.flatMap { addr ->
                            AddressResolver.resolve(addr, modules).map { (mod, res) ->
                                ModuleAddressView(mod.name, res)
                            }
                        }
                        views.forEachIndexed { i, v ->
                            val ord = i
                            repo.saveQuery(req.sessionId, v.resolution.runtimeAddress, ord,
                                Json { encodeDefaults = true }.encodeToString(v.resolution))
                        }
                        call.respond(BatchResp(req.sessionId, views))
                    }
                }
            }
        }.start(wait = true)
    }

    private fun resolveModules(sessionId: Long, override: List<ModuleSpec>?): List<ModuleSnapshot> {
        val rows = if (override != null) {
            override.map { SessionModuleRow(0, sessionId, it.versionId, it.moduleName, it.buildId, it.loadBias, it.generation, it.segment) }
        } else repo.listModules(sessionId)
        return rows.mapNotNull { row ->
            val idx = versions.indexFor(row.versionId) ?: return@mapNotNull null
            ModuleSnapshot(row.moduleName, row.buildId, row.loadBias, row.generation, row.segment, idx)
        }
    }

    private fun parseAddress(s: String): Long? {
        val t = s.trim().substringBefore('!').trim().removePrefix("0x").removePrefix("0X")
        return t.toLongOrNull(16) ?: s.trim().toLongOrNull()
    }

    @Serializable
    data class VersionDetail(
        val versionId: Long,
        val rawSha256: String,
        val elfClass: String,
        val cus: List<CuView>,
        val sections: List<compass.dwarf.SectionInfo>,
        val warnings: List<String>
    )
    @Serializable
    data class CuView(
        val offset: Long, val version: Int, val name: String?, val compDir: String?,
        val dwoName: String?, val skeleton: Boolean, val split: Boolean,
        val ranges: List<compass.dwarf.RangeEntry>,
        val sequences: List<SeqView>, val scopeCount: Int, val notes: List<String>
    )
    @Serializable
    data class SeqView(val start: Long, val end: Long, val rows: List<RowView>)
    @Serializable
    data class RowView(val address: Long, val file: String?, val line: Int, val column: Int, val endSequence: Boolean, val isStmt: Boolean)

    private fun versionDetail(id: Long, idx: DwarfIndex): VersionDetail = VersionDetail(
        versionId = id,
        rawSha256 = idx.rawSha256,
        elfClass = if (idx.elf.is64) "ELF64" else "ELF32",
        cus = idx.cus.map { cu ->
            CuView(
                offset = cu.offset.toLong(), version = cu.version, name = cu.name,
                compDir = cu.compDir, dwoName = cu.dwoName, skeleton = cu.skeletonFor,
                split = cu.split, ranges = cu.ranges,
                sequences = cu.sequences.map { s ->
                    SeqView(s.startAddress, s.rows.last().address,
                        s.rows.map { RowView(it.address, it.file?.fullPath, it.line, it.column, it.endSequence, it.isStmt) })
                },
                scopeCount = idx.scopes.count { it.cuOffset == cu.offset },
                notes = cu.notes
            )
        },
        sections = idx.sections,
        warnings = idx.warnings
    )
}
