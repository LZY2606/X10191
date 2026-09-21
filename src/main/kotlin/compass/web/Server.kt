package compass.web

import com.fasterxml.jackson.databind.SerializationFeature
import compass.dwarf.*
import compass.resolve.*
import compass.store.*
import io.ktor.http.*
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.util.Base64

fun startServer(repo: Repository, workspace: Workspace, host: String, port: Int) {
    embeddedServer(Netty, host = host, port = port) {
        install(ContentNegotiation) {
            jackson {
                enable(SerializationFeature.INDENT_OUTPUT)
                // Long -> string for exact JS display done on client; keep numeric
            }
        }
        routing {
            get("/") { call.respondText(resource("/web/index.html"), ContentType.Text.Html) }
            get("/app.js") { call.respondText(resource("/web/app.js"), ContentType.Application.JavaScript) }
            get("/styles.css") { call.respondText(resource("/web/styles.css"), ContentType.Text.CSS) }

            route("/api") {
                get("/modules") {
                    call.respond(repo.modules.values
                        .sortedWith(compareBy({ it.key }, { it.version }))
                        .map { ModuleSummaryDto(it.id, it.key, it.version, it.fileName, it.sha256, it.importedAt, it.superseded, it.dwarf.cus.size) })
                }

                get("/modules/{id}") {
                    val id = call.parameters["id"]!!.toLong()
                    val module = repo.modules[id]
                    if (module == null) { call.respond(HttpStatusCode.NotFound, mapOf("error" to "module not found")); return@get }
                    call.respond(detail(module, workspace))
                }

                post("/modules/import") {
                    val req = call.receive<ImportRequest>()
                    if (req.base64.isNullOrBlank()) {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "missing base64 ELF payload")); return@post
                    }
                    val bytes = Base64.getDecoder().decode(req.base64)
                    val key = (req.key?.takeIf { it.isNotBlank() } ?: req.fileName ?: "module").let {
                        Regex("[^A-Za-z0-9_.-]").replace(it, "_")
                    }
                    val module = try {
                        repo.importModule(key, req.fileName ?: key, bytes)
                    } catch (e: Exception) {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to ("导入失败: ${e.message}"))); return@post
                    }
                    call.respond(ModuleSummaryDto(module.id, module.key, module.version, module.fileName, module.sha256, module.importedAt, module.superseded, module.dwarf.cus.size))
                }

                post("/query/relative") {
                    val req = call.receive<RelativeQueryRequest>()
                    val module = repo.moduleByKeyVersion(req.moduleKey, req.moduleVersion)
                    if (module == null) { call.respond(HttpStatusCode.NotFound, mapOf("error" to "module version not found")); return@post }
                    val exp = workspace.engineFor(module).resolveRelative(req.relative, req.loadBias, req.generation)
                    call.respond(toQueryDto(exp))
                }

                post("/snapshots") {
                    val req = call.receive<SnapshotRequest>()
                    val loads = req.loads.map { l ->
                        val module = repo.moduleByKeyVersion(l.moduleKey, l.moduleVersion)
                            ?: throw IllegalArgumentException("未知模块 ${l.moduleKey}@${l.moduleVersion}")
                        ModuleLoad(module.key, module.version, l.loadBias, l.generation, l.label)
                    }
                    val snap = repo.createSnapshot(req.name, loads)
                    call.respond(mapOf("id" to snap.id, "name" to snap.name, "createdAt" to snap.createdAt, "loads" to loads))
                }
                get("/snapshots") { call.respond(repo.listSnapshots()) }

                post("/batches") {
                    val req = call.receive<BatchRequest>()
                    val snap = repo.snapshot(req.snapshotId)
                        ?: run { call.respond(HttpStatusCode.NotFound, mapOf("error" to "snapshot not found")); return@post }
                    val addrs = workspace.parseAddresses(req.raw)
                    val batch = repo.saveCrashBatch(req.name ?: "batch", snap.id, req.raw, addrs)
                    val results = workspace.resolveBatch(snap, addrs)
                    call.respond(mapOf("batch" to batch, "results" to results.map { batchResultDto(it) }))
                }
                get("/batches") { call.respond(repo.listCrashBatches()) }
            }
        }
    }.start(wait = true)
}

data class ModuleSummaryDto(val id: Long, val key: String, val version: Int, val fileName: String, val sha256: String, val importedAt: String, val superseded: Boolean, val cuCount: Int)

private fun tagName(tag: Int): String = when (tag) {
    DW.TAG_compile_unit -> "DW_TAG_compile_unit"
    DW.TAG_subprogram -> "DW_TAG_subprogram"
    DW.TAG_inlined_subroutine -> "DW_TAG_inlined_subroutine"
    else -> "TAG_0x${tag.toString(16)}"
}

private fun detail(module: LoadedModule, workspace: Workspace): ModuleDetailDto {
    val engine = workspace.engineFor(module)
    val scopes = HashMap<Int, List<ScopeDto>>()
    val sequences = HashMap<Int, List<SequenceDto>>()
    val rows = HashMap<Int, List<LineRowDto>>()
    val cus = module.dwarf.cus.map { cu ->
        val se = engine.scopesFor(cu.index)
        scopes[cu.index] = se.map { s ->
            ScopeDto(s.name, s.linkageName, tagName(s.die.tag), s.die.offset, s.depth, s.isInline,
                s.ranges.map { RangeDto(it.start, it.end, it.length, it.length == 0L) },
                s.callFile, s.callLine)
        }
        val lp = cu.lineProgram
        sequences[cu.index] = lp?.sequences?.map {
            SequenceDto(it.index, it.startAddress, it.endAddress, it.rows.size, cu.index)
        }.orEmpty()
        rows[cu.index] = lp?.sequences?.flatMap { seq ->
            seq.rows.map { r ->
                val f = lp.files.getOrNull(r.file - 1) ?: lp.files.getOrNull(r.file)
                LineRowDto(r.address, f?.fullPath ?: f?.name, r.line, r.column, r.isStatement,
                    r.endSequence, r.basicBlock, r.prologueEnd, r.epilogueBegin,
                    r.discriminator, seq.index)
            }
        }.orEmpty()
        CuDto(cu.index, cu.version, cu.unitType, cu.offset,
            (cu.root.attr(DW.AT_name) as? AttrValue.Str)?.value,
            (cu.root.attr(DW.AT_comp_dir) as? AttrValue.Str)?.value,
            cu.dwoName, cu.tableVersion, cu.warnings,
            se.size, lp?.sequences?.size ?: 0)
    }
    return ModuleDetailDto(module.id, module.key, module.version, module.fileName, module.sha256,
        module.importedAt, module.superseded, module.dwarf.digests, module.dwarf.warnings,
        cus, scopes, sequences, rows)
}

private fun toQueryDto(e: QueryExplanation): QueryResponseDto = QueryResponseDto(
    e.resolved, e.loadBias, e.generation, e.moduleKey, e.moduleVersion,
    e.candidates.map { c ->
        CandidateDto(c.moduleKey, c.moduleVersion, c.moduleFileName, c.loadBias, c.generation,
            c.inputAddress, c.relativeAddress, c.cuName, c.cuCompDir, c.cuOffset, c.cuVersion,
            c.tableVersion, c.scopeName, c.filePath, c.line, c.column, c.sequenceIndex,
            c.matchedRangeStart, c.matchedRangeEnd, c.matchedRangeLength, c.inlineDepth,
            c.inlineChain, c.priority, c.source, c.dwoMissing, c.warnings)
    },
    e.warnings, e.notes,
)

private fun batchResultDto(r: BatchAddressResult) = mapOf(
    "ordinal" to r.ordinal,
    "inputAddress" to r.inputAddress,
    "moduleKey" to r.moduleKey,
    "moduleVersion" to r.moduleVersion,
    "relativeAddress" to r.relativeAddress,
    "loadBias" to r.loadBias,
    "generation" to r.generation,
    "error" to r.error,
    "explanation" to r.explanation?.let { toQueryDto(it) },
)


private fun resource(path: String): String =
    object {}.javaClass.getResourceAsStream(path)?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }
        ?: error("missing resource $path")
