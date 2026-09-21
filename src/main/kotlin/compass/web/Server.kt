package compass.web

import compass.dwarf.*
import compass.db.Repository
import compass.elf.ElfFile
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.http.content.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.http.content.PartData
import io.ktor.utils.io.toByteArray
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class UploadResp(
    val versionId: Long, val label: String, val fileName: String,
    val cuCount: Int, val splitStatus: String, val issues: List<String>
)

@Serializable
data class VersionDto(
    val id: Long, val label: String, val fileName: String, val kind: String,
    val cuCount: Int, val splitStatus: String,
    val sectionCount: Int, val tableVersions: List<String>
)

@Serializable
data class SectionDto(
    val name: String, val addr: Long, val offset: Long, val size: Long,
    val flags: Long, val sha256: String, val summary: String, val allocated: Boolean
)

@Serializable
data class CuDto(
    val offset: Long, val name: String?, val compDir: String?, val version: String,
    val ranges: List<RangeDto>, val sequenceCount: Int, val split: Boolean, val issues: List<String>
)

@Serializable
data class RangeDto(val low: Long, val high: Long, val zeroLength: Boolean)

@Serializable
data class SnapshotReq(
    val versionId: Long, val moduleName: String,
    val preferredBase: Long, val loadBase: Long, val generation: Int
)

@Serializable
data class BatchReq(val versionId: Long, val text: String, val snapshotId: Long? = null)

@Serializable
data class SaveCrashReq(
    val versionId: Long, val label: String, val snapshotId: Long? = null, val text: String
)

@Serializable
data class LineHitDto(
    val file: String, val line: Int, val column: Int, val sequenceIndex: Int,
    val rowAddress: Long, val tableVersion: String
)

@Serializable
data class InlineFrameDto(
    val function: String, val depth: Int, val callFile: String?, val callLine: Int,
    val rangeLow: Long, val rangeHigh: Long, val dieOffset: Long
)

@Serializable
data class CandidateDto(
    val rank: Int, val cuName: String?, val compDir: String?,
    val line: LineHitDto?, val sequenceIndex: Int,
    val inlineChain: List<InlineFrameDto>, val coveringFunction: String?,
    val confidence: String, val tieKey: String
)

@Serializable
data class QueryResultDto(
    val ordinal: Int, val input: String,
    val runtimePc: Long, val relativePc: Long, val loadBias: Long,
    val module: String?, val generation: Int?,
    val candidates: List<CandidateDto>,
    val trusted: List<String>, val warnings: List<String>, val tableVersions: List<String>
)

fun Application.compassModule(repo: Repository, db: compass.db.CompassDatabase) {
    install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; prettyPrint = false }) }
    routing {
        get("/") { call.respondRedirect("/static/index.html") }

        route("/api") {
            get("/versions") {
                call.respond(repo.allVersions().map { v ->
                    VersionDto(
                        v.id, v.label, v.fileName, v.kind, v.info.units.size,
                        v.info.splitStatus.name, v.elf.sections.size,
                        v.info.units.map { it.tableVersion }.distinct()
                    )
                })
            }

            post("/import") {
                val multipart = call.receiveMultipart()
                var label = "导入"
                var kind = "debug"
                var main: ByteArray? = null
                var mainName = "debug.bin"
                var dwo: ByteArray? = null
                while (true) {
                    val part = multipart.readPart() ?: break
                    try {
                        when (part) {
                            is PartData.FormItem -> when (part.name) {
                                "label" -> label = part.value
                                "kind" -> kind = part.value
                            }
                            is PartData.FileItem -> when (part.name) {
                                "file" -> {
                                    mainName = part.originalFileName ?: mainName
                                    main = part.provider().toByteArray()
                                }
                                "dwo" -> dwo = part.provider().toByteArray()
                            }
                            else -> {}
                        }
                    } finally { part.dispose() }
                }
                val bytes = main ?: return@post call.respondText("缺少 file", status = HttpStatusCode.BadRequest)
                val v = repo.importDebugFile(bytes, mainName, label, kind, dwo)
                call.respond(UploadResp(
                    v.id, v.label, v.fileName, v.info.units.size,
                    v.info.splitStatus.name, v.info.issues.map { "[${it.section}] ${it.message}" }
                ))
            }

            get("/version/{id}/sections") {
                val id = call.parameters["id"]!!.toLong()
                val rows = db.listSections(id)
                call.respond(rows.map { r ->
                    val flags = (r["flags"] as? Long) ?: 0L
                    SectionDto(
                        r["name"] as String, (r["addr"] as Long), (r["offset"] as Long),
                        (r["size"] as Long), flags, r["sha256"] as String,
                        r["byte_summary"] as String, (flags and 2L) != 0L
                    )
                })
            }

            get("/version/{id}/cus") {
                val id = call.parameters["id"]!!.toLong()
                val v = repo.version(id) ?: return@get call.respondText("未知版本", status = HttpStatusCode.NotFound)
                call.respond(v.info.units.map { cu ->
                    CuDto(
                        cu.offset, cu.name, cu.compDir, cu.tableVersion,
                        cuRanges(cu).map { RangeDto(it.low, it.high, it.zeroLength) },
                        cu.lineProgram?.sequences?.size ?: 0, cu.isSplit, cu.issues
                    )
                })
            }

            get("/version/{id}/ranges") {
                val id = call.parameters["id"]!!.toLong()
                val v = repo.version(id) ?: return@get call.respondText("未知版本", status = HttpStatusCode.NotFound)
                call.respond(allFunctionRanges(v.info))
            }

            get("/version/{id}/line/{cuOffset}") {
                val id = call.parameters["id"]!!.toLong()
                val cuOff = call.parameters["cuOffset"]!!.toLong()
                val v = repo.version(id) ?: return@get call.respondText("未知版本", status = HttpStatusCode.NotFound)
                val cu = v.info.units.firstOrNull { it.offset == cuOff }
                    ?: return@get call.respondText("未知 CU", status = HttpStatusCode.NotFound)
                call.respond(lineProgramView(cu))
            }

            post("/snapshot") {
                val req = call.receive<SnapshotReq>()
                val sid = repo.addSnapshot(req.versionId, req.moduleName, req.preferredBase, req.loadBase, req.generation)
                call.respond(mapOf("snapshotId" to sid, "loadBias" to (req.loadBase - req.preferredBase)))
            }

            get("/snapshots/{versionId}") {
                val vid = call.parameters["versionId"]!!.toLong()
                call.respond(db.listSnapshots(vid).map {
                    mapOf(
                        "id" to it["id"], "moduleName" to it["module_name"],
                        "preferredBase" to it["preferred_base"], "loadBase" to it["load_base"],
                        "generation" to it["generation"]
                    )
                })
            }

            post("/query") {
                val req = call.receive<BatchReq>()
                val load = req.snapshotId?.let { repo.snapshot(it) }
                val hits = repo.resolveBatch(req.versionId, req.text, load)
                call.respond(hits.map { dto(it, load) })
            }

            post("/crash") {
                val req = call.receive<SaveCrashReq>()
                val load = req.snapshotId?.let { repo.snapshot(it) }
                val hits = repo.resolveBatch(req.versionId, req.text, load)
                val crashId = repo.saveCrash(req.label, req.snapshotId, req.versionId, hits)
                call.respond(mapOf("crashId" to crashId, "frames" to hits.size))
            }

            get("/crashes/{versionId}") {
                val vid = call.parameters["versionId"]!!.toLong()
                call.respond(db.listCrashes(vid).map {
                    mapOf(
                        "id" to it["id"], "label" to it["label"],
                        "snapshotId" to it["snapshot_id"], "createdAt" to it["created_at"]
                    )
                })
            }
        }

        staticResources("/static", "static")
    }
}

private fun cuRanges(cu: CompilationUnit): List<PcRange> {
    val out = ArrayList<PcRange>()
    fun walk(die: Die) {
        if (die.isSubprogram || die.isInlinedSubroutine) out.addAll(DieRanges.of(die))
        die.children.forEach(::walk)
    }
    cu.root?.let(::walk)
    return out.sortedBy { it.low }
}

@Serializable
data class FuncRangeDto(
    val cuOffset: Long, val function: String?, val low: Long, val high: Long,
    val zeroLength: Boolean, val inlined: Boolean
)

private fun allFunctionRanges(info: DebugInfo): List<FuncRangeDto> {
    val out = ArrayList<FuncRangeDto>()
    for (cu in info.units) {
        fun walk(die: Die) {
            if (die.isSubprogram || die.isInlinedSubroutine) {
                val name = die.str(DW_AT_linkage_name) ?: die.str(DW_AT_name)
                for (r in DieRanges.of(die)) {
                    out.add(FuncRangeDto(cu.offset, name, r.low, r.high, r.zeroLength, die.isInlinedSubroutine))
                }
            }
            die.children.forEach(::walk)
        }
        cu.root?.let(::walk)
    }
    return out.sortedWith(compareBy({ it.low }, { it.high }))
}

@Serializable
data class LineRowDto(
    val address: Long, val file: String, val line: Int, val column: Int,
    val endSequence: Boolean, val isStmt: Boolean, val basicBlock: Boolean,
    val prologueEnd: Boolean, val epilogueBegin: Boolean, val discriminator: Int
)

@Serializable
data class SequenceDto(val index: Int, val start: Long, val end: Long, val rows: List<LineRowDto>)

@Serializable
data class LineProgramViewDto(
    val version: Int, val files: List<String>, val directories: List<String>,
    val addressSize: Int, val segmentSelectorSize: Int, val sequences: List<SequenceDto>
)

private fun lineProgramView(cu: CompilationUnit): LineProgramViewDto {
    val lp = cu.lineProgram ?: return LineProgramViewDto(0, emptyList(), emptyList(), cu.addressSize, 0, emptyList())
    val seqs = lp.sequences.mapIndexed { i, s ->
        SequenceDto(i, s.start, s.end, s.rows.map { row ->
            val fname = lp.files.getOrNull(row.file - 1)?.name
                ?: lp.files.getOrNull(row.file)?.name ?: "?"
            LineRowDto(row.address, fname, row.line, row.column, row.endSequence, row.isStmt,
                row.basicBlock, row.prologueEnd, row.epilogueBegin, row.discriminator)
        })
    }
    return LineProgramViewDto(
        lp.version, lp.files.map { it.name }, lp.directories,
        lp.addressSize, lp.segmentSelectorSize, seqs
    )
}

private fun dto(hit: compass.db.BatchHit, load: ModuleLoad?): QueryResultDto {
    val r = hit.result
    return QueryResultDto(
        hit.ordinal, hit.input, r.runtimePc, r.relativePc, r.loadBias,
        r.module?.moduleName ?: load?.moduleName,
        r.module?.generation ?: load?.generation,
        r.candidates.map { c ->
            CandidateDto(
                c.rank, c.cuName, c.compDir,
                c.line?.let { LineHitDto(it.file, it.line, it.column, it.sequenceIndex, it.rowAddress, it.tableVersion) },
                c.sequenceIndex,
                c.inlineChain.map { f ->
                    InlineFrameDto(f.function, f.depth, f.callFile, f.callLine, f.rangeLow, f.rangeHigh, f.dieOffset)
                },
                c.coveringFunction, c.confidence, c.tieKey
            )
        },
        r.trusted, r.warnings, r.tableVersions
    )
}

fun startServer(host: String, port: Int, repo: Repository, db: compass.db.CompassDatabase) {
    embeddedServer(Netty, host = host, port = port) {
        compassModule(repo, db)
    }.start(wait = true)
}
