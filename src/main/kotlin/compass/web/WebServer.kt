package compass.web

import compass.dwarf.*
import compass.service.CompassService
import compass.service.ImportException
import compass.store.SectionSummaryRow
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import java.io.File

@Serializable
data class ResolveRequest(val versionId: Long, val address: String, val loadBias: String = "0x0")

@Serializable
data class SnapshotRequest(val versionId: Long, val loadBias: String, val moduleBase: String? = null, val note: String = "")

@Serializable
data class BatchRequest(val snapshotId: Long, val addresses: String, val persist: Boolean = true)

@Serializable
data class SimpleMessage(val message: String, val id: Long? = null)

fun parseHex(s: String): ULong {
    val t = s.trim().removePrefix("0x").removePrefix("0X")
    return t.toULong(16)
}

class WebServer(private val service: CompassService) {
    fun start(host: String, port: Int) {
        embeddedServer(Netty, host = host, port = port) {
            install(ContentNegotiation) { json() }
            routing {
                staticResources("/", "static")
                get("/") {
                    call.respondRedirect("/index.html", permanent = false)
                }
                get("/api/health") {
                    call.respond(mapOf("status" to "ok", "name" to "行址罗盘"))
                }
                route("/api/versions") {
                    get {
                        call.respond(service.versions().map {
                            VersionDto(it.id, it.label, it.fileName, it.sha256, it.createdAt, it.dwarfVersions)
                        })
                    }
                    post("/import") {
                        val multipart = call.receiveMultipart()
                        var label = "imported"
                        var fileName = "unnamed"
                        var bytes: ByteArray? = null
                        multipart.forEachPart { part ->
                            when (part) {
                                is io.ktor.http.content.PartData.FormItem ->
                                    if (part.name == "label") label = part.value
                                is io.ktor.http.content.PartData.FileItem -> {
                                    fileName = File(part.originalFileName ?: "unnamed").name
                                    bytes = part.provider().readBytes()
                                }
                                else -> Unit
                            }
                            part.dispose()
                        }
                        val data = bytes ?: return@post call.respondText("missing file", status = HttpStatusCode.BadRequest)
                        try {
                            val id = service.importFile(label, fileName, data!!)
                            call.respond(SimpleMessage("imported as version $id", id))
                        } catch (e: ImportException) {
                            call.respondText(e.message ?: "import failed", status = HttpStatusCode.BadRequest)
                        }
                    }
                    get("/{id}/sections") {
                        val id = call.parameters["id"]!!.toLong()
                        call.respond(service.db.sectionSummaries(id).map(::toSectionDto))
                    }
                    get("/{id}/cus") {
                        val id = call.parameters["id"]!!.toLong()
                        call.respond(cuDtos(id))
                    }
                    get("/{id}/sequences") {
                        val id = call.parameters["id"]!!.toLong()
                        val cuOffset = call.request.queryParameters["cu"]?.toIntOrNull()
                        call.respond(sequenceDtos(id, cuOffset))
                    }
                    get("/{id}/inlines") {
                        val id = call.parameters["id"]!!.toLong()
                        call.respond(inlineTreeDtos(id))
                    }
                    get("/{id}/ranges") {
                        val id = call.parameters["id"]!!.toLong()
                        call.respond(rangeDtos(id))
                    }
                }
                route("/api/snapshots") {
                    get {
                        val versionId = call.request.queryParameters["versionId"]?.toLongOrNull()
                        call.respond(service.snapshots(versionId).map {
                            mapOf(
                                "id" to it.id, "versionId" to it.versionId,
                                "generation" to it.generation, "loadBias" to "0x${it.loadBias.toString(16)}",
                                "moduleBase" to (it.moduleBase?.let { b -> "0x${b.toString(16)}" }),
                                "note" to it.note, "createdAt" to it.createdAt,
                            )
                        })
                    }
                    post {
                        val req = call.receive<SnapshotRequest>()
                        val id = service.createSnapshot(
                            req.versionId, parseHex(req.loadBias),
                            req.moduleBase?.let { parseHex(it) }, req.note,
                        )
                        call.respond(SimpleMessage("snapshot $id fixed", id))
                    }
                }
                post("/api/resolve") {
                    val req = call.receive<ResolveRequest>()
                    val explanation = service.resolve(req.versionId, parseHex(req.address), parseHex(req.loadBias))
                    call.respond(Explanations.from(explanation))
                }
                post("/api/batch") {
                    val req = call.receive<BatchRequest>()
                    val addrs = extractAddresses(req.addresses)
                    val results = service.resolveWithSnapshot(req.snapshotId, addrs)
                    val id = if (req.persist) service.saveBatch(req.snapshotId, req.addresses, results) else null
                    call.respond(mapOf(
                        "batchId" to id,
                        "results" to results.map { Explanations.from(it) },
                    ))
                }
            }
        }.start(wait = true)
    }

    private fun toSectionDto(r: SectionSummaryRow) =
        SectionDto(r.name, r.size, r.addr, r.allocated, r.sha256, r.error)

    private fun cuDtos(versionId: Long): List<CuDto> {
        val mod = service.module(versionId)
        val all = mod.units.map { false to it } + mod.dwoUnits.map { true to it }
        val links = mod.splitLinks.associateBy { it.skeleton.sectionOffset }
        return all.map { (dwo, cu) ->
            val ranges = mod.rangeResolver.dieRanges(cu.root, cu)
            val link = links[cu.sectionOffset]
            val split = when {
                dwo -> "split-resident"
                link == null -> "none"
                link.resolved -> "linked:${link.dwoName ?: link.dwoId?.toString(16)}"
                else -> "missing:${link.dwoName ?: link.dwoId?.toString(16)}"
            }
            CuDto(
                index = cu.index,
                offset = "0x${cu.sectionOffset.toString(16)}",
                version = cu.version,
                name = cu.name,
                compDir = cu.compDir,
                isDwo = dwo,
                dwoId = cu.dwoId?.toString(16),
                stmtList = cu.stmtList?.let { "0x${it.toString(16)}" },
                ranges = ranges.map { it.toDto() },
                split = split,
            )
        }
    }

    private fun rangeDtos(versionId: Long): List<Map<String, Any?>> {
        val mod = service.module(versionId)
        val out = ArrayList<Map<String, Any?>>()
        for (cu in mod.units) {
            fun walk(die: Die) {
                val ranges = mod.rangeResolver.dieRanges(die, cu)
                if (ranges.isNotEmpty()) {
                    out.add(mapOf(
                        "cu" to cu.name,
                        "dieOffset" to "0x${die.offset.toString(16)}",
                        "tag" to when (die.tag) {
                            Tag.SUBPROGRAM -> "subprogram"
                            Tag.INLINED_SUBROUTINE -> "inlined_subroutine"
                            Tag.LEXICAL_BLOCK -> "lexical_block"
                            Tag.COMPILE_UNIT, Tag.SKELETON_UNIT -> "compile_unit"
                            else -> "0x${die.tag.toString(16)}"
                        },
                        "name" to die.name,
                        "depth" to die.depth,
                        "ranges" to ranges.map { it.toDto() },
                    ))
                }
                die.children.forEach(::walk)
            }
            walk(cu.root)
        }
        return out.sortedBy { it["cu"] as String? }
    }

    private fun sequenceDtos(versionId: Long, cuOffset: Int?): List<Map<String, Any?>> {
        val mod = service.module(versionId)
        val out = ArrayList<Map<String, Any?>>()
        val units = mod.units.filter { cuOffset == null || it.sectionOffset == cuOffset }
        for (cu in units) {
            val stmt = cu.stmtList ?: continue
            val prog = mod.lineParser.parse(stmt, cu.version, isDwo = false) ?: continue
            for (seq in prog.sequences) {
                out.add(mapOf(
                    "cu" to cu.name,
                    "cuVersion" to cu.version,
                    "tableVersion" to prog.tableVersion,
                    "sequence" to seq.index,
                    "start" to "0x${seq.startAddress.toString(16)}",
                    "end" to "0x${seq.endAddress.toString(16)}",
                    "rows" to seq.rows.map { r ->
                        mapOf(
                            "address" to "0x${r.address.toString(16)}",
                            "file" to resolveName(prog, r.fileIndex, cu),
                            "line" to r.line, "column" to r.column,
                            "endSequence" to r.endSequence,
                        )
                    },
                    "trace" to prog.trace.map { t ->
                        mapOf(
                            "address" to "0x${t.address.toString(16)}", "file" to t.file,
                            "line" to t.line, "column" to t.column,
                            "emitted" to t.emitted, "endSequence" to t.endSequence,
                            "opcode" to t.opcode,
                        )
                    },
                ))
            }
        }
        return out
    }

    private fun resolveName(prog: LineProgram, index: Int, cu: CompilationUnit): String? {
        val f = when {
            prog.tableVersion >= 5 -> prog.files.getOrNull(index)
            index == 0 -> prog.files.getOrNull(0) ?: LineFile(cu.name ?: "", 0, 0, 0, null)
            else -> prog.files.getOrNull(index - 1)
        } ?: return null
        val dir = prog.directories.getOrNull((f.dirIndex - 1).coerceAtLeast(0)) ?: cu.compDir
        return if (dir != null) "$dir/${f.name}" else f.name
    }

    private fun inlineTreeDtos(versionId: Long): List<Map<String, Any?>> {
        val mod = service.module(versionId)
        val out = ArrayList<Map<String, Any?>>()
        for (cu in mod.units) {
            fun walk(path: List<Die>, die: Die) {
                if (die.tag == Tag.INLINED_SUBROUTINE || die.tag == Tag.SUBPROGRAM || die.tag == Tag.LEXICAL_BLOCK) {
                    val ranges = mod.rangeResolver.dieRanges(die, cu)
                    out.add(mapOf(
                        "cu" to cu.name,
                        "depth" to die.depth,
                        "name" to die.name,
                        "tag" to when (die.tag) {
                            Tag.SUBPROGRAM -> "subprogram"
                            Tag.INLINED_SUBROUTINE -> "inlined_subroutine"
                            else -> "lexical_block"
                        },
                        "callLine" to die.attr(Attr.CALL_LINE)?.value?.asLong,
                        "callColumn" to die.attr(Attr.CALL_COLUMN)?.value?.asLong,
                        "ranges" to ranges.map { it.toDto() },
                        "path" to path.map { it.name ?: "0x${it.tag.toString(16)}" },
                    ))
                }
                die.children.forEach { walk(path + die, it) }
            }
            walk(emptyList(), cu.root)
        }
        return out
    }

    private val addressRegex = Regex("""(?<!\w)(0x[0-9a-fA-F]+|[0-9a-fA-F]{6,})(?!\w)""")

    fun extractAddresses(raw: String): List<ULong> =
        addressRegex.findAll(raw).map { it.groupValues[1] }.map(::parseHex).toList()
}
