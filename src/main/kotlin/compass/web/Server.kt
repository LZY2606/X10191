package compass.web

import compass.dwarf.DwarfNames
import compass.dwarf.DW
import compass.model.ElfFile
import compass.storage.BatchExplanationDto
import compass.storage.CrashDto
import compass.storage.CuDto
import compass.storage.ExplanationDto
import compass.storage.FileDto
import compass.storage.ImportResponse
import compass.storage.IssueDto
import compass.storage.LineEventDto
import compass.storage.LineRowDto
import compass.storage.ProgramDto
import compass.storage.RangeDto
import compass.storage.SectionDto
import compass.storage.SegmentDto
import compass.storage.SequenceDto
import compass.storage.SnapshotDto
import compass.storage.SymbolDto
import compass.storage.VersionDetail
import compass.storage.VersionDto
import compass.storage.Workspace
import compass.storage.toDto
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receiveMultipart
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.http.content.PartData
import io.ktor.server.http.content.staticResources
import kotlinx.serialization.Serializable
import java.lang.NumberFormatException

@Serializable
data class SnapshotRequest(val versionId: Long, val label: String, val loadBase: String, val generation: Int = 1)

class WebServer(private val workspace: Workspace) {
    fun start(host: String, port: Int) {
        embeddedServer(Netty, host = host, port = port) { module() }.start(wait = true)
    }

    fun Application.module() {
        install(ContentNegotiation) { json() }
        install(StatusPages) {
            exception<Throwable> { call, cause ->
                call.respond(
                    HttpStatusCode.BadRequest,
                    mapOf("error" to (cause.message ?: cause.javaClass.simpleName)),
                )
            }
        }
        routing {
            get("/") {
                val html = javaClass.getResourceAsStream("/web/index.html")?.readBytes()
                    ?: error("index.html missing")
                call.respondText(String(html, Charsets.UTF_8), ContentType.Text.Html)
            }
            staticResources("/static", "web")

            get("/api/health") { call.respond(mapOf("status" to "ok", "name" to "行址罗盘")) }

            get("/api/versions") {
                call.respond(workspace.versions().map {
                    VersionDto(it.id, it.originalFilename, it.sha256, it.buildId, it.elfClass, it.machine, it.importedAt)
                })
            }

            post("/api/versions/import") {
                val multipart = call.receiveMultipart()
                var filename = "uploaded.elf"
                var bytes: ByteArray? = null
                multipart.forEachPart { part ->
                    if (part is PartData.FileItem) {
                        filename = part.originalFileName ?: filename
                        bytes = part.provider().readBytes()
                    }
                    part.dispose()
                }
                val data = bytes ?: error("no file part")
                val existed = workspace.versions().firstOrNull {
                    it.sha256 == compass.elf.ElfParser.sha256(data)
                }
                val id = workspace.importFile(filename, data)
                val parsed = workspace.parsed(id)
                call.respond(ImportResponse(id, parsed.fileSha, parsed.elf.buildId, existed != null, parsed.issues.size))
            }

            get("/api/versions/{id}") {
                val id = call.parameters["id"]!!.toLong()
                val v = workspace.versions().firstOrNull { it.id == id } ?: error("version not found")
                val parsed = workspace.parsed(id)
                val elf: ElfFile = parsed.elf
                val sections = elf.sections.map {
                    SectionDto(it.name, it.addr, it.fileOffset, it.size,
                        if (it.data.isNotEmpty()) compass.elf.ElfParser.sha256(it.data) else null,
                        it.isDebug, it.type, it.flags)
                }
                val segments = parsed.elf.segments.map {
                    SegmentDto(it.flags, it.fileOffset, it.vaddr, it.filesz, it.memsz)
                }
                val cus = parsed.units.map {
                    CuDto(
                        it.headerOffset, it.name, it.compDir, it.version, it.unitType, it.dies.size,
                        it.dwoId?.toString(16), it.dwoName, it.isSkeleton, it.isSplit, it.sourceLanguage,
                    )
                }
                val programs = parsed.linePrograms.map { p ->
                    ProgramDto(
                        p.cuHeaderOffset, p.version,
                        p.files.map { FileDto(it.id, it.name, it.dirIndex, it.mtime, it.size) },
                        p.dirs, p.defaultIsStmt, p.minimumInstructionLength, p.maximumOperationsPerInstruction,
                        p.sequences.map { s ->
                            SequenceDto(
                                s.cuHeaderOffset, s.index, p.version, s.selector, s.start, s.end,
                                s.rows.map { row ->
                                    LineRowDto(row.address, row.file, row.line, row.column,
                                        row.endSequence, row.isStmt, row.basicBlock, row.prologueEnd,
                                        row.epilogueBegin, row.isa, row.discriminator)
                                },
                            )
                        },
                    )
                }
                val rr = compass.dwarf.RangeResolver(compass.dwarf.DebugSections(elf))
                val symbols = compass.dwarf.DwarfFileParser.symbols(parsed, rr).map { s ->
                    SymbolDto(
                        s.cuHeaderOffset, s.dieOffset, DwarfNames.tag(s.tag), s.name, s.linkageName,
                        s.ranges.map { RangeDto(it.selector, it.start, it.end, it.start == it.end) },
                        s.depth, s.isInline,
                        callLine = s.callLine, callColumn = s.callColumn, explicitPriority = s.explicitPriority,
                    )
                }
                val issues: List<IssueDto> = parsed.issues.map { it.toDto() }
                val events = parsed.linePrograms.flatMap { lp ->
                    lp.events.map { ev ->
                        val row = ev.row
                        LineEventDto(
                            ev.seqIndex, ev.trigger,
                            LineRowDto(row.address, row.file, row.line, row.column, row.endSequence,
                                row.isStmt, row.basicBlock, row.prologueEnd, row.epilogueBegin,
                                row.isa, row.discriminator, ev.trigger),
                        )
                    }
                }
                val dwoMissing = parsed.units.filter { it.isSkeleton && it.dwoId != null && !parsed.dwoUnits.containsKey(it.dwoId) }
                    .map { it.dwoName ?: "dwo_id=${it.dwoId?.toString(16)}" }
                val dwoAvailable = parsed.dwoUnits.values.map { it.name ?: "dwo_id=${it.dwoId?.toString(16)}" }
                call.respond(
                    VersionDetail(
                        VersionDto(v.id, v.originalFilename, v.sha256, v.buildId, v.elfClass, v.machine, v.importedAt),
                        sections, segments, cus, programs, symbols, issues, events,
                        parsed.hasSplitRefs, dwoAvailable, dwoMissing,
                    )
                )
            }

            get("/api/versions/{id}/snapshots") {
                val id = call.parameters["id"]!!.toLong()
                call.respond(workspace.snapshots(id).map { SnapshotDto.from(it) })
            }

            post("/api/snapshots") {
                val req = call.receive<SnapshotRequest>()
                val loadBase = parseAddress(req.loadBase)
                val snapId = workspace.addSnapshot(req.versionId, req.label, loadBase, req.generation)
                call.respond(workspace.snapshots(req.versionId).first { it.id == snapId }.let { SnapshotDto.from(it) })
            }

            post("/api/resolve") {
                val req = call.receive<compass.storage.ResolveRequest>()
                val addrs = req.addresses.map { parseAddress(it) }
                val explanations = addrs.map { workspace.resolve(req.versionId, it, req.selector, req.snapshotIds) }
                var crashId: Long? = null
                if (req.saveAs != null) {
                    crashId = workspace.saveCrash(req.saveAs, req.versionId,
                        req.snapshotIds?.firstOrNull(), addrs, explanations)
                }
                call.respond(BatchExplanationDto(
                    explanations.map { ExplanationDto.from(it) },
                    orderStable = true, crashId = crashId,
                ))
            }

            get("/api/crashes") {
                call.respond(workspace.crashes().map {
                    CrashDto(it.id, it.label, it.createdAt, it.id, it.addressesJson, it.resultJson, it.versionFingerprint)
                })
            }
        }
    }

    private fun parseAddress(s: String): Long {
        val t = s.trim().substringBefore('#').trim().substringBefore(";").trim()
        return if (t.startsWith("0x") || t.startsWith("0X")) java.lang.Long.parseUnsignedLong(t.substring(2), 16)
        else if (t.all { it.isDigit() }) t.toLong()
        else if (t.isNotEmpty() && t.all { it.isLetterOrDigit() }) java.lang.Long.parseUnsignedLong(t, 16)
        else throw NumberFormatException("cannot parse address '$s'")
    }
}
