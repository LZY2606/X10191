package com.compass.web

import com.compass.dwarf.*
import com.compass.store.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.http.content.forEachPart
import io.ktor.server.response.*
import io.ktor.server.http.content.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.*
import java.io.File

class WebServer(private val repo: Repository, private val queries: QueryService) {
    private fun jstr(v: String?): JsonElement = if (v == null) JsonNull else JsonPrimitive(v)

    private fun sectionMap(bundle: VersionBundle): JsonArray = buildJsonArray {
        for (f in bundle.files) {
            for (s in f.elf.sections) add(buildJsonObject {
                put("file", f.filename)
                put("index", s.index); put("name", s.name)
                put("type", s.type); put("flags", hx(s.flags)); put("addr", hx(s.addr))
                put("offset", hx(s.fileOffset)); put("size", hx(s.size))
                put("alignment", hx(s.addralign))
                put("parsed", bundle.merged.sectionsParsed.contains(s.name) ||
                    bundle.dwoBundles.any { it.sectionsParsed.contains(s.name) })
            })
        }
    }

    private fun versionDetail(bundle: VersionBundle) = buildJsonObject {
        put("versionId", bundle.versionId)
        put("files", buildJsonArray {
            for (f in bundle.files) add(buildJsonObject {
                put("id", f.fileId); put("filename", f.filename); put("role", f.role)
                put("summary", buildJsonObject {
                    put("size", f.summary.size); put("sha256", f.summary.sha256)
                    put("head16", f.summary.head16); put("tail16", f.summary.tail16)
                })
                put("elfClass", if (f.elf.is64) "ELF64" else "ELF32")
                put("machine", f.elf.machine)
                put("linkBase", hx(f.elf.linkBase()))
                put("sectionsParsed", JsonArray(f.parsed.sectionsParsed.map { JsonPrimitive(it) }))
            })
        })
        put("sections", sectionMap(bundle))
        put("cus", buildJsonArray {
            for (cu in bundle.merged.cus) add(cuJson(cu))
        })
        put("issues", buildJsonArray {
            bundle.merged.issues.forEach { add(issueJson(it)) }
        })
    }

    private fun issueJson(i: ParseIssue) = buildJsonObject {
        put("scope", i.scope); put("message", i.message); put("severity", i.severity)
    }

    private fun cuJson(cu: CuInfo) = buildJsonObject {
        put("offset", hx(cu.offset)); put("version", cu.version); put("dwarf64", cu.dwarf64)
        put("unitType", cu.unitType); put("isSplit", cu.isSplit)
        put("dwoId", (cu.dwoId?.let { JsonPrimitive(hx(it)) } ?: JsonNull) as JsonElement)
        put("name", jstr(cu.name)); put("compDir", jstr(cu.compDir))
        put("lowPc", (cu.lowPc?.let { JsonPrimitive(hx(it)) } ?: JsonNull) as JsonElement)
        put("dwoResolved", cu.dwoResolved)
        put("ranges", buildJsonArray {
            cu.ranges.forEach { r -> add(buildJsonObject {
                put("low", hx(r.low)); put("high", hx(r.high)); put("length", hx(r.high - r.low))
                put("zeroLength", r.zeroLength)
            }) }
        })
        put("issues", JsonArray(cu.issues.map { issueJson(it) }))
        put("line", (cu.lineTable?.let { Json.parseToJsonElement(JsonCodec.lineTable(it)) } ?: JsonNull) as JsonElement)
        put("dies", Json.parseToJsonElement(JsonCodec.dies(cu.dies)))
    }

    fun start(host: String, port: Int) {
        embeddedServer(Netty, port = port, host = host) {
            install(ContentNegotiation) { json(JsonCodec.json) }
            routing {
                get("/api/health") { call.respond(buildJsonObject { put("ok", true); put("name", "行址罗盘") }) }

                get("/api/versions") {
                    call.respond(buildJsonObject {
                        put("versions", buildJsonArray {
                            repo.versions().forEach { v ->
                                add(buildJsonObject {
                                    put("id", v.id); put("label", v.label); put("createdAt", v.createdAt)
                                    put("note", jstr(v.note))
                                    put("imported", repo.bundle(v.id) != null)
                                })
                            }
                        })
                    })
                }

                post("/api/versions") {
                    val body = call.receive<JsonObject>()
                    val label = body["label"]?.jsonPrimitive?.content ?: "version-${System.currentTimeMillis()}"
                    val id = repo.createVersion(label, body["note"]?.jsonPrimitive?.contentOrNull)
                    call.respond(buildJsonObject { put("id", id); put("label", label) })
                }

                get("/api/versions/{id}") {
                    val id = call.parameters["id"]!!.toLong()
                    val bundle = repo.bundle(id) ?: return@get call.respondText("version not found", status = HttpStatusCode.NotFound)
                    call.respond(versionDetail(bundle))
                }

                post("/api/versions/{id}/import") {
                    val id = call.parameters["id"]!!.toLong()
                    val multipart = call.receiveMultipart()
                    var filename = "debug-file"
                    var role = "main"
                    var bytes: ByteArray? = null
                    multipart.forEachPart { part ->
                        when (part) {
                            is io.ktor.http.content.PartData.FormItem -> if (part.name == "role") role = part.value
                            is io.ktor.http.content.PartData.FileItem -> {
                                filename = part.originalFileName ?: filename
                                val input = part.provider()
                                val n = input.remaining.toInt()
                                val arr = ByteArray(n)
                                for (idx in 0 until n) arr[idx] = input.readByte()
                                bytes = arr
                            }
                            else -> {}
                        }
                        part.dispose()
                    }
                    val data = bytes ?: return@post call.respondText("missing file", status = HttpStatusCode.BadRequest)
                    val imported = try {
                        repo.importFile(id, filename, data, role)
                    } catch (e: ParseException) {
                        return@post call.respondText("ELF/DWARF 解析失败: ${e.message}", status = HttpStatusCode.UnprocessableEntity)
                    }
                    call.respond(buildJsonObject {
                        put("fileId", imported.fileId); put("filename", imported.filename)
                        put("sha256", imported.summary.sha256); put("size", imported.summary.size)
                        put("cuCount", imported.parsed.cus.size)
                        put("issues", JsonArray(imported.parsed.issues.map { issueJson(it) }))
                    })
                }

                get("/api/versions/{id}/query") {
                    val id = call.parameters["id"]!!.toLong()
                    val addr = call.request.queryParameters["addr"] ?: return@get call.respondText("missing addr", status = HttpStatusCode.BadRequest)
                    val crashId = call.request.queryParameters["crashId"]?.toLong()
                    val gen = call.request.queryParameters["generation"]?.toInt()
                    val bias = call.request.queryParameters["bias"]
                    val mode = call.request.queryParameters["mode"] ?: "runtime"
                    val results = if (mode == "relative") listOf(queries.resolveRelative(id, addr, crashId))
                    else queries.resolve(id, addr, crashId, gen, bias)
                    call.respond(buildJsonObject {
                        put("results", JsonArray(results.map { QueryService.buildJsonObject0(it) }))
                    })
                }

                post("/api/versions/{id}/query-batch") {
                    val id = call.parameters["id"]!!.toLong()
                    val body = call.receive<JsonObject>()
                    val crashId = body["crashId"]?.jsonPrimitive?.contentOrNull?.toLong()
                    val generation = body["generation"]?.jsonPrimitive?.contentOrNull?.toInt()
                    val bias = body["bias"]?.jsonPrimitive?.contentOrNull
                    val mode = body["mode"]?.jsonPrimitive?.contentOrNull ?: "runtime"
                    val raw = body["addresses"]?.jsonPrimitive?.content ?: ""
                    val lines = raw.split("\n", " ", ",", ";", "\t")
                        .map { it.trim() }.filter { it.isNotEmpty() }
                    val out = lines.map { raw ->
                        try {
                            val rs = if (mode == "relative") listOf(queries.resolveRelative(id, raw, crashId))
                            else queries.resolve(id, raw, crashId, generation, bias)
                            buildJsonObject {
                                put("input", raw)
                                put("results", JsonArray(rs.map { QueryService.buildJsonObject0(it) }))
                            }
                        } catch (e: Exception) {
                            buildJsonObject { put("input", raw); put("error", e.message ?: "解析失败") }
                        }
                    }
                    call.respond(buildJsonObject { put("results", JsonArray(out)) })
                }

                post("/api/crashes") {
                    val body = call.receive<JsonObject>()
                    val versionId = body["versionId"]!!.jsonPrimitive.content.toLong()
                    val label = body["label"]?.jsonPrimitive?.content ?: "crash-${System.currentTimeMillis()}"
                    val id = repo.createCrash(versionId, label)
                    call.respond(buildJsonObject { put("id", id); put("versionId", versionId); put("label", label) })
                }

                get("/api/crashes") {
                    call.respond(buildJsonObject {
                        put("crashes", buildJsonArray {
                            repo.crashes().forEach { c ->
                                add(buildJsonObject {
                                    put("id", c.id); put("versionId", c.versionId); put("label", c.label)
                                    put("createdAt", c.createdAt)
                                })
                            }
                        })
                    })
                }

                post("/api/crashes/{id}/loads") {
                    val cid = call.parameters["id"]!!.toLong()
                    val body = call.receive<JsonObject>()
                    val load = repo.addModuleLoad(
                        cid,
                        body["moduleName"]?.jsonPrimitive?.content ?: "main",
                        body["fileSha"]?.jsonPrimitive?.contentOrNull,
                        body["runtimeBase"]!!.jsonPrimitive.content,
                        body["bias"]?.jsonPrimitive?.contentOrNull
                    )
                    call.respond(buildJsonObject {
                        put("id", load.id); put("generation", load.generation)
                        put("runtimeBase", hx(load.runtimeBase)); put("linkBase", hx(load.linkBase))
                        put("bias", hx(load.bias)); put("moduleName", load.moduleName)
                    })
                }

                get("/api/crashes/{id}/loads") {
                    val cid = call.parameters["id"]!!.toLong()
                    call.respond(buildJsonObject {
                        put("loads", buildJsonArray {
                            repo.loads(cid).forEach { l ->
                                add(buildJsonObject {
                                    put("id", l.id); put("generation", l.generation)
                                    put("moduleName", l.moduleName); put("fileSha", jstr(l.fileSha))
                                    put("runtimeBase", hx(l.runtimeBase)); put("linkBase", hx(l.linkBase))
                                    put("bias", hx(l.bias))
                                })
                            }
                        })
                    })
                }

                staticResources("/static", "web")
                get("/") {
                    call.respondText(javaClass.getResource("/web/index.html")!!.readText(),
                        ContentType.Text.Html.withCharset(Charsets.UTF_8))
                }
            }
        }.start(wait = true)
    }
}

private fun hx(v: Long) = "0x${v.toULong().toString(16)}"
