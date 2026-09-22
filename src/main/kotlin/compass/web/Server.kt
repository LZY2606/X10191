package compass.web

import compass.db.CrashRow
import compass.db.Repository
import compass.db.SectionJson
import compass.db.SnapshotRow
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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

@Serializable
data class ImportRequest(val module: String? = null, val filename: String? = null, val hexBase64: String? = null)

@Serializable
data class SnapshotRequest(val moduleVersionId: Long, val generation: Int? = null, val loadBias: String = "0x0", val note: String? = null)

@Serializable
data class QueryRequest(val snapshotId: Long, val address: String)

@Serializable
data class BatchQueryRequest(val snapshotId: Long, val addresses: List<String>, val saveAs: String? = null)

fun parseAddress(s: String): Long {
    val t = s.trim().substringBefore('+').substringBefore(' ').removePrefix("0x").removePrefix("0X")
    if (t.isEmpty()) throw NumberFormatException("空地址")
    return java.lang.Long.parseUnsignedLong(t, 16)
}

fun Application.configureServer(repo: Repository) {
    install(ContentNegotiation) {
        json(Json { prettyPrint = true; encodeDefaults = true })
    }
    routing {
        get("/demo-fixture") {
            val bytes = compass.fixture.DemoFixtures.buildFull()
            call.respond(mapOf("hex" to compass.fixture.DemoFixtures.hex(bytes), "size" to bytes.size))
        }

        get("/") {
            val html = javaClass.getResourceAsStream("/web/index.html")?.bufferedReader()?.use { it.readText() }
                ?: return@get call.respond(HttpStatusCode.InternalServerError, "index.html 缺失")
            call.respondText(html, ContentType.Text.Html)
        }

        route("/api") {
            get("modules") {
                call.respond(mapOf("modules" to repo.listModules().map { mapOf("id" to it.first, "name" to it.second) }))
            }
            get("versions") {
                val mid = call.request.queryParameters["moduleId"]?.toLongOrNull()
                call.respond(mapOf("versions" to repo.listVersions(mid)))
            }
            get("versions/{id}") {
                val v = repo.getVersion(call.parameters["id"]!!.toLong())
                    ?: return@get call.respond(HttpStatusCode.NotFound, ApiResult(false, error = "版本不存在"))
                call.respond(v)
            }
            get("versions/{id}/sections") {
                val v = repo.getVersion(call.parameters["id"]!!.toLong())
                    ?: return@get call.respond(HttpStatusCode.NotFound, ApiResult(false, error = "版本不存在"))
                call.respond(mapOf("sections" to v.sections, "digests" to v.sections.filter { it.present }))
            }
            get("versions/{id}/cus") {
                val id = call.parameters["id"]!!.toLong()
                call.respond(mapOf("cus" to repo.cuDetails(id)))
            }
            get("versions/{id}/tree") {
                call.respond(mapOf("trees" to repo.inlineTrees(call.parameters["id"]!!.toLong())))
            }
            get("versions/{id}/lines") {
                call.respond(mapOf("programs" to repo.linePrograms(call.parameters["id"]!!.toLong())))
            }
            get("versions/{id}/lines/{cuOffset}") {
                val map = repo.lineProgram(call.parameters["id"]!!.toLong(), call.parameters["cuOffset"]!!.toLong())
                    ?: return@get call.respond(HttpStatusCode.NotFound, ApiResult(false, error = "行程序不存在"))
                call.respond(map)
            }

            post("import") {
                val req = call.receive<ImportRequest>()
                val raw = try {
                    if (req.hexBase64 == null) throw IllegalArgumentException("需要 hexBase64（hex 或 base64 的 ELF 字节）")
                    decodePayload(req.hexBase64)
                } catch (e: Exception) {
                    return@post call.respond(HttpStatusCode.BadRequest, ApiResult(false, error = "导入负载解码失败：${e.message}"))
                }
                val name = req.module?.takeIf { it.isNotBlank() }
                    ?: (req.filename?.substringAfterLast('/')?.substringAfterLast('\\'))?.takeIf { it.isNotBlank() }
                    ?: "module-${System.currentTimeMillis()}"
                val row = try {
                    repo.importFile(name, req.filename, raw)
                } catch (e: Exception) {
                    return@post call.respond(HttpStatusCode.BadRequest, ApiResult(false, error = "ELF/DWARF 解析失败：${e.message}"))
                }
                call.respond(row)
            }

            route("snapshots") {
                post {
                    val req = call.receive<SnapshotRequest>()
                    val bias = try { parseAddress(req.loadBias) } catch (e: Exception) {
                        return@post call.respond(HttpStatusCode.BadRequest, ApiResult(false, error = "loadBias 非法：${e.message}"))
                    }
                    call.respond(repo.createSnapshot(req.moduleVersionId, req.generation, bias, req.note))
                }
                get {
                    val vid = call.request.queryParameters["moduleVersionId"]?.toLongOrNull()
                    call.respond(mapOf("snapshots" to repo.listSnapshots(vid)))
                }
            }

            post("query") {
                val req = call.receive<QueryRequest>()
                val snap = repo.listSnapshots().firstOrNull { it.id == req.snapshotId }
                    ?: return@post call.respond(HttpStatusCode.NotFound, ApiResult(false, error = "快照不存在"))
                val addr = try { parseAddress(req.address) } catch (e: Exception) {
                    return@post call.respond(HttpStatusCode.BadRequest, ApiResult(false, error = "地址非法：${e.message}"))
                }
                call.respond(repo.query(snap, addr).toDto())
            }

            post("query/batch") {
                val req = call.receive<BatchQueryRequest>()
                val snap = repo.listSnapshots().firstOrNull { it.id == req.snapshotId }
                    ?: return@post call.respond(HttpStatusCode.NotFound, ApiResult(false, error = "快照不存在"))
                val items = req.addresses.map { raw ->
                    val r = try {
                        repo.query(snap, parseAddress(raw)).toDto()
                    } catch (e: Exception) {
                        null
                    }
                    BatchItemDto(raw, raw, r)
                }
                var crashId: Long? = null
                if (!req.saveAs.isNullOrBlank()) crashId = repo.saveCrash(req.saveAs, req.addresses, snap.id)
                call.respond(buildJsonObject {
                    put("snapshotId", JsonPrimitive(snap.id))
                    put("crashId", JsonPrimitive(crashId))
                    put("items", Json.encodeToJsonElement(kotlinx.serialization.builtins.ListSerializer(BatchItemDto.serializer()), items))
                })
            }

            get("crashes") {
                call.respond(mapOf("crashes" to repo.listCrashes()))
            }
        }
    }
}

private fun decodePayload(payload: String): ByteArray {
    val compact = payload.trim().replace(Regex("\\s"), "")
    return when {
        compact.startsWith("0x", true) -> hex(compact.substring(2))
        compact.all { it in "0123456789abcdefABCDEF" } && compact.length % 2 == 0 -> hex(compact)
        else -> java.util.Base64.getDecoder().decode(compact)
    }
}

private fun hex(s: String): ByteArray {
    val out = ByteArray(s.length / 2)
    for (i in out.indices) {
        out[i] = ((Character.digit(s[i * 2], 16) shl 4) + Character.digit(s[i * 2 + 1], 16)).toByte()
    }
    return out
}

fun startServer(repo: Repository, host: String, port: Int) {
    embeddedServer(Netty, host = host, port = port) { configureServer(repo) }.start(wait = true)
}
