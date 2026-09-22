package compass.web

import compass.db.Db
import compass.dwarf.DwarfParser
import compass.elf.ElfParser
import compass.query.QueryEngine
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class SnapshotModuleSpec(val moduleVersionId: Long, val loadBase: String, val generation: Int = 1)

@Serializable
data class SnapshotRequest(val name: String, val modules: List<SnapshotModuleSpec>)

@Serializable
data class QueryRequest(val snapshotId: Long, val addresses: List<String>, val saveRecord: Boolean = false)

fun installApp(db: Db, host: String, port: Int) {
    val engine = QueryEngine(db)
    val json = Json { prettyPrint = true }
    embeddedServer(CIO, host = host, port = port) {
        install(ContentNegotiation) { json(json) }
        routing {
            get("/") { call.respondText(homePage(db), ContentType.Text.Html) }
            get("/modules/{id}") {
                val id = call.parameters["id"]!!.toLong()
                call.respondText(modulePage(db, id), ContentType.Text.Html)
            }
            get("/query") {
                val sid = call.request.queryParameters["snapshot"]?.toLongOrNull()
                val addrs = call.request.queryParameters["addresses"].orEmpty()
                call.respondText(queryPage(db, engine, sid, addrs), ContentType.Text.Html)
            }
            get("/records") { call.respondText(recordsPage(db), ContentType.Text.Html) }

            post("/import") {
                val multipart = call.receiveMultipart()
                var moduleName = "module"
                var fileBytes: ByteArray? = null
                while (true) {
                    when (val part = multipart.readPart() ?: break) {
                        is PartData.FormItem -> if (part.name == "name") moduleName = part.value.ifBlank { "module" }
                        is PartData.FileItem -> if (part.name == "file") fileBytes = part.provider().readBytes()
                        else -> {}
                    }
                    part.dispose()
                }
                val bytes = fileBytes ?: return@post call.respondText("no file uploaded", status = HttpStatusCode.BadRequest)
                val result = importBytes(db, moduleName, bytes)
                call.respondText(result, ContentType.Text.Html)
            }

            post("/api/import") {
                val moduleName = call.request.queryParameters["name"] ?: "module"
                val bytes = call.receive<ByteArray>()
                val id = importBytesQuiet(db, moduleName, bytes)
                call.respond(mapOf("moduleVersionId" to id.toString()))
            }

            post("/api/snapshots") {
                val req = call.receive<SnapshotRequest>()
                val mods = req.modules.map {
                    Triple(it.moduleVersionId, it.loadBase.removePrefix("0x").toLong(16), it.generation)
                }
                val id = db.createSnapshot(req.name, mods)
                call.respond(mapOf("snapshotId" to id.toString()))
            }

            post("/api/query") {
                val req = call.receive<QueryRequest>()
                val addrs = parseAddresses(req.addresses.joinToString(" "))
                val resp = engine.query(req.snapshotId, addrs)
                if (req.saveRecord) {
                    db.saveCrashRecord(req.snapshotId, req.addresses.joinToString("\n"), json.encodeToString(resp))
                }
                call.respond(resp)
            }

            get("/api/modules") {
                call.respond(moduleList(db))
            }
        }
    }.start(wait = true)
}

fun parseAddresses(text: String): List<Long> =
    text.split(Regex("[\\s,;]+")).filter { it.isNotBlank() }.map { tok ->
        val t = tok.trim()
        if (t.startsWith("0x") || t.startsWith("0X")) t.drop(2).toLong(16)
        else if (t.any { it in 'a'..'f' || it in 'A'..'F' }) t.toLong(16)
        else t.toLong()
    }

fun importBytesQuiet(db: Db, name: String, bytes: ByteArray): Long {
    val elf = ElfParser.parse(bytes)
    val sections = elf.sections.associate { it.name to it.bytes }
    val parsed = DwarfParser(sections, elf.littleEndian).parse()
    return db.importModule(name, elf, bytes, parsed)
}

fun importBytes(db: Db, name: String, bytes: ByteArray): String {
    return try {
        val id = importBytesQuiet(db, name, bytes)
        """<html><body><p>导入成功：<a href="/modules/$id">$name (module_version #$id)</a></p>
           <p><a href="/">返回行址罗盘首页</a></p></body></html>"""
    } catch (e: Exception) {
        """<html><body><p>导入失败：${e.message}</p><p><a href="/">返回</a></p></body></html>"""
    }
}
