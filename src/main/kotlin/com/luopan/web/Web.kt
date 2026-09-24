package com.luopan.web

import com.luopan.dwarf.*
import com.luopan.service.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.server.request.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

@Serializable
data class ImportRequest(val moduleKey: String, val fileName: String)

@Serializable
data class CrashAddressDto(val label: String? = null, val address: String, val segment: String = "0")

@Serializable
data class CreateCrashRequest(
    val moduleKey: String,
    val title: String,
    val versionId: Long? = null,
    val actualBase: String,
    val preferredBase: String,
    val addresses: List<CrashAddressDto>,
)

@Serializable
data class QueryRequest(
    val moduleKey: String,
    val versionId: Long? = null,
    val actualBase: String,
    val preferredBase: String = "0",
    val addresses: List<CrashAddressDto>,
)

fun Application.configureWeb(store: ImportStore, crashes: CrashService, resolver: Resolver) {
    install(ContentNegotiation) {
        json()
    }
    routing {
        get("/") {
            val html = javaClass.getResourceAsStream("/web/index.html")?.readBytes()
                ?: error("index.html missing")
            call.respondBytes(html, ContentType.Text.Html)
        }

        get("/api/modules") {
            call.respond(mapOf("modules" to store.moduleKeys().map { key ->
                mapOf("moduleKey" to key, "versions" to store.versions(key))
            }))
        }

        post("/api/import") {
            val multipart = call.receiveMultipart()
            var moduleKey = "main"
            var fileName = "uploaded.bin"
            var data: ByteArray? = null
            multipart.forEachPart { part ->
                when (part) {
                    is PartData.FormItem -> {
                        if (part.name == "moduleKey") moduleKey = part.value
                        if (part.name == "fileName") fileName = part.value
                    }
                    is PartData.FileItem -> {
                        fileName = part.originalFileName ?: fileName
                        val input = part.provider()
                        val out = java.io.ByteArrayOutputStream()
                        while (input.canRead()) out.write(input.readByte().toInt())
                        data = out.toByteArray()
                    }
                    else -> {}
                }
                part.dispose()
            }
            val bytes = data ?: return@post call.respondText("no file", status = HttpStatusCode.BadRequest)
            val imp = store.import(moduleKey, fileName, bytes)
            call.respond(importView(imp))
        }

        get("/api/file/{id}") {
            val id = call.parameters["id"]!!.toLong()
            val imp = store.allFiles().firstOrNull { it.versionId == id }
                ?: return@get call.respondText("not found", status = HttpStatusCode.NotFound)
            call.respond(importView(imp))
        }

        get("/api/file/{id}/sections") {
            val id = call.parameters["id"]!!.toLong()
            val imp = store.allFiles().firstOrNull { it.versionId == id }
                ?: return@get call.respondText("not found", status = HttpStatusCode.NotFound)
            call.respond(sectionsView(imp))
        }

        get("/api/file/{id}/ranges") {
            val id = call.parameters["id"]!!.toLong()
            val imp = store.allFiles().firstOrNull { it.versionId == id }
                ?: return@get call.respondText("not found", status = HttpStatusCode.NotFound)
            call.respond(rangesView(imp))
        }

        get("/api/file/{id}/line") {
            val id = call.parameters["id"]!!.toLong()
            val imp = store.allFiles().firstOrNull { it.versionId == id }
                ?: return@get call.respondText("not found", status = HttpStatusCode.NotFound)
            call.respond(lineView(imp))
        }

        get("/api/file/{id}/inline") {
            val id = call.parameters["id"]!!.toLong()
            val imp = store.allFiles().firstOrNull { it.versionId == id }
                ?: return@get call.respondText("not found", status = HttpStatusCode.NotFound)
            call.respond(inlineView(imp))
        }

        post("/api/query") {
            val req = call.receive<QueryRequest>()
            val snap = LoadSnapshot(req.moduleKey, parseHex(req.actualBase), parseHex(req.preferredBase))
            val results = req.addresses.map { dto ->
                resolver.resolve(req.moduleKey, parseHex(dto.address),
                    parseHex(dto.segment), snap, req.versionId)
            }
            call.respond(mapOf("results" to results.map { resultView(it) }))
        }

        post("/api/crashes") {
            val req = call.receive<CreateCrashRequest>()
            val id = crashes.create(
                req.moduleKey, req.title, req.versionId,
                parseHex(req.actualBase), parseHex(req.preferredBase),
                req.addresses.map { CrashAddressInput(it.label, parseHex(it.address), parseHex(it.segment)) },
            )
            call.respond(mapOf("id" to id))
        }

        get("/api/crashes") {
            call.respond(mapOf("crashes" to crashes.list().map { c ->
                mapOf(
                    "id" to c.id, "moduleKey" to c.moduleKey, "title" to c.title,
                    "createdAt" to c.createdAt, "versionId" to c.versionId,
                    "actualBase" to "0x${"%x".format(c.actualBase)}",
                    "preferredBase" to "0x${"%x".format(c.preferredBase)}",
                    "loadBias" to "0x${"%x".format(c.actualBase - c.preferredBase)}",
                    "addresses" to c.addresses.map { (seq, label, addr) ->
                        mapOf("seq" to seq, "label" to label, "address" to "0x${"%x".format(addr)}")
                    },
                )
            }))
        }

        get("/api/crashes/{id}/resolve") {
            val id = call.parameters["id"]!!.toLong()
            val crash = crashes.list().firstOrNull { it.id == id }
                ?: return@get call.respondText("not found", status = HttpStatusCode.NotFound)
            val snap = LoadSnapshot(crash.moduleKey, crash.actualBase, crash.preferredBase)
            val results = crash.addresses.map { (_, label, addr) ->
                resolver.resolve(crash.moduleKey, addr, 0, snap, crash.versionId)
            }
            call.respond(mapOf(
                "crashId" to crash.id, "fixedVersionId" to crash.versionId,
                "loadBias" to "0x${"%x".format(crash.actualBase - crash.preferredBase)}",
                "results" to results.map { resultView(it) },
            ))
        }

        get("/api/generations") {
            val key = call.request.queryParameters["moduleKey"] ?: "main"
            call.respond(mapOf("moduleKey" to key, "generations" to crashes.generations(key)))
        }
    }
}

private fun parseHex(s: String): Long {
    val t = s.trim()
    return if (t.startsWith("0x") || t.startsWith("0X")) java.lang.Long.parseUnsignedLong(t.substring(2), 16)
    else if (t.isEmpty()) 0L
    else t.toLong()
}
