package com.compass.web

import com.compass.dwarf.DebugFileParser
import com.compass.storage.CreateCrashRequest
import com.compass.storage.Database
import com.compass.storage.QueryEngine
import com.compass.storage.SnapshotModule
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.http.content.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.security.MessageDigest

fun Application.module(database: Database) {
    install(ContentNegotiation) { json() }
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to (cause.message ?: "Invalid request")))
        }
    }
    routing {
        staticResources("/", "web") { default("index.html") }
        route("/api/versions") {
            get { call.respond(database.listVersions().map(::summary)) }
            post {
                val multipart = call.receiveMultipart()
                var filename = "debug-file"
                var bytes: ByteArray? = null
                while (true) {
                    val part = multipart.readPart() ?: break
                    if (part is io.ktor.http.content.PartData.FileItem) {
                        filename = part.originalFileName ?: filename
                        bytes = part.provider().use { input ->
                            val out = java.io.ByteArrayOutputStream()
                            while (input.canRead()) out.write(input.readByte().toInt())
                            out.toByteArray()
                        }
                    }
                    part.dispose()
                }
                val payload = bytes ?: error("Upload a file")
                val digest = MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { "%02x".format(it) }
                val document = DebugFileParser.parse(payload)
                call.respond(database.insertVersion(filename, digest, document))
            }
            get("{id}") { call.respond(database.getVersion(call.parameters["id"]!!.toLong()) ?: throw NotFoundException()) }
        }
        get("/api/crashes") { call.respond(database.listCrashes()) }
        get("/api/crashes/{id}") { call.respond(database.getCrash(call.parameters["id"]!!.toLong()) ?: throw NotFoundException()) }
        post("/api/crashes") {
            val request = call.receive<CreateCrashRequest>()
            val versions = request.modules.mapNotNull { database.getVersion(it.versionId) }.associateBy { it.id }
            val results = QueryEngine.batch(request.addressText, request.modules, versions)
            call.respond(database.insertCrash(request.label, request.addressText, request.modules, results))
        }
        post("/api/query") {
            val request = call.receive<CreateCrashRequest>()
            val versions = request.modules.mapNotNull { database.getVersion(it.versionId) }.associateBy { it.id }
            call.respond(mapOf("results" to QueryEngine.batch(request.addressText, request.modules, versions)))
        }
    }
}

class NotFoundException : RuntimeException("Not found")

private fun summary(version: com.compass.storage.StoredVersion) = mapOf(
    "id" to version.id,
    "createdAt" to version.createdAt,
    "filename" to version.filename,
    "buildId" to version.buildId,
    "byteSha256" to version.byteSha256,
    "elfType" to version.elfType,
    "programBase" to version.programBase,
    "cuCount" to version.document.compilationUnits.size,
    "warnings" to version.document.warnings
)

fun startServer(host: String, port: Int, databasePath: java.nio.file.Path) {
    val database = Database(databasePath)
    io.ktor.server.engine.embeddedServer(Netty, port = port, host = host) { module(database) }.start(wait = true)
}
