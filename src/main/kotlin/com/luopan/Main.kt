package com.luopan

import com.luopan.db.DatabaseFactory
import com.luopan.service.CrashService
import com.luopan.service.ImportStore
import com.luopan.service.LoadSnapshot
import com.luopan.service.Resolver
import com.luopan.web.configureWeb
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.io.File

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var dbPath = "luopan.db"
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> { host = args[++i] }
            "--port" -> { port = args[++i].toInt() }
            "--db" -> { dbPath = args[++i] }
            else -> {}
        }
        i++
    }
    val conn = DatabaseFactory.open(dbPath)
    val store = ImportStore(conn)
    val crashes = CrashService(conn)
    val resolver = Resolver(store)

    embeddedServer(Netty, host = host, port = port) {
        configureWeb(store, crashes, resolver)
    }.start(wait = true)
}
