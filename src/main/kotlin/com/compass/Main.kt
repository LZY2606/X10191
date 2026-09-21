package com.compass

import com.compass.store.Database
import com.compass.store.QueryService
import com.compass.store.Repository
import com.compass.web.WebServer

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var dbPath = "compass.db"
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> host = args[++i]
            "--port" -> port = args[++i].toInt()
            "--db" -> dbPath = args[++i]
        }
        i++
    }
    val db = Database(dbPath)
    val repo = Repository(db)
    repo.warmAll()
    val queries = QueryService(repo)
    println("行址罗盘 starting on http://$host:$port")
    WebServer(repo, queries).start(host, port)
}
