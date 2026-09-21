package compass

import compass.service.CompassService
import compass.store.Database
import compass.web.WebServer

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
            else -> {
                if (args[i].startsWith("--")) System.err.println("unknown arg ${args[i]}")
            }
        }
        i++
    }
    val db = Database(dbPath)
    val service = CompassService(db)
    println("行址罗盘 listening on http://$host:$port (db=$dbPath)")
    WebServer(service).start(host, port)
}
