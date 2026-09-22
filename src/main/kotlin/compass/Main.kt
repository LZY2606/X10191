package compass

import compass.db.AppService
import compass.db.Database
import compass.web.WebServer
import java.nio.file.Paths

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var dbPath = "data/luopan.sqlite"
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
    val db = Database(Paths.get(dbPath))
    val service = AppService(db)
    println("行址罗盘 (Line Address Compass) listening on http://$host:$port")
    WebServer(service).start(host, port)
}
