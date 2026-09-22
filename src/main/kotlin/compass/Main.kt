package compass

import compass.db.Database
import compass.web.AppService
import compass.web.startServer
import java.io.File

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 8080
    var dbPath = File(System.getProperty("user.dir"), "compass-data/compass.db").absolutePath
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> { host = args[++i] }
            "--port" -> { port = args[++i].toInt() }
            "--db" -> { dbPath = args[++i] }
            else -> System.err.println("unknown arg ${args[i]}")
        }
        i++
    }
    val db = Database(dbPath)
    val service = AppService(db)
    println("行址罗盘 (Line-Address Compass) listening on http://$host:$port")
    startServer(service, host, port)
}
