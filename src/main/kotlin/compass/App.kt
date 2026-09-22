package compass

import compass.storage.Database
import compass.storage.Workspace
import compass.web.WebServer
import java.io.File

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var dbPath = File(System.getProperty("user.dir"), "compass.db").absolutePath
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> host = args[++i]
            "--port" -> port = args[++i].toInt()
            "--db" -> dbPath = args[++i]
            else -> System.err.println("unknown argument ${args[i]}")
        }
        i++
    }
    val db = Database(dbPath)
    val workspace = Workspace(db)
    workspace.warmAll()
    println("行址罗盘 starting on http://$host:$port (db=$dbPath)")
    WebServer(workspace).start(host, port)
}
