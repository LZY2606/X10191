package compass

import compass.web.WebServer

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var dbPath = "compass.db"
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> { host = args[++i] }
            "--port" -> { port = args[++i].toInt() }
            "--db" -> { dbPath = args[++i] }
            else -> System.err.println("未知参数: ${args[i]}")
        }
        i++
    }
    WebServer(host, port, dbPath).start(wait = true)
}
