package compass

import compass.web.WebServer

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var db = "compass.db"
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> host = args[++i]
            "--port" -> port = args[++i].toInt()
            "--db" -> db = args[++i]
        }
        i++
    }
    println("行址罗盘 (Line-Address Compass) 启动于 http://$host:$port")
    WebServer(db, host, port).start()
}
