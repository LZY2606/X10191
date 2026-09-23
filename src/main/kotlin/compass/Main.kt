package compass

import compass.query.Store
import compass.web.Server
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var db = "line-address-compass.db"
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> { host = args.getOrElse(i + 1) { host }; i += 2 }
            "--port" -> { port = args.getOrElse(i + 1) { "$port" }.toInt(); i += 2 }
            "--db" -> { db = args.getOrElse(i + 1) { db }; i += 2 }
            else -> i++
        }
    }
    val store = Store(db)
    val server = Server(store)
    println("行址罗盘 (line-address-compass) listening on http://$host:$port  db=$db")
    embeddedServer(Netty, port = port, host = host) {
        server.configure(this)
    }.start(wait = true)
}
