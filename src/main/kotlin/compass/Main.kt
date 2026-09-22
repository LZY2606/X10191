package compass

import compass.db.Db
import compass.web.installApp

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var dbPath = "linecompass.db"
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> host = args[++i]
            "--port" -> port = args[++i].toInt()
            "--db" -> dbPath = args[++i]
        }
        i++
    }
    val db = Db(dbPath)
    println("行址罗盘 LineCompass listening on http://$host:$port (db=$dbPath)")
    installApp(db, host, port)
}
