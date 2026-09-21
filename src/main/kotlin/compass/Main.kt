package compass

import compass.db.CompassDatabase
import compass.db.Repository
import compass.web.startServer
import java.nio.file.Paths

/**
 * 行址罗盘 (Address-Line Compass) — local ELF/DWARF attribution service.
 * No system debugger is ever invoked; all parsing happens in-process.
 */
fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var home = Paths.get(System.getProperty("user.dir"), ".compass-data")
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> { host = args[++i] }
            "--port" -> { port = args[++i].toInt() }
            "--data" -> { home = Paths.get(args[++i]) }
            else -> System.err.println("未知参数: ${args[i]}")
        }
        i++
    }
    val db = CompassDatabase(home.resolve("compass.sqlite"))
    val repo = Repository(db, home.resolve("blobs"))
    println("行址罗盘 启动于 http://$host:$port （数据目录 $home）")
    startServer(host, port, repo, db)
}
