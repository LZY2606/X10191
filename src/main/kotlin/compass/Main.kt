package compass

import compass.db.Database
import compass.db.Repository
import compass.web.startServer
import java.nio.file.Path
import kotlin.io.path.absolutePathString

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var dir = "data"
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> host = args[++i]
            "--port" -> port = args[++i].toInt()
            "--data" -> dir = args[++i]
        }
        i++
    }
    val dataPath = Path.of(dir).toAbsolutePath()
    val db = Database.open(dataPath)
    val repo = Repository(db, dataPath)
    println("行址罗盘（Address Compass）数据目录: ${dataPath.absolutePathString()}")
    println("打开 http://$host:$port/")
    startServer(repo, host, port)
}
