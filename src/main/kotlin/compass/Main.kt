package compass

import compass.resolve.Workspace
import compass.store.Repository
import compass.web.startServer
import java.nio.file.Path
import kotlin.system.exitProcess

/**
 * 行址罗盘 (Address Compass) — local ELF/DWARF address explainer.
 * No external debugger is invoked; all parsing happens in-process.
 */
fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var dataDir: Path = Path.of(System.getProperty("user.dir"), ".compass-data")
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--host" -> { host = args[++i] }
            "--port" -> { port = args[++i].toInt() }
            "--data" -> { dataDir = Path.of(args[++i]) }
            "-h", "--help" -> {
                println("Usage: run --args='--host 127.0.0.1 --port 5251 [--data DIR]'")
                exitProcess(0)
            }
            else -> { System.err.println("Unknown argument: ${args[i]}"); exitProcess(2) }
        }
        i++
    }
    val repo = Repository(dataDir)
    repo.init()
    val workspace = Workspace(repo)
    println("行址罗盘 listening on http://$host:$port")
    startServer(repo, workspace, host, port)
}
