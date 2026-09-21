package compass

import compass.server.startServer

/**
 * 行址罗盘 (Line-Address Compass) — local ELF/DWARF crash address navigator.
 *
 * Usage: run --args='--host 127.0.0.1 --port 5251 [--db compass.db]'
 */
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
            else -> System.err.println("unknown argument: ${args[i]}")
        }
        i++
    }
    println("行址罗盘 starting on http://$host:$port (db=$db)")
    startServer(db, host, port)
}
