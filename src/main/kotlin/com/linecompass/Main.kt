package com.linecompass

import com.linecompass.web.CompassServer

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
            else -> {
                System.err.println("unknown argument: ${args[i]}")
                System.err.println("usage: [--host H] [--port P] [--db PATH]")
                kotlin.system.exitProcess(2)
            }
        }
        i++
    }
    println("行址罗盘 (Line-Address Compass) listening on http://$host:$port  db=$db")
    CompassServer(db).start(host, port)
}
