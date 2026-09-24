package com.compass

import com.compass.web.startServer
import kotlin.io.path.Path

fun main(args: Array<String>) {
    var host = "127.0.0.1"
    var port = 5251
    var index = 0
    while (index < args.size) {
        when (args[index++]) {
            "--host" -> host = args[index++]
            "--port" -> port = args[index++].toInt()
            else -> error("Unknown argument")
        }
    }
    startServer(host, port, Path("compass.db"))
}
