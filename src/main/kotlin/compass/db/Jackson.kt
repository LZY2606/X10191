package compass.db

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

fun jacksonMapper(): ObjectMapper = jacksonObjectMapper()
