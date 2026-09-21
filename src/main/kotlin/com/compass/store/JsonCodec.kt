package com.compass.store

import com.compass.dwarf.*
import kotlinx.serialization.json.*

object JsonCodec {
    val json = Json { prettyPrint = false; encodeDefaults = true }

    fun jstr(v: String?): JsonElement = if (v == null) JsonNull else JsonPrimitive(v)

    fun hx(v: Long) = "0x${v.toULong().toString(16)}"

    fun ranges(rs: List<AddrRange>): String = (buildJsonArray {
        for (r in rs) add(buildJsonObject {
            put("low", hx(r.low)); put("high", hx(r.high))
            put("length", hx(r.high - r.low)); put("zeroLength", r.zeroLength)
        })
    }).toString()

    fun issues(list: List<ParseIssue>): String = (buildJsonArray {
        for (i in list) add(buildJsonObject {
            put("scope", i.scope); put("message", i.message); put("severity", i.severity)
        })
    }).toString()

    fun dies(dies: List<DieRecord>): String = (buildJsonArray {
        for (d in dies) add(buildJsonObject {
            put("offset", hx(d.offset.toLong())); put("tag", d.tagName); put("depth", d.depth)
            put("name", d.resolvedName)
            put("parent", if (d.parentOffset < 0) JsonNull else JsonPrimitive(hx(d.parentOffset.toLong())))
            put("ranges", JsonArray(d.ranges.map { r ->
                buildJsonObject { put("low", hx(r.low)); put("high", hx(r.high)); put("zeroLength", r.zeroLength) }
            }))
            val callLine = (d.attr(DW_AT_call_line) as? AttrValue.Num)?.v
            if (callLine != null) put("callLine", callLine)
            val callCol = (d.attr(DW_AT_call_column) as? AttrValue.Num)?.v
            if (callCol != null) put("callColumn", callCol)
            if (d.callFileResolved != null) put("callFile", d.callFileResolved)
        })
    }).toString()

    fun lineTable(lt: LineTable): String = (buildJsonObject {
        put("cuOffset", hx(lt.cuOffset)); put("version", lt.version); put("dwarf64", lt.dwarf64)
        put("minimumInstructionLength", lt.minimumInstructionLength)
        put("defaultIsStmt", lt.defaultIsStmt)
        put("dirs", JsonArray(lt.dirs.map { JsonPrimitive(it) }))
        put("files", buildJsonArray {
            for (f in lt.files) add(buildJsonObject {
                put("index", f.index); put("name", f.name); put("dirIndex", f.dirIndex)
                put("path", lt.resolveFile(f.index))
            })
        })
        put("sequences", buildJsonArray {
            for (s in lt.sequences) add(buildJsonObject {
                put("index", s.index); put("start", hx(s.startAddress)); put("end", hx(s.endAddress))
                put("rows", buildJsonArray {
                    for (r in s.rows) add(buildJsonObject {
                        put("address", hx(r.address)); put("file", r.fileIndex)
                        put("path", lt.resolveFile(r.fileIndex))
                        put("line", r.line); put("column", r.column)
                        put("endSequence", r.endSequence)
                        put("discriminator", r.discriminator); put("isa", r.isa); put("stmt", r.stmt)
                        put("basicBlock", r.basicBlock); put("prologueEnd", r.prologueEnd)
                    })
                })
            })
        })
    }).toString()

    fun candidate(c: QueryEngine.Candidate): JsonObject = buildJsonObject {
        put("rank", c.rank)
        put("cuName", jstr(c.cuName))
        put("cuOffset", hx(c.cuOffset))
        put("cuCompDir", jstr(c.cuCompDir))
        put("dwarfVersion", c.dwarfVersion)
        put("file", c.fileName); put("line", c.line); put("column", c.column)
        put("sequenceIndex", c.sequenceIndex)
        put("sequenceStart", hx(c.sequenceStart)); put("sequenceEnd", hx(c.sequenceEnd))
        put("rowAddress", hx(c.rowAddress))
        put("function", jstr(c.functionName))
        put("enclosingRange", c.enclosingRange?.let {
            buildJsonObject { put("low", hx(it.low)); put("high", hx(it.high)); put("length", hx(it.length)); put("zeroLength", it.zeroLength) }
        } ?: JsonNull as JsonElement)
        put("inlineDepth", c.inlineDepth)
        put("inlineChain", buildJsonArray {
            for (f in c.inlineChain) add(buildJsonObject {
                put("tag", f.tag); put("name", jstr(f.name))
                put("depth", f.depth); put("source", f.source)
                put("callFile", jstr(f.callFile))
                put("callLine", if (f.callLine == null) JsonNull else JsonPrimitive(f.callLine)); put("callColumn", if (f.callColumn == null) JsonNull else JsonPrimitive(f.callColumn))
                put("ranges", buildJsonArray {
                    f.ranges.forEach { r -> add(buildJsonObject { put("low", hx(r.low)); put("high", hx(r.high)); put("zeroLength", r.zeroLength) }) }
                })
            })
        })
        put("lineTableVersion", c.lineTableVersion)
        put("dwoResolved", c.dwoResolved)
        put("confidence", c.confidence)
        put("stableKey", c.stableKey)
        put("issues", buildJsonArray { c.issues.forEach { add(buildJsonObject {
            put("scope", it.scope); put("message", it.message); put("severity", it.severity)
        }) } })
        put("trustNotes", buildJsonArray { c.trustNotes.forEach { add(it) } })
    }
}
