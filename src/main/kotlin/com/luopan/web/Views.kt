package com.luopan.web

import com.luopan.dwarf.*
import com.luopan.service.*

fun hex(v: Long): String = "0x" + java.lang.Long.toUnsignedString(v, 16)

fun importView(imp: ImportedFile): Map<String, Any?> {
    val d = imp.dwarf
    return mapOf(
        "versionId" to imp.versionId,
        "moduleKey" to imp.moduleKey,
        "fileName" to imp.fileName,
        "sha256" to imp.sha256,
        "buildId" to imp.buildId,
        "digest" to mapOf(
            "sha256" to d.elf.digest.sha256,
            "size" to d.elf.digest.size,
            "first16Hex" to d.elf.digest.first16Hex,
        ),
        "elf" to mapOf(
            "class" to if (d.elf.elfClass == 2) "ELF64" else "ELF32",
            "endian" to d.elf.endian.name,
            "machine" to d.elf.machine,
            "type" to when (d.elf.type) {
                1 -> "ET_REL"; 2 -> "ET_EXEC"; 3 -> "ET_DYN"; else -> d.elf.type
            },
            "preferredLoadBase" to hex(d.elf.preferredLoadBase),
            "entry" to hex(d.elf.entry),
            "isRelocatable" to d.elf.isRelocatable,
        ),
        "summary" to mapOf(
            "cus" to d.units.size,
            "splitCus" to d.splitUnits.size,
            "functions" to d.functions.size,
            "sequences" to (d.line.sequences.size + d.splitLine.sequences.size),
            "relocationsApplied" to d.relocationsApplied,
            "dwoExpected" to d.dwoExpected.map { (id, name) ->
                mapOf("dwoId" to (id?.let { hex(it) }), "dwoName" to name)
            },
        ),
        "diagnostics" to d.diagnostics.map {
            mapOf("severity" to it.severity, "scope" to it.scope,
                "message" to it.message, "cu" to it.cuName)
        },
    )
}

fun sectionsView(imp: ImportedFile): Map<String, Any?> {
    val elf = imp.dwarf.elf
    val debugNames = setOf(
        ".debug_info", ".debug_abbrev", ".debug_line", ".debug_ranges", ".debug_rnglists",
        ".debug_str", ".debug_line_str", ".debug_str_offsets", ".debug_addr",
        ".debug_info.dwo", ".debug_abbrev.dwo", ".debug_str.dwo",
        ".debug_str_offsets.dwo", ".debug_line.dwo", ".debug_line_str.dwo",
        ".note.gnu.build-id",
    )
    return mapOf(
        "versionId" to imp.versionId,
        "sections" to elf.sections.drop(1).map { s ->
            mapOf(
                "name" to s.name, "type" to s.type, "addr" to hex(s.addr),
                "fileOffset" to hex(s.offset), "size" to s.size, "flags" to hex(s.flags),
                "isDebug" to (s.name in debugNames || s.name.startsWith(".debug_")),
            )
        },
        "programHeaders" to elf.programHeaders.map { p ->
            mapOf("type" to p.type, "flags" to p.flags, "offset" to hex(p.offset),
                "vaddr" to hex(p.vaddr), "filesz" to p.filesz, "memsz" to p.memsz)
        },
    )
}

fun rangesView(imp: ImportedFile): Map<String, Any?> {
    val units = imp.dwarf.units + imp.dwarf.splitUnits
    data class R(val cu: String, val split: Boolean, val die: Int, val tag: String,
                 val name: String?, val start: Long, val end: Long, val source: String,
                 val zeroLength: Boolean, val depth: Int)
    val rows = ArrayList<R>()
    for (cu in units) {
        val split = cu in imp.dwarf.splitUnits
        val dieByIndex = cu.dies
        for (dr in cu.ranges) {
            val die = dieByIndex.getOrNull(dr.dieIndex) ?: continue
            val fn = imp.dwarf.functions.firstOrNull { it.cuOffset == cu.sectionOffset && it.dieOffset == die.offset }
            rows.add(R(cu.name, split, die.offset, DwarfTag.name(die.tag), fn?.name,
                dr.range.start, dr.range.end, dr.source, dr.range.length == 0L, die.depth))
        }
    }
    rows.sortWith(compareBy({ it.start }, { it.end }, { it.cu }, { it.die }))
    val overlaps = ArrayList<Map<String, Any?>>()
    val nonZero = rows.filter { !it.zeroLength }
    for (i in nonZero.indices) {
        for (j in i + 1 until nonZero.size) {
            val a = nonZero[i]; val b = nonZero[j]
            if (b.start >= a.end) continue
            if (a.start < b.end && b.start < a.end) {
                overlaps.add(mapOf(
                    "a" to "${a.name ?: a.tag}@${a.cu}",
                    "b" to "${b.name ?: b.tag}@${b.cu}",
                    "start" to hex(maxOf(a.start, b.start)),
                    "end" to hex(minOf(a.end, b.end)),
                ))
            }
        }
        if (nonZero[i].start - nonZero.first().start > 0L && i > 0 && nonZero[i].start >= nonZero.subList(0, i).maxOf { it.end }) {
            // 已越过所有早期范围，简单跳过（规模小，保持直接双重循环也可接受）
        }
    }
    return mapOf(
        "versionId" to imp.versionId,
        "ranges" to rows.map {
            mapOf(
                "cu" to it.cu, "fromSplit" to it.split, "dieOffset" to hex(it.die.toLong()),
                "tag" to it.tag, "function" to it.name,
                "start" to hex(it.start), "end" to hex(it.end),
                "length" to it.end - it.start, "zeroLength" to it.zeroLength,
                "source" to it.source, "depth" to it.depth,
            )
        },
        "overlaps" to overlaps,
    )
}

fun lineView(imp: ImportedFile): Map<String, Any?> {
    val seqs = imp.dwarf.line.sequences + imp.dwarf.splitLine.sequences
    return mapOf(
        "versionId" to imp.versionId,
        "headers" to (imp.dwarf.line.headers + imp.dwarf.splitLine.headers).map { h ->
            mapOf(
                "offset" to hex(h.offset.toLong()), "version" to h.version,
                "minInstructionLength" to h.minInstructionLength,
                "defaultIsStmt" to h.defaultIsStmt,
                "lineBase" to h.lineBase, "lineRange" to h.lineRange,
                "opcodeBase" to h.opcodeBase, "addressSize" to h.addressSize,
                "segmentSelectorSize" to h.segmentSelectorSize,
                "directories" to h.directories.map { it.path },
                "files" to h.fileNames.map { it.path },
            )
        },
        "sequences" to seqs.map { s ->
            mapOf(
                "cu" to s.cuName, "version" to "DWARF v${s.version}",
                "start" to hex(s.startAddress), "end" to hex(s.endAddress),
                "segmentSelectorSize" to s.segSelectorSize,
                "rows" to s.rows.map { r ->
                    mapOf(
                        "address" to hex(r.address), "segment" to r.segment,
                        "file" to (r.file?.path ?: ""), "line" to r.line, "column" to r.column,
                        "isStmt" to r.isStmt, "endSequence" to r.endSequence,
                        "isa" to r.isa, "discriminator" to r.discriminator,
                    )
                },
            )
        },
        "transitions" to (imp.dwarf.line.transitions + imp.dwarf.splitLine.transitions).map { t ->
            mapOf("op" to t.opName, "address" to hex(t.address), "fileIdx" to t.fileIdx,
                "line" to t.line, "column" to t.column, "isStmt" to t.isStmt,
                "endSequence" to t.endSequence)
        },
    )
}

fun inlineView(imp: ImportedFile): Map<String, Any?> {
    val out = ArrayList<Map<String, Any?>>()
    for (cu in imp.dwarf.units + imp.dwarf.splitUnits) {
        val dieByOffset = cu.dies.associateBy { it.offset }
        val children = cu.dies.filter { it.tag == DwarfTag.INLINED_SUBROUTINE }
        for (die in children) {
            val parentFn = generateSequence(die.parent) { p ->
                cu.dies.getOrNull(p)?.let { d -> if (d.tag == DwarfTag.SUBPROGRAM) null else if (d.parent >= 0) d.parent else null }
            }.toList().mapNotNull { cu.dies.getOrNull(it) }.firstOrNull { it.tag == DwarfTag.SUBPROGRAM }
            val name = (die.attr(DwarfAttr.NAME) as? AttrVal.Str)?.v
                ?: ((die.attr(DwarfAttr.ABSTRACT_ORIGIN) as? AttrVal.Ref)?.offset
                    ?.let { dieByOffset[it] }?.let { (it.attr(DwarfAttr.NAME) as? AttrVal.Str)?.v })
                ?: "<anonymous>"
            val callLine = (die.attr(DwarfAttr.CALL_LINE) as? AttrVal.Const)?.v
            out.add(mapOf(
                "cu" to cu.name,
                "dieOffset" to hex(die.offset.toLong()),
                "depth" to die.depth,
                "function" to name,
                "callLine" to callLine,
                "parentFunction" to ((parentFn?.let { (it.attr(DwarfAttr.NAME) as? AttrVal.Str)?.v })),
            ))
        }
    }
    return mapOf("versionId" to imp.versionId, "inlines" to out)
}

fun resultView(r: AddressResult): Map<String, Any?> = mapOf(
    "queryAddress" to hex(r.queryAddress),
    "relativeAddress" to hex(r.relativeAddress),
    "segment" to r.segment,
    "moduleKey" to r.moduleKey,
    "loadBias" to hex(r.loadBias),
    "actualBase" to hex(r.actualBase),
    "preferredBase" to hex(r.preferredBase),
    "tableVersionUsed" to r.tableVersionUsed,
    "trusted" to r.trusted,
    "trustNotes" to r.trustNotes,
    "lineCandidates" to r.lineCandidates.map { c ->
        mapOf(
            "file" to c.file, "line" to c.line, "column" to c.column,
            "segment" to c.segment,
            "sequenceStart" to hex(c.sequenceStart), "sequenceEnd" to hex(c.sequenceEnd),
            "cu" to c.cuName, "cuOffset" to hex(c.cuOffset.toLong()),
            "lineTableVersion" to "DWARF v${c.version}",
            "isStmt" to c.isStmt, "endSequenceRow" to c.endSequenceRow,
        )
    },
    "functionCandidates" to r.functionCandidates.map { c ->
        mapOf(
            "function" to (c.info.name ?: "<anonymous>"),
            "tag" to c.info.tag,
            "cu" to c.info.cuName,
            "dieOffset" to hex(c.info.dieOffset.toLong()),
            "matchedRange" to (c.matchedRange?.let {
                mapOf("start" to hex(it.start), "end" to hex(it.end),
                    "length" to it.length, "zeroLength" to (it.length == 0L))
            }),
            "fromSplitDwo" to c.fromSplit,
            "explicitPriority" to c.priority,
            "inlineChain" to c.inlineFrames.map { f ->
                mapOf("depth" to f.depth, "function" to f.functionName,
                    "file" to f.file, "line" to f.line,
                    "dieOffset" to hex(f.dieOffset.toLong()),
                    "abstractOrigin" to (f.abstractOriginOffset?.let { off -> hex(off.toLong()) }),
                    "inlineCode" to f.inlineCode)
            },
        )
    },
)
