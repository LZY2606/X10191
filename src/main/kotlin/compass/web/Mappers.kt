package compass.web

import compass.dwarf.*
import compass.elf.ElfSection
import kotlinx.serialization.json.Json

object QueryJson {
    val json = Json { prettyPrint = false; encodeDefaults = true }
    fun encode(q: QueryResult): String = json.encodeToString(QueryResponseJson.serializer(), Mappers.toJson(q))
}

object Mappers {
    fun hex(v: Long) = "0x" + v.toUnsignedString()
    private fun Long.toUnsignedString(): String = java.lang.Long.toUnsignedString(this, 16)

    fun range(r: compass.dwarf.AddressRange) =
        RangeJson(hex(r.start), hex(r.end), r.segment, r.zeroLength)

    fun toJson(q: QueryResult): QueryResponseJson = QueryResponseJson(
        raw = q.input.raw,
        runtimeAddress = hex(q.runtimeAddress),
        relativeAddress = hex(q.relativeAddress),
        loadBias = q.loadBias?.let { hex(it) },
        moduleBase = q.moduleBase?.let { hex(it) },
        moduleName = q.moduleName,
        summary = q.summary,
        warnings = q.warnings,
        candidates = q.candidates.map { c ->
            CandidateJson(
                rank = c.rank, fileId = c.fileId, fileName = c.fileName,
                fileSha256 = c.fileSha256, cuName = c.cuName, cuOffset = hex(c.cuOffset),
                dwarfVersion = c.dwarfVersion, matchedRange = range(c.matchedRange),
                rangeWidth = hex(c.rangeWidth), inlineDepth = c.inlineDepth,
                explicitScore = c.explicitScore, function = c.function,
                line = c.line?.let {
                    LineHitJson(it.file, it.directory, it.line, it.column, it.sequenceIndex,
                        hex(it.sequenceStart), hex(it.sequenceEnd), it.dwarfVersion, it.isStmt)
                },
                inlineChain = c.inlineChain.map { f ->
                    InlineFrameJson(f.depth, f.function, hex(f.dieOffset), f.callFile,
                        f.line, f.column, f.ranges.map { range(it) })
                },
                tableVersion = c.tableVersion, trusted = c.trusted, notes = c.notes
            )
        }
    )

    fun section(s: ElfSection) = SectionJson(
        s.name, s.type, hex(s.flags), hex(s.addr), hex(s.offset), s.size, s.sha256
    )

    fun issue(i: ParseIssue) = IssueJson(i.severity, i.where, i.message)

    fun unit(u: CompUnit, scopeCount: Int) = UnitJson(
        unitOffset = hex(u.unitOffset), version = u.version, unitType = u.unitType,
        name = u.name(), isSkeleton = u.isSkeleton, isSplit = u.isSplit,
        dwoId = u.dwoId?.let { "0x" + it.toString(16) },
        stmtList = (u.root.attr(DW.AT_stmt_list)?.value as? FormValue.SectionOffset)
            ?.let { hex(it.value) },
        linked = u.linkedDwoFileId != null,
        scopes = scopeCount,
        issues = u.issues.map { issue(it) }
    )

    fun scope(sc: ScopeDie, names: DwarfNames) = ScopeJson(
        dieOffset = hex(sc.die.offset), tag = sc.die.tag,
        name = names.name(sc.die, sc.unit), inlineDepth = sc.inlineDepth,
        ranges = sc.ranges.map { range(it) },
        callFile = (sc.die.attr(DW.AT_call_file)?.value as? FormValue.Number)?.let { "file#${it.value}" },
        callLine = sc.die.num(DW.AT_call_line),
        callColumn = sc.die.num(DW.AT_call_column)
    )

    fun lineProgram(lp: compass.dwarf.LineProgram) = LineProgramJson(
        stmtList = hex(lp.sectionOffset), dwarfVersion = lp.version,
        minInsnLength = lp.minimumInstructionLength, defaultIsStmt = lp.defaultIsStmt,
        lineBase = lp.lineBase, lineRange = lp.lineRange, opcodeBase = lp.opcodeBase,
        files = lp.files.map { LineFileJson(it.index, it.name, it.directory) },
        sequences = lp.sequences.map {
            SequenceJson(it.index, hex(it.startAddress), hex(it.endAddress), it.segment,
                lp.version, it.rows.size)
        },
        transitions = lp.transitions.map {
            TransitionJson(it.seq, hex(it.address), it.line, it.column, it.fileIndex,
                it.isStmt, it.endSequence, it.opcode)
        },
        issues = lp.issues.map { issue(it) }
    )

    fun snapshot(s: SnapshotView) = SnapshotJson(
        s.id, s.label, s.createdAt,
        s.modules.map { ModuleSpecJson(it.name, it.fileId, hex(it.base), it.generation) }
    )
}
