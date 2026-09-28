package com.linecompass.compass

import com.linecompass.db.Repository
import com.linecompass.db.StoredDebugFile
import com.linecompass.db.StoredSnapshot
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class JsFile(
    val id: Long, val name: String, val sha256: String, val versionNo: Int,
    val importedAt: Long, val size: Long? = null,
    val cuCount: Int, val rangeCount: Int, val issueCount: Int,
    val issues: List<JsIssue> = emptyList(),
    val sections: List<JsSection> = emptyList()
)

@Serializable
data class JsIssue(val section: String, val severity: String, val code: String, val message: String)

@Serializable
data class JsSection(val name: String, val size: Long, val vaddr: String, val summary: String)

@Serializable
data class JsCu(
    val offset: String, val version: Int, val kind: String, val name: String,
    val compDir: String?, val producer: String?, val dwoMissing: Boolean,
    val rangeCount: Int, val sequenceCount: Int
)

@Serializable
data class JsRange(
    val start: String, val end: String, val segment: Int, val kind: String,
    val dieOffset: String?, val symbol: String?, val zeroLength: Boolean,
    val explicitPriority: Int
)

@Serializable
data class JsLineRow(
    val order: Int, val address: String, val file: String, val line: Int,
    val column: Int, val isStmt: Boolean, val endSequence: Boolean,
    val isa: Int, val discriminator: Int
)

@Serializable
data class JsSequence(
    val start: String, val end: String, val segment: Int,
    val tableVersion: Int, val rows: List<JsLineRow>
)

@Serializable
data class JsLineHit(
    val file: String, val line: Int, val column: Int, val isStmt: Boolean,
    val sequenceStart: String, val sequenceEnd: String,
    val tableVersion: Int, val rowOrder: Int
)

@Serializable
data class JsInlineFrame(
    val depth: Int, val name: String, val declaredFile: String?,
    val declaredLine: Int?, val callFile: String?, val callLine: Int?,
    val dieOffset: String
)

@Serializable
data class JsCandidate(
    val kind: String, val rangeStart: String, val rangeEnd: String,
    val rangeWidth: String, val segment: Int, val inlineDepth: Int,
    val explicitPriority: Int, val isWinner: Boolean,
    val cuName: String?, val cuOffset: String?, val symbol: String?,
    val dieOffset: String?, val line: JsLineHit?
)

@Serializable
data class JsModuleMatch(
    val moduleId: Long, val moduleName: String, val debugFileVersionId: Long,
    val loadGeneration: Int, val loadBias: String,
    val relativeAddress: String, val segment: Int,
    val candidateCount: Int,
    val winner: JsCandidate?, val candidates: List<JsCandidate>,
    val inlineChain: List<JsInlineFrame>, val reliability: List<JsIssue>
)

@Serializable
data class JsResolution(
    val inputToken: String, val runtimeAddress: String, val segment: Int,
    val resolved: Boolean, val matches: List<JsModuleMatch>,
    val unmatchedGenerations: List<Int>
)

@Serializable
data class JsSnapshot(
    val id: Long, val name: String, val fixed: Boolean, val createdAt: Long,
    val modules: List<JsSnapshotModule>
)

@Serializable
data class JsSnapshotModule(
    val moduleId: Long, val moduleName: String, val debugFileId: Long,
    val debugFileName: String, val versionNo: Int,
    val baseAddress: String, val generation: Int
)

@Serializable
data class JsCrash(
    val id: Long, val snapshotId: Long?, val title: String,
    val createdAt: Long, val rawInput: String, val resolutions: List<JsResolution>
)

class CompassService(private val repo: Repository) {
    private val files = LinkedHashMap<Long, StoredDebugFile>()
    private val snapshots = LinkedHashMap<Long, StoredSnapshot>()

    init {
        repo.listDebugFiles().forEach { files[it.id] = it }
        repo.listSnapshots().forEach { snapshots[it.id] = it }
    }

    fun importFile(name: String, bytes: ByteArray, supersedesId: Long?): JsFile {
        val stored = repo.importDebugFile(name, bytes, supersedesId)
        files[stored.id] = stored
        return fileJson(stored, detailed = false)
    }

    fun listFiles(): List<JsFile> = files.values.map { fileJson(it, detailed = false) }

    fun fileDetail(id: Long): JsFile? = files[id]?.let { fileJson(it, detailed = true) }

    fun cus(id: Long): List<JsCu> = files[id]?.parsed?.cus?.map { cu ->
        JsCu(hex(cu.offset), cu.version, cu.kind.name, cu.name, cu.compDir, cu.producer,
            cu.splitMissing, cu.ranges.size, cu.lineProgram?.sequences?.size ?: 0)
    } ?: emptyList()

    fun ranges(id: Long): List<JsRange> = files[id]?.parsed?.cus
        ?.flatMap { cu -> cu.ranges.map { r ->
            JsRange(hex(r.start), hex(r.end), r.segment, r.kind.name,
                r.die?.offset?.let(::hex),
                r.die?.nameOrNull() ?: r.die?.let { fallbackName(it) },
                r.zeroLength, r.explicitPriority)
        } }
        ?.sortedWith(compareBy({ parseHex(it.start) }, { it.explicitPriority }))
        ?: emptyList()

    fun sequences(id: Long): List<JsSequence> = files[id]?.parsed?.cus
        ?.flatMap { cu ->
            cu.lineProgram?.sequences?.map { seq ->
                JsSequence(hex(seq.startAddress), hex(seq.endAddress), seq.segment,
                    cu.lineProgram.version,
                    seq.rows.map { row ->
                        JsLineRow(row.order, hex(row.address),
                            row.file.fullPath.ifEmpty { row.file.name },
                            row.line, row.column, row.isStmt, row.endSequence,
                            row.isa, row.discriminator)
                    })
            } ?: emptyList()
        } ?: emptyList()

    fun createSnapshot(name: String, fixed: Boolean, modules: List<Triple<String, Long, Long>>): JsSnapshot {
        val id = repo.createSnapshot(name, fixed, modules)
        val stored = repo.getSnapshot(id)!!
        snapshots[id] = stored
        return snapshotJson(stored)
    }

    fun listSnapshots(): List<JsSnapshot> = snapshots.values.map { snapshotJson(it) }

    fun resolveBatch(tokens: List<String>, snapshotId: Long?): List<JsResolution> {
        val resolver = buildResolver()
        val snap = snapshotId?.let { id ->
            val stored = snapshots[id] ?: error("snapshot $id not found")
            QuerySnapshot(id, stored.name, stored.loads.map { load ->
                SnapshotModule(load.debugFileId, load.moduleName, load.debugFileId, load.baseAddress, load.generation)
            })
        }
        return tokens.map { token -> resolutionJson(resolver.resolve(token, snap?.id)) }
    }

    fun saveCrash(snapshotId: Long?, title: String, tokens: List<String>): JsCrash {
        val js = resolveBatch(tokens, snapshotId)
        val json = json.encodeToString(kotlinx.serialization.builtins.ListSerializer(JsResolution.serializer()), js)
        val id = repo.saveCrash(snapshotId, title, tokens.joinToString("\n"), json)
        return JsCrash(id, snapshotId, title, System.currentTimeMillis(), tokens.joinToString("\n"), js)
    }

    fun listCrashes(): List<JsCrash> = repo.listCrashes().map { c ->
        val items = json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(JsResolution.serializer()), c.resolutionJson)
        JsCrash(c.id, c.snapshotId, c.title, c.createdAt, c.rawInput, items)
    }

    private fun buildResolver(): CompassResolver {
        val modules = HashMap<Long, ParsedModule>()
        // Module identity follows snapshot module_load rows, which are added
        // lazily; the resolver also supports snapshot-free queries, so we
        // register every imported debug file as module id == file id.
        files.values.forEach { f ->
            modules[f.id] = ParsedModule(f.id, f.id, f.parsed, f.name)
        }
        val snaps = HashMap<Long, QuerySnapshot>()
        for ((id, s) in snapshots) {
            snaps[id] = QuerySnapshot(id, s.name, s.loads.map { l ->
                SnapshotModule(l.debugFileId, l.moduleName, l.debugFileId, l.baseAddress, l.generation)
            })
        }
        return CompassResolver(modules, snaps)
    }

    private fun fileJson(f: StoredDebugFile, detailed: Boolean): JsFile {
        val sectionRows = repo.sectionsOf(f.id)
        return JsFile(
            id = f.id, name = f.name, sha256 = f.sha256, versionNo = f.versionNo,
            importedAt = f.importedAt,
            cuCount = f.parsed.cus.size,
            rangeCount = f.parsed.rangeIndex.size,
            issueCount = f.parsed.issues.size,
            issues = if (detailed) f.parsed.issues.map { JsIssue(it.section, it.severity, it.code, it.message) } else emptyList(),
            sections = sectionRows.map { (name, size, summary) ->
                val vaddr = f.parsed.sections.sections[name]?.vaddr ?: 0L
                JsSection(name, size, hex(vaddr), summary)
            }
        )
    }

    private fun snapshotJson(s: StoredSnapshot): JsSnapshot = JsSnapshot(
        s.id, s.name, s.fixed, s.createdAt,
        s.loads.map { l ->
            val f = files[l.debugFileId]
            JsSnapshotModule(l.debugFileId, l.moduleName, l.debugFileId, f?.name ?: "file#${l.debugFileId}",
                f?.versionNo ?: 0, hex(l.baseAddress), l.generation)
        })

    private fun resolutionJson(r: AddressResolution): JsResolution = JsResolution(
        r.inputToken, hex(r.runtimeAddress), r.segment, r.resolved,
        r.matches.map { m ->
            JsModuleMatch(
                m.moduleId, m.moduleName, m.debugFileVersionId, m.loadGeneration,
                hex(m.loadBias), hex(m.relativeAddress), m.segment, m.candidateCount,
                m.winner?.let(::candidateJson),
                m.candidates.map(::candidateJson),
                m.inlineChain.map { f ->
                    JsInlineFrame(f.depth, f.name, f.declaredFile, f.declaredLine,
                        f.callFile, f.callLine, hex(f.dieOffset))
                },
                m.reliability.map { JsIssue(it.code, it.level, it.code, it.message) }
            )
        },
        r.unmatchedGenerations
    )

    private fun candidateJson(c: AddressCandidate): JsCandidate {
        val die = c.die
        return JsCandidate(
            c.range.kind.name, hex(c.range.start), hex(c.range.end), hex(c.rangeWidth),
            c.range.segment, c.inlineDepth, c.explicitPriority, c.isWinner,
            c.cu?.name, c.cu?.offset?.let(::hex),
            die?.let { fallbackName(it) }, die?.offset?.let(::hex),
            c.lineHit?.let {
                JsLineHit(it.file, it.line, it.column, it.isStmt,
                    hex(it.sequenceStart), hex(it.sequenceEnd), it.tableVersion, it.rowOrder)
            }
        )
    }

    private fun fallbackName(die: com.linecompass.dwarf.DieNode): String =
        die.nameOrNull() ?: if (die.isInline) "<inlined>" else "<subprogram>"

    companion object {
        val json = Json { ignoreUnknownKeys = true; prettyPrint = false; encodeDefaults = true }
        fun hex(v: Long): String = Repository.hex(v)
        fun parseHex(s: String): Long = Repository.parseHex(s)
    }
}
