package compass.db

import compass.dwarf.*
import compass.query.AddressExplanation
import compass.query.AddressResolver
import compass.query.ModuleLoad
import java.util.concurrent.ConcurrentHashMap

data class CuView(val offset: Long, val version: Int, val name: String?, val compDir: String?,
    val isSkeleton: Boolean, val dieCount: Int, val warnings: List<String>)

data class SequenceView(
    val id: String, val cuOffset: Long?, val cuVersion: Int, val headerOffset: Long,
    val startAddress: Long, val endAddress: Long, val rowCount: Int, val fileCount: Int,
    val files: List<String?>,
)

data class RangeView(val dieOffset: Long, val name: String?, val tag: Int, val start: Long, val end: Long,
    val zeroLength: Boolean, val cuName: String?, val inline: Boolean)

data class LineRowView(val address: Long, val line: Int, val column: Int, val file: String?,
    val isStmt: Boolean, val endSeq: Boolean, val prologueEnd: Boolean, val epilogueBegin: Boolean,
    val discriminator: Int, val isa: Int, val opIndex: Int, val segment: Long)

data class ModelView(
    val version: VersionRow,
    val sections: List<SectionRow>,
    val cus: List<CuView>,
    val sequences: List<SequenceView>,
    val ranges: List<RangeView>,
    val warnings: List<String>,
    val loadBaseDefault: Long,
)

/**
 * Caches parsed [DwarfModel]s per debug version. Importing a new file only adds a
 * version; old snapshots and crash rows keep pointing at their original version.
 */
class AppService(private val db: Database) {
    private val cache = ConcurrentHashMap<Long, DwarfModel>()

    fun importVersion(label: String, mainName: String, mainBytes: ByteArray,
                      dwos: List<Pair<String, ByteArray>>): VersionRow {
        // parse once to fail fast on garbage input; still store even if sections are partially corrupt
        DwarfModelLoader.load(mainBytes, dwos, mainName)
        val row = db.createVersion(label, mainName, mainBytes, dwos)
        val model = DwarfModelLoader.load(mainBytes, dwos, mainName)
        cache[row.id] = model
        val secRows = model.allObjects.first().elf.sections
            .filter { it.name.isNotBlank() }
            .map { s ->
                SectionRow(row.id, s.name, s.shType, s.flags, s.addr, s.offset, s.size, s.addralign,
                    if (s.data.isNotEmpty()) db.sha256(s.data) else "nobits")
            }
        db.addSections(row.id, secRows)
        return row
    }

    fun modelFor(versionId: Long): DwarfModel = cache.getOrPut(versionId) {
        val (main, dwos, row) = db.loadVersionBytes(versionId)
        DwarfModelLoader.load(main, dwos, row.mainFileName)
    }

    fun addCrash(snapshotId: Long, versionId: Long, addressHex: String, label: String?) =
        db.addCrash(snapshotId, versionId, addressHex, label)

    fun versions() = db.listVersions()
    fun snapshots() = db.listSnapshots()
    fun crashes(snapshotId: Long? = null) = db.listCrashes(snapshotId)

    fun createSnapshot(versionId: Long, label: String, modules: List<ModuleLoad>): SnapshotRow {
        val mapper = jacksonMapper()
        val json = mapper.writeValueAsString(modules.map {
            mapOf("moduleName" to it.moduleName, "runtimeBase" to it.runtimeBase,
                "fileBase" to it.fileBase, "note" to it.note)
        })
        return db.createSnapshot(versionId, label, json)
    }

    fun modulesOf(snapshot: SnapshotRow): List<ModuleLoad> {
        val mapper = jacksonMapper()
        val arr = mapper.readTree(snapshot.payload)
        return arr.map { n ->
            ModuleLoad(
                n.get("moduleName").asText(),
                if (n.has("runtimeBase") && !n.get("runtimeBase").isNull) n.get("runtimeBase").asLong() else null,
                if (n.has("fileBase") && !n.get("fileBase").isNull) n.get("fileBase").asLong() else null,
                if (n.has("note") && !n.get("note").isNull) n.get("note").asText() else null,
            )
        }
    }

    fun view(versionId: Long): ModelView {
        val model = modelFor(versionId)
        val row = db.listVersions().first { it.id == versionId }
        val secs = db.sections(versionId)
        val cus = model.allUnits.map { cu ->
            var count = 0
            fun countD(d: DIE?) { if (d == null) return; count++; d.children.forEach { countD(it) } }
            countD(cu.root)
            CuView(cu.headerOffset, cu.version,
                model.stringOf(cu.root?.at(Dw.AT_name), cu),
                model.stringOf(cu.root?.at(Dw.AT_comp_dir), cu),
                cu.isSkeleton, count, cu.warnings)
        }
        val seqs = model.allSequences.mapIndexed { i, s ->
            val cu = model.allUnits.firstOrNull { it.root?.at(Dw.AT_stmt_list)?.asLong() == s.unitOffset }
            SequenceView(
                id = "seq-$i", cuOffset = cu?.headerOffset, cuVersion = s.cuVersion,
                headerOffset = s.headerOffset, startAddress = s.startAddress, endAddress = s.endAddress,
                rowCount = s.rows.size, fileCount = s.files.size,
                files = s.files.map { it.name },
            )
        }
        val ranges = model.subprograms().flatMap { info ->
            info.ranges.map { r ->
                RangeView(info.die.offset, model.nameOf(info.die), info.die.tag, r.start, r.end,
                    r.zeroLength, model.stringOf(info.cu.root?.at(Dw.AT_name), info.cu),
                    info.die.tag == Dw.TAG_inlined_subroutine)
            }
        }.sortedWith(compareBy({ it.start }, { it.end }, { it.dieOffset }))
        return ModelView(row, secs, cus, seqs, ranges, model.allWarnings, model.main.elf.defaultLoadBase())
    }

    fun lineRows(versionId: Long, sequenceId: String): List<LineRowView> {
        val model = modelFor(versionId)
        val index = sequenceId.removePrefix("seq-").toIntOrNull() ?: return emptyList()
        val seq = model.allSequences.getOrNull(index) ?: return emptyList()
        return seq.rows.map { r ->
            LineRowView(r.address, r.line, r.column, seq.files.getOrNull(r.fileIndex - 1)?.name,
                r.isStatement, r.endSequence, r.prologueEnd, r.epilogueBegin,
                r.discriminator, r.isa, r.opIndex, r.segment)
        }
    }

    /** Inline tree: nested frames of every subprogram-bearing DIE for the address. */
    fun inlineTree(versionId: Long, addressHex: String, loads: List<ModuleLoad>): List<AddressExplanation> {
        val model = modelFor(versionId)
        val resolver = AddressResolver(model)
        val addrs = addressHex.split('\n', ',', ' ', '\t').map { it.trim() }.filter { it.isNotEmpty() }
        return addrs.flatMap { a -> loads.let { resolver.resolve(a, it) } }
    }

    fun resolveBatch(versionId: Long, addresses: List<String>, loads: List<ModuleLoad>): List<AddressExplanation> {
        val model = modelFor(versionId)
        val resolver = AddressResolver(model)
        return addresses.flatMap { addr -> resolver.resolve(addr, loads) }
    }
}
