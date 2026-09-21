package compass.web

import compass.db.Database
import compass.db.SnapshotRepository
import compass.db.StoredQuery
import compass.db.VersionRepository
import compass.dwarf.AddressAnswer
import compass.dwarf.AddressResolver
import compass.dwarf.DW_AT
import compass.dwarf.DW_TAG
import compass.dwarf.DebugVersion
import compass.dwarf.LineEvent
import compass.dwarf.LineRow
import compass.dwarf.LineSequence
import compass.dwarf.ModuleLoad
import compass.dwarf.tableVersionSummary
import java.io.File

class AppService(val db: Database) {
    val versions = VersionRepository(db)
    val snapshots = SnapshotRepository(db)

    @Volatile private var cache: List<DebugVersion>? = null

    @Synchronized
    fun invalidateCache() { cache = null }

    private fun loadedVersions(): List<DebugVersion> {
        cache?.let { return it }
        val v = versions.loadAll()
        cache = v
        return v
    }

    fun importFile(path: String, label: String?, priority: Int): Long {
        val f = File(path)
        require(f.exists()) { "文件不存在: $path" }
        val bytes = f.readBytes()
        val id = versions.import(label ?: f.name, bytes, priority, path).versionId
        invalidateCache()
        return id
    }

    fun importBytes(label: String, bytes: ByteArray, priority: Int, split: ByteArray? = null): Long {
        val id = versions.import(label, bytes, priority, label, split).versionId
        invalidateCache()
        return id
    }

    fun resolveBatch(addresses: List<Long>, snapshotId: Long?): List<AddressAnswer> {
        val vs = loadedVersions()
        val loads = if (snapshotId != null) snapshots.loadsFor(snapshotId)
        else allLoadsAcrossSnapshots()
        val resolver = AddressResolver(vs, loads)
        return addresses.map { resolver.resolve(it) }
    }

    fun resolveAndFreeze(snapshotId: Long, title: String, addresses: List<Long>): Long {
        val answers = resolveBatch(addresses, snapshotId)
        val queries = addresses.mapIndexed { i, addr -> StoredQuery(i, addr, answers[i]) }
        return snapshots.saveCrash(snapshotId, title, queries)
    }

    private fun allLoadsAcrossSnapshots(): List<ModuleLoad> =
        snapshots.listSnapshots().flatMap { snapshots.loadsFor(it.id) }

    // ---------- section map / detail DTOs ----------
    fun sectionMap(versionId: Long): Map<String, Any?> {
        val v = loadedVersions().firstOrNull { it.versionId == versionId }
            ?: error("版本 $versionId 不存在")
        val img = v.image
        val secs = img.elf.sections.filter { it.name.isNotEmpty() }.map { s ->
            mapOf(
                "name" to s.name, "type" to s.type, "addr" to s.addr,
                "offset" to s.offset, "size" to s.size, "flags" to s.flags,
                "debug" to s.name.startsWith(".debug"),
                "sha256" to (runCatching {
                    val b = img.elf.sectionBytes(s.name)
                    java.security.MessageDigest.getInstance("SHA-256").digest(b!!)
                        .joinToString("") { "%02x".format(it) }
                }.getOrNull())
            )
        }
        return mapOf(
            "versionId" to versionId,
            "label" to v.label,
            "buildId" to img.elf.buildId(),
            "elfClass" to img.elf.elfClass,
            "littleEndian" to img.elf.littleEndian,
            "tableVersion" to v.dwarfTableVersion,
            "sections" to secs,
            "segments" to img.elf.segments.map {
                mapOf("type" to it.type, "vaddr" to it.vaddr, "filesz" to it.filesz,
                    "memsz" to it.memsz, "flags" to it.flags)
            }
        )
    }

    fun addressRanges(versionId: Long): List<Map<String, Any?>> {
        val v = loadedVersions().first { it.versionId == versionId }
        val out = mutableListOf<Map<String, Any?>>()
        for (cu in v.image.cus + v.image.splitCus) {
            val root = cu.root ?: continue
            walk(root) { d ->
                for (rg in d.ranges) {
                    out.add(mapOf(
                        "dieOffset" to d.offset, "cuOffset" to cu.offset,
                        "tag" to d.tag,
                        "name" to (d.str(DW_AT.NAME) ?: d.str(DW_AT.LINKAGE_NAME)
                            ?: "<anon>@0x${d.offset.toString(16)}"),
                        "start" to rg.start, "end" to rg.end,
                        "width" to rg.width, "zeroLength" to rg.zeroLength,
                        "source" to rg.source.name, "inline" to (d.tag == DW_TAG.INLINED_SUBROUTINE)
                    ))
                }
            }
        }
        return out.sortedBy { it["start"] as Long }
    }

    fun sequences(versionId: Long): List<Map<String, Any?>> {
        val v = loadedVersions().first { it.versionId == versionId }
        return v.image.sequences.map { seq ->
            mapOf(
                "id" to seq.id, "cuOffset" to seq.cuOffset,
                "start" to seq.startAddress, "end" to seq.endAddress,
                "dwarfVersion" to seq.dwarfVersion, "segmented" to seq.segmented,
                "rows" to seq.rows.size, "events" to seq.events.size
            )
        }
    }

    fun lineEvents(versionId: Long, sequenceId: Int): Map<String, Any?> {
        val v = loadedVersions().first { it.versionId == versionId }
        val seq = v.image.sequences.first { it.id == sequenceId }
        return mapOf(
            "sequence" to mapOf(
                "id" to seq.id, "cuOffset" to seq.cuOffset,
                "start" to seq.startAddress, "end" to seq.endAddress,
                "dwarfVersion" to seq.dwarfVersion, "segmented" to seq.segmented,
                "dirs" to seq.dirs
            ),
            "rows" to seq.rows.map { rowDto(it) },
            "events" to seq.events.map { eventDto(it) }
        )
    }

    fun inlineTree(versionId: Long): List<Map<String, Any?>> {
        val v = loadedVersions().first { it.versionId == versionId }
        val out = mutableListOf<Map<String, Any?>>()
        for (cu in v.image.cus + v.image.splitCus) {
            val root = cu.root ?: continue
            walk(root) { d ->
                if (d.tag == DW_TAG.SUBPROGRAM || d.tag == DW_TAG.INLINED_SUBROUTINE) {
                    out.add(mapOf(
                        "cuOffset" to cu.offset, "dieOffset" to d.offset,
                        "tag" to d.tag, "depth" to d.depth,
                        "parent" to d.parent?.offset,
                        "name" to (d.str(DW_AT.NAME) ?: d.str(DW_AT.LINKAGE_NAME)
                            ?: "<anon>@0x${d.offset.toString(16)}"),
                        "callLine" to d.num(DW_AT.CALL_LINE),
                        "ranges" to d.ranges.map {
                            mapOf("start" to it.start, "end" to it.end, "zeroLength" to it.zeroLength)
                        }
                    ))
                }
            }
        }
        return out
    }

    fun diagnostics(versionId: Long): List<Map<String, Any?>> {
        val v = loadedVersions().first { it.versionId == versionId }
        return v.image.diagnostics.map {
            mapOf("severity" to it.severity, "code" to it.code, "message" to it.message,
                "section" to it.section, "offset" to it.offset)
        }
    }

    fun cus(versionId: Long) = run {
        val v = loadedVersions().first { it.versionId == versionId }
        (v.image.cus + v.image.splitCus).map { cu ->
            mapOf(
                "offset" to cu.offset, "version" to cu.version, "unitType" to cu.unitType,
                "addressSize" to cu.addressSize,
                "name" to (cu.root?.str(DW_AT.NAME) ?: ""),
                "compDir" to cu.root?.str(DW_AT.COMP_DIR),
                "isSkeleton" to cu.isSkeleton, "isDwo" to cu.isDwo,
                "dwoName" to cu.dwoName, "dwoId" to cu.dwoId?.toString(16),
                "dwoResolved" to cu.dwoResolved,
                "dies" to cu.dieByOffset.size
            )
        }
    }

    private fun rowDto(r: LineRow) = mapOf(
        "address" to r.address, "file" to r.fileId, "line" to r.line, "column" to r.column,
        "isStmt" to r.isStmt, "basicBlock" to r.basicBlock, "endSequence" to r.endSequence,
        "prologueEnd" to r.prologueEnd, "discriminator" to r.discriminator
    )
    private fun eventDto(e: LineEvent) = mapOf(
        "pos" to e.seqPos, "address" to e.address, "file" to e.file, "line" to e.line,
        "column" to e.column, "isStmt" to e.isStmt, "kind" to e.kind, "detail" to e.opcodeDetail
    )
    private fun walk(d: compass.dwarf.DieNode, fn: (compass.dwarf.DieNode) -> Unit) {
        fn(d); d.children.forEach { walk(it, fn) }
    }
}
