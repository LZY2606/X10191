package compass.storage

import compass.dwarf.CodeSymbol
import compass.dwarf.DebugSections
import compass.dwarf.DwarfFileParser
import compass.dwarf.RangeResolver
import compass.elf.ElfParser
import compass.model.ParsedDebugFile
import compass.resolve.AddressExplanation
import compass.resolve.AddressResolver
import compass.resolve.ModuleSnapshot
import java.util.concurrent.ConcurrentHashMap

class Workspace(private val db: Database) {
    private data class CacheEntry(
        val versionId: Long,
        val parsed: ParsedDebugFile,
        val symbols: List<CodeSymbol>,
        val resolver: AddressResolver,
        val rangeResolver: RangeResolver,
    )

    private val cache = ConcurrentHashMap<Long, CacheEntry>()

    fun importFile(filename: String, bytes: ByteArray): Long {
        val elf = ElfParser.parse(bytes, filename)
        val parsed = DwarfFileParser(elf).parse()
        val isSplit = parsed.units.any { it.isSplit }
        val dwoId = parsed.units.firstNotNullOfOrNull { it.dwoId }?.toString(16)
        val versionId = db.insertVersion(
            filename, parsed.fileSha, elf.buildId, elf.elfClass.name, elf.machine,
            bytes, isSplit, dwoId,
        )
        // Sections rows are idempotent only when version is new; detect by count.
        if (!db.sectionsExist(versionId)) {
            for (s in elf.sections) {
                val sha = if (s.data.isNotEmpty()) ElfParser.sha256(s.data) else null
                db.insertSection(versionId, s.name, s.addr, s.fileOffset, s.size, sha)
            }
            for (seg in elf.segments.filter { it.type == 1 }) {
                db.insertSegment(versionId, seg.flags, seg.fileOffset, seg.vaddr, seg.memsz)
            }
            for (issue in parsed.issues) {
                db.insertIssue(versionId, issue.severity, issue.code, issue.message, issue.section, issue.offset)
            }
            val rr = RangeResolver(DebugSections(elf))
            val symbols = DwarfFileParser.symbols(parsed, rr)
            for (sym in symbols) {
                val cu = parsed.units.firstOrNull { it.headerOffset == sym.cuHeaderOffset }
                for (r in sym.ranges) {
                    db.insertSummaryRange(
                        versionId, cu?.name, if (sym.isInline) "INLINE" else "FUNCTION",
                        sym.name ?: sym.linkageName, r, sym.depth,
                    )
                }
            }
            for (prog in parsed.linePrograms) {
                for (seq in prog.sequences) {
                    val r = seq.range()
                    db.insertSummaryRange(
                        versionId, cuNameForStmtOffset(parsed, seq.cuHeaderOffset),
                        "LINE_SEQUENCE", "seq#${seq.index}", r, 0,
                    )
                }
            }
        }
        loadIntoCache(versionId)
        return versionId
    }

    private fun cuNameForStmtOffset(parsed: ParsedDebugFile, stmtOffset: Long): String? =
        parsed.units.firstOrNull { it.root?.num(compass.dwarf.DW.AT_stmt_list) == stmtOffset }?.name

    fun loadIntoCache(versionId: Long) {
        if (cache.containsKey(versionId)) return
        val version = db.getVersion(versionId) ?: error("version $versionId missing")
        val elf = ElfParser.parse(version.fileBlob, version.originalFilename)
        val parsed = DwarfFileParser(elf).parse()
        val rr = RangeResolver(DebugSections(elf))
        val symbols = DwarfFileParser.symbols(parsed, rr)
        val resolver = AddressResolver(parsed, symbols, rr)
        cache[versionId] = CacheEntry(versionId, parsed, symbols, resolver, rr)
    }

    fun warmAll() {
        db.listVersions().forEach { loadIntoCache(it.id) }
    }

    fun parsed(versionId: Long): ParsedDebugFile =
        cache[versionId]?.parsed ?: error("version $versionId not imported")

    fun symbols(versionId: Long): List<CodeSymbol> =
        cache[versionId]?.symbols ?: error("version $versionId not imported")

    fun resolve(versionId: Long, runtimeAddr: Long, selector: Long, snapshotIds: List<Long>?): AddressExplanation {
        val entry = cache[versionId] ?: error("version $versionId not imported")
        val snaps = if (snapshotIds == null) db.listSnapshots(versionId)
        else db.listSnapshots(versionId).filter { it.id in snapshotIds }
        return entry.resolver.resolve(runtimeAddr, selector, snaps)
    }

    fun addSnapshot(versionId: Long, label: String, loadBase: Long, generation: Int): Long {
        val elf = parsed(versionId).elf
        val firstLoad = elf.segments.filter { it.type == 1 }.minByOrNull { it.vaddr }
            ?: throw IllegalStateException("no PT_LOAD segment to compute bias")
        val id = db.addSnapshot(versionId, label, loadBase, firstLoad.vaddr, generation)
        return id
    }

    fun snapshots(versionId: Long): List<ModuleSnapshot> = db.listSnapshots(versionId)

    fun versions() = db.listVersions()

    fun saveCrash(label: String, versionId: Long, snapshotId: Long?, addresses: List<Long>, results: List<AddressExplanation>): Long {
        val fingerprint = parsed(versionId).fileSha
        val addressesJson = kotlinx.serialization.json.Json.encodeToString(
            kotlinx.serialization.builtins.ListSerializer(kotlinx.serialization.serializer<Long>()), addresses,
        )
        val dto = results.map { ExplanationDto.from(it) }
        val resultJson = kotlinx.serialization.json.Json.encodeToString(
            kotlinx.serialization.builtins.ListSerializer(ExplanationDto.serializer()), dto,
        )
        return db.insertCrash(label, snapshotId, addressesJson, resultJson, fingerprint)
    }

    fun crashes() = db.listCrashes()
}
