package compass.db

import compass.dwarf.*
import compass.elf.ElfParser
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

data class ImportedVersion(
    val id: Long,
    val label: String,
    val fileName: String,
    val info: DebugInfo,
    val elf: compass.elf.ElfFile,
    val bytes: ByteArray,
    val kind: String,
    val splitVersionId: Long?
)

data class BatchHit(val ordinal: Int, val input: String, val result: AddressQueryResult)

/**
 * In-memory parsed versions on top of the immutable SQLite history. Re-import
 * adds a new row/version and never mutates existing crash records.
 */
class Repository(private val db: CompassDatabase, private val blobDir: Path) {
    private val versions = LinkedHashMap<Long, ImportedVersion>()
    private val snapshots = LinkedHashMap<Long, ModuleLoad>()

    init { Files.createDirectories(blobDir) }

    fun importDebugFile(
        bytes: ByteArray, fileName: String, label: String, kind: String,
        dwoBytes: ByteArray? = null
    ): ImportedVersion {
        val elf = ElfParser.parse(bytes)
        val splitElf = dwoBytes?.let { ElfParser.parse(it) }
        val info = DwarfParser.parse(elf, splitElf, fileName)

        val versionId = db.createVersion(label, fileName, bytes, kind, info.splitStatus.name, null)
        // Persist section map + raw byte summaries.
        for (sec in elf.sections) {
            val view = sec.bytes
            val raw = view?.let { ba ->
                java.util.Arrays.copyOfRange(ba.data, ba.offset, ba.offset + ba.length)
            }
            db.addSection(versionId, sec.name, sec.addr, sec.offset, sec.size, sec.flags, raw)
        }
        // Store the raw bytes blob on disk so later sessions can re-parse without re-upload.
        val blob = blobDir.resolve("v$versionId-${safe(fileName)}")
        Files.write(blob, bytes)

        val imported = ImportedVersion(versionId, label, fileName, info, elf, bytes, kind, null)
        versions[versionId] = imported
        return imported
    }

    fun version(id: Long): ImportedVersion? = versions[id]
    fun allVersions(): List<ImportedVersion> = versions.values.toList()

    fun addSnapshot(versionId: Long, moduleName: String, preferredBase: Long, loadBase: Long, generation: Int): Long {
        val id = db.createSnapshot(versionId, moduleName, preferredBase, loadBase, generation)
        snapshots[id] = ModuleLoad(moduleName, preferredBase, loadBase, generation)
        return id
    }

    fun snapshot(id: Long): ModuleLoad? = snapshots[id]

    fun saveCrash(label: String, snapshotId: Long?, versionId: Long, hits: List<BatchHit>): Long {
        val crashId = db.createCrash(label, snapshotId, versionId)
        for (h in hits) db.addFrame(crashId, h.ordinal, h.result.runtimePc, JsonCodec.encode(h.result))
        return crashId
    }

    /**
     * Batch resolve pasted stack addresses. Hex lines may contain surrounding
     * noise; we extract the first hex token per line.
     */
    fun resolveBatch(versionId: Long, text: String, load: ModuleLoad?): List<BatchHit> {
        val v = versions[versionId] ?: throw IllegalArgumentException("未知版本: $versionId")
        val resolver = Resolver(v.info)
        val out = ArrayList<BatchHit>()
        text.lines().forEachIndexed { idx, rawLine ->
            val line = rawLine.trim()
            if (line.isEmpty()) return@forEachIndexed
            val token = HEX.find(line)?.value ?: return@forEachIndexed
            val pc = java.lang.Long.parseUnsignedLong(token.removePrefix("0x"), 16)
            out.add(BatchHit(idx, line, resolver.query(pc, load)))
        }
        return out
    }

    private fun safe(n: String) = n.replace(Regex("[^A-Za-z0-9._-]"), "_")

    companion object {
        private val HEX = Regex("(?i)(?:0x)?[0-9a-f]{8,16}")
    }
}

/** Trivial JSON codec for query results — keeps one dependency surface small. */
object JsonCodec {
    fun encode(r: AddressQueryResult): String = buildString {
        append("{\"runtimePc\":").append(r.runtimePc)
        append(",\"relativePc\":").append(r.relativePc)
        append(",\"loadBias\":").append(r.loadBias)
        append(",\"candidateCount\":").append(r.candidates.size)
        append("}")
    }
}

@Suppress("unused")
private fun ByteArray.sha(): String =
    MessageDigest.getInstance("SHA-256").digest(this).joinToString("") { "%02x".format(it) }
