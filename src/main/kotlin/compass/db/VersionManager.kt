package compass.db

import compass.dwarf.DwarfIndex
import compass.dwarf.DwarfLoader
import compass.elf.BuildId
import compass.elf.DwarfParseException
import compass.elf.ElfFile
import java.util.concurrent.ConcurrentHashMap
import java.io.ByteArrayInputStream

class ImportResult(
    val versionId: Long,
    val reused: Boolean,
    val index: DwarfIndex,
    val buildId: String?
)

class VersionManager(private val repo: Repository) {
    private val cache = ConcurrentHashMap<Long, DwarfIndex>()
    private val bySha = ConcurrentHashMap<String, Long>()

    fun init() {
        for (row in repo.listVersions()) {
            bySha[row.sha256] = row.id
            val bytes = runCatching { repo.loadBlobQuiet(row.id) }.getOrNull()
            if (bytes != null) {
                runCatching {
                    val idx = DwarfLoader.load(ElfFile(bytes, row.fileName))
                    cache[row.id] = idx
                }
            }
        }
    }

    fun indexFor(versionId: Long): DwarfIndex? = cache[versionId]

    fun importFile(fileName: String, raw: ByteArray): ImportResult {
        // Parse fully BEFORE writing any DB row.
        val elf = ElfFile(raw, fileName)
        val idx = DwarfLoader.load(elf)
        val sha = idx.rawSha256
        val existing = bySha[sha]
        if (existing != null) {
            return ImportResult(existing, true, cache.getOrPut(existing) { idx }, BuildId.extract(elf))
        }
        val buildId = BuildId.extract(elf)
        val versions = idx.cus.map { it.version }.distinct().sorted()
        val hasDwo = elf.section(".debug_info.dwo") != null
        val id = repo.insertVersion(
            fileName = fileName,
            buildId = buildId,
            sha256 = sha,
            elfClass = if (elf.is64) "ELF64" else "ELF32",
            endian = if (elf.bigEndian) "big" else "little",
            machine = elf.machine,
            dwarfVersions = versions,
            cuCount = idx.cus.size,
            sectionCount = idx.sections.size,
            hasDwo = hasDwo,
            warnings = idx.warnings
        )
        repo.storeBlobQuiet(id, raw)
        cache[id] = idx
        bySha[sha] = id
        return ImportResult(id, false, idx, buildId)
    }

    /** Re-parse isn't supported after restart (bytes not stored); callers register preloaded indexes. */
    fun register(versionId: Long, idx: DwarfIndex) {
        cache[versionId] = idx
    }
}
