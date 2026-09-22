package compass.dwarf

import compass.elf.ElfFile

/** All imported debug files + global cross-file resolution. */
class Registry {
    private val files = LinkedHashMap<Long, ParsedFile>()
    private val bySha = HashMap<String, Long>()
    private var nextId = 1L

    @Synchronized
    fun importElf(elf: ElfFile): Pair<ParsedFile, Boolean> {
        val existing = bySha[elf.fileSha256]
        if (existing != null) return files.getValue(existing) to false
        val id = nextId++
        val parsed = FileParser.parse(id, elf)
        files[id] = parsed
        bySha[elf.fileSha256] = id
        relink()
        return parsed to true
    }

    @Synchronized fun file(id: Long): ParsedFile? = files[id]
    @Synchronized fun all(): List<ParsedFile> = files.values.toList()
    @Synchronized fun size(): Int = files.size

    /** Resolve a section-global info offset (DW_FORM_ref_addr) in a given file. */
    fun globalInfoDie(fileId: Long, offset: Long): DieNode? =
        files[fileId]?.dieAtGlobalOffset(offset)?.second

    /** Insert a pre-parsed file with a fixed id (rehydration from disk). */
    @Synchronized
    fun adopt(parsed: ParsedFile) {
        files[parsed.id] = parsed
        bySha[parsed.sha256] = parsed.id
        if (parsed.id >= nextId) nextId = parsed.id + 1
    }

    @Synchronized
    fun relink() {
        SplitLinker.link(files.values)
        for (f in files.values) DeferredResolver.resolve(f, files.values)
    }
}
