package compass.store

import compass.dwarf.ParsedDwarf
import compass.elf.ElfFile

/** A loaded debug file = one immutable version of a module keyed by ELF build id/name. */
data class LoadedModule(
    val id: Long,
    val key: String,
    val version: Int,
    val fileName: String,
    val sha256: String,
    val elf: ElfFile,
    val dwarf: ParsedDwarf,
    val importedAt: String,
    /** True when a later version exists. Old versions remain queryable. */
    val superseded: Boolean,
)

/** A fixed view of a module load: base + generation, pinned by a snapshot. */
data class ModuleLoad(
    val moduleKey: String,
    val moduleVersion: Int,
    val loadBias: Long,
    val generation: Int,
    val label: String?,
)

data class LoadSnapshot(
    val id: Long,
    val name: String,
    val createdAt: String,
    val loads: List<ModuleLoad>,
)

data class CrashBatch(
    val id: Long,
    val name: String,
    val snapshotId: Long,
    val createdAt: String,
    val rawInput: String,
    val addresses: List<Long>,
)
