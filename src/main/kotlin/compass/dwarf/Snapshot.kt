package compass.dwarf

/** One loaded module in a pinned crash-time snapshot. */
data class SnapshotModule(
    val name: String,
    val fileId: Long,
    val base: Long,
    /** Optional generation tag so the same relative address can map to reloads. */
    val generation: Int = 0
)

/**
 * An immutable loading snapshot. Once created, later imports never alter
 * which (module base, debug file) pairs a query uses.
 */
class SnapshotView(
    val id: Long,
    val label: String,
    val createdAt: String,
    val modules: List<SnapshotModule>
) {
    fun modulesMatching(input: AddressInput): List<SnapshotModule> {
        val named = input.moduleKey?.let { key -> modules.filter { it.name == key } } ?: modules
        // Generations are preserved; all modules remain legal candidates and
        // stable ordering (base, then insertion order) keeps queries deterministic.
        return named.sortedWith(compareBy({ it.base }, { it.generation }, { it.name }))
    }
}
