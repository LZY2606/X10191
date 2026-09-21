package compass.dwarf

/**
 * One fully parsed debug module: main ELF plus, when available, a linked split DWARF
 * companion (.dwo / .dwp). The companion is matched by `DW_AT_dwo_id`/GNU dwo id.
 *
 * Everything needed to explain an address is kept in memory; raw bytes stay in the
 * importing version record so a re-import reproduces identical results.
 */
class DebugModule(
    val data: DwarfData,
    val units: List<CompilationUnit>,
    val dwoUnits: List<CompilationUnit>,
    val rangeResolver: RangeResolver,
    val lineParser: LineProgramParser,
) {
    val warnings: List<String> get() = data.warnings.toList()

    private val dwoById = dwoUnits.mapNotNull { u -> u.dwoId?.let { it to u } }.toMap()

    /** Skeleton units (DWARF5 unit_type=4 / DW_TAG_skeleton_unit) that request a dwo. */
    data class SplitLink(val skeleton: CompilationUnit, val dwoId: ULong?, val dwoName: String?, val resolved: Boolean)

    val splitLinks: List<SplitLink>
        get() = units.mapNotNull { cu ->
            val root = cu.root
            val isSkeleton = cu.version >= 5 && root.tag == Tag.SKELETON_UNIT
            val hasDwoName = root.attr(Attr.DW_AT_dwo_name) != null || root.attr(Attr.DW_AT_GNU_dwo_name) != null
            if (!isSkeleton && !hasDwoName) return@mapNotNull null
            val id = root.attr(Attr.DW_AT_GNU_dwo_id)?.value?.asLong?.toULong()
                ?: root.attr(Attr.DW_AT_dwo_id5)?.value?.asLong?.toULong()
            val name = root.attr(Attr.DW_AT_dwo_name)?.value?.asString
                ?: root.attr(Attr.DW_AT_GNU_dwo_name)?.value?.asString
            SplitLink(cu, id ?: cu.dwoId, name, (id ?: cu.dwoId)?.let { dwoById.containsKey(it) } == true)
        }

    fun dwoFor(cu: CompilationUnit): CompilationUnit? {
        val id = cu.dwoId ?: cu.root.attr(Attr.DW_AT_GNU_dwo_id)?.value?.asLong?.toULong()
        return id?.let { dwoById[it] }
    }

    companion object {
        fun load(data: DwarfData): DebugModule {
            val units = try {
                UnitParser(data, isDwo = false).parse()
            } catch (e: Exception) {
                data.warnings += ".debug_info parse aborted: ${e.message}"
                emptyList()
            }
            units.forEachIndexed { i, cu -> cu.let { it.root.cuIndex = i } }
            val dwoUnits = if (data.debugInfoDwo != null) {
                try {
                    UnitParser(data, isDwo = true).parse()
                } catch (e: Exception) {
                    data.warnings += ".debug_info.dwo parse aborted: ${e.message}"
                    emptyList()
                }
            } else emptyList()
            dwoUnits.forEachIndexed { i, cu -> cu.root.cuIndex = i }
            return DebugModule(data, units, dwoUnits, RangeResolver(data), LineProgramParser(data))
        }
    }
}

/** Flatten a DIE tree in pre-order, keeping parent links implicit via depth. */
fun Die.flatten(): List<Die> {
    val out = ArrayList<Die>()
    fun walk(d: Die) {
        out.add(d)
        d.children.forEach(::walk)
    }
    walk(this)
    return out
}
