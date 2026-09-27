package compass.dwarf

/** Raw, unresolved attribute value read with a specific form. */
sealed class RawValue {
    data class Addr(val v: Long) : RawValue()
    data class Num(val v: Long) : RawValue()
    data class Bytes(val v: ByteArray) : RawValue()
    data class Str(val v: String) : RawValue()
    data class StrRef(val offset: Long) : RawValue()
    data class LineStrRef(val offset: Long) : RawValue()
    data class CuRef(val offset: Long) : RawValue()          // CU-relative ref
    data class GlobalRef(val offset: Long) : RawValue()      // .debug_info global offset
    data class StrIndex(val index: Long) : RawValue()
    data class AddrIndex(val index: Long) : RawValue()
    data class RngListIndex(val index: Long) : RawValue()
    data class RngListOffset(val offset: Long) : RawValue()
    data class Signature(val v: Long) : RawValue()
    data object Flag : RawValue()
    data object Present : RawValue()
}

data class RawAttr(val name: Int, val form: Int, val value: RawValue)

data class RawDie(
    val offset: Long,
    val tag: Int,
    val attrs: List<RawAttr>,
    val children: List<RawDie>,
    /** depth below the CU root DIE (root = 0). */
    val depth: Int,
    /** stable DFS ordinal within the CU. */
    val ordinal: Int,
) {
    fun attr(name: Int): RawAttr? = attrs.firstOrNull { it.name == name }
}

data class CompileUnit(
    /** global .debug_info offset of the unit header. */
    val offset: Long,
    val version: Int,
    val unitType: Int,
    val is64: Boolean,
    val abbrevOffset: Long,
    val addressSize: Int,
    /** CU-relative .debug_line offset from DW_AT_stmt_list. */
    val stmtList: Long?,
    val root: RawDie,
    val allDies: List<RawDie>,
    /** split / dwo linkage, parsed from the root DIE. */
    val dwoName: String?,
    val dwoId: Long?,
    /** true for skeleton units whose split CU bytes were not supplied. */
    var dwoMissing: Boolean = false,
    /** non-fatal diagnostics gathered while parsing this unit. */
    val warnings: MutableList<String> = mutableListOf(),
    /** when parsing this CU had to be aborted, what went wrong. */
    var fatal: String? = null,
    /** bytes covered by the whole unit header+DIEs (for global ref checks). */
    val unitEnd: Long,
) {
    val isSkeleton: Boolean get() = unitType == DwUt.SKELETON || tagIsSkeleton(root.tag)
    val isSplit: Boolean get() = unitType == DwUt.SPLIT_COMPILE || unitType == DwUt.SPLIT_TYPE
    private fun tagIsSkeleton(tag: Int) = tag == DwTag.SKELETON_UNIT

    fun compDir(): String? = (root.attr(DwAt.COMP_DIR)?.value as? RawValue.Str)?.v
    fun nameAttr(): String? = (root.attr(DwAt.NAME)?.value as? RawValue.Str)?.v
}
