package compass.dwarf

/** Resolved attribute value. Forms that cannot be resolved (e.g. strx without
 *  .debug_str_offsets) become [Unresolved] so the cursor never misaligns. */
sealed class AttrValue {
    data class Addr(val v: Long) : AttrValue()
    data class Const(val v: Long) : AttrValue()
    data class SConst(val v: Long) : AttrValue()
    data class Str(val v: String) : AttrValue()
    data class Strp(val offset: Long, val resolved: String?) : AttrValue()
    data class Ref(val cuRelative: Boolean, val offset: Long) : AttrValue()
    data class Flag(val v: Boolean) : AttrValue()
    data class SecOffset(val v: Long) : AttrValue()
    data class Block(val bytes: ByteArray) : AttrValue()
    /** addrx/strx kept as raw index until the CU root attributes (addr_base,
     *  str_offsets_base) are known; resolved in a second pass. */
    data class Addrx(val index: Long) : AttrValue()
    data class Strx(val index: Long) : AttrValue()
    data class Unresolved(val form: Int, val note: String) : AttrValue()
}

data class Die(
    val offset: Int,
    val tag: Int,
    val depth: Int,
    val attrs: LinkedHashMap<Int, AttrValue>,
    val children: MutableList<Die> = mutableListOf()
) {
    fun strAttr(at: Int): String? = when (val v = attrs[at]) {
        is AttrValue.Str -> v.v
        is AttrValue.Strp -> v.resolved
        else -> null
    }

    fun constAttr(at: Int): Long? = when (val v = attrs[at]) {
        is AttrValue.Const -> v.v
        is AttrValue.SConst -> v.v
        is AttrValue.Addr -> v.v
        is AttrValue.SecOffset -> v.v
        else -> null
    }

    fun addrAttr(at: Int): Long? = (attrs[at] as? AttrValue.Addr)?.v
}

data class CuHeader(
    val unitOffset: Int,
    val unitLength: Long,
    val version: Int,
    val unitType: Int,
    val addressSize: Int,
    val abbrevOffset: Long,
    val diesOffset: Int,
    val nextUnitOffset: Int,
    val dwarf64: Boolean
)

object Limits {
    const val MAX_DEPTH = 64
    const val MAX_DIES = 200_000
    const val MAX_REF_HOPS = 16
    const val MAX_LINE_ROWS = 1_000_000
    const val MAX_RANGES = 1_000_000
}
