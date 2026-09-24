package compass.dwarf

/** One resolved attribute value; unresolved forms keep raw forms so isolation is explicit. */
sealed class AttrValue {
    data class Addr(val value: Long) : AttrValue()
    data class Const(val value: Long) : AttrValue()
    data class Str(val value: String) : AttrValue()
    /** Offset into .debug_info (global, i.e. absolute section offset). */
    data class Ref(val offset: Long) : AttrValue()
    data class SectionOffset(val section: String, val offset: Long) : AttrValue()
    data class Bytes(val value: ByteArray) : AttrValue() {
        override fun equals(other: Any?) = other is Bytes && value.contentEquals(other.value)
        override fun hashCode() = value.contentHashCode()
    }
    /** Kept until str/addr indices can be resolved against the CU's bases. */
    data class PendingStrIndex(val index: Int) : AttrValue()
    data class PendingAddrIndex(val index: Int) : AttrValue()
}

data class Attribute(val name: Int, val form: Int, val value: AttrValue)

data class DIE(
    val offset: Long,
    val tag: Int,
    val children: MutableList<DIE> = mutableListOf(),
    val attributes: MutableList<Attribute> = mutableListOf(),
    var parent: DIE? = null,
    var unit: CompUnit? = null,
) {
    fun attr(name: Int): Attribute? = attributes.firstOrNull { it.name == name }
    fun attrValue(name: Int): AttrValue? = attr(name)?.value

    /** Walk the tree rooted here (pre-order). Depth is capped by the parser. */
    inline fun walk(action: (DIE) -> Unit) {
        val stack = ArrayDeque<DIE>()
        stack.addLast(this)
        while (stack.isNotEmpty()) {
            val d = stack.removeLast()
            action(d)
            for (i in d.children.indices.reversed()) stack.addLast(d.children[i])
        }
    }
}

/** A resolved code-address range. start==end marks a zero-length range (retained). */
data class AddrRange(val start: Long, val end: Long, val segment: Int = 0) {
    val isZeroLength get() = start == end
    fun contains(addr: Long): Boolean = addr in start until end
}

class CompUnit(
    val version: Int,
    val is64BitDwarf: Boolean,
    val unitType: Int,
    val headerOffset: Long,
    val endOffset: Long,
    val abbrevOffset: Long,
    val addressSize: Int,
    val dwoId: Long?,
    val root: DIE,
    /** Section the unit came from: .debug_info or .debug_types/.debug_info.dwo */
    val infoSection: String,
) {
    val name: String? get() = root.attrValue(DW.AT.name)?.let { it as? AttrValue.Str }?.value
    val compDir: String? get() = root.attrValue(DW.AT.comp_dir)?.let { it as? AttrValue.Str }?.value
    val dwoName: String?
        get() = (root.attrValue(DW.AT.dwo_name) ?: root.attrValue(DW.AT.GNU_dwo_name))
            ?.let { it as? AttrValue.Str }?.value
    val isSkeleton get() = version >= 5 && unitType == DW.UT.skeleton
    val isSplitCompile get() = version >= 5 && unitType == DW.UT.split_compile

    var parseError: String? = null
    var partial: Boolean = false

    /** Base for DW_FORM_addrx indices (offset into .debug_addr), set from root attrs. */
    var addrBase: Long = 0L
    /** Base for DW_FORM_strx indices (offset into .debug_str_offsets). */
    var strOffsetsBase: Long = 0L
    /** Base for DW_AT_rnglists_base-relative rnglistx. */
    var rnglistsBase: Long = 0L

    /** When this is a skeleton unit, the linked split unit (after pairing). */
    var splitUnit: CompUnit? = null
    /** When this is a split unit, its skeleton. */
    var skeletonUnit: CompUnit? = null

    fun attr(which: Int) = root.attrValue(which)
}
