package compass.dwarf

/** One decoded attribute value on a DIE. */
sealed class AttrValue {
    data class Addr(val v: Long) : AttrValue()
    data class Number(val v: Long) : AttrValue()
    data class Str(val v: String) : AttrValue()
    data class Block(val v: ByteArray) : AttrValue() {
        override fun equals(other: Any?) = other is Block && v.contentEquals(other.v)
        override fun hashCode() = v.contentHashCode()
    }
    /** DW_FORM_rnglistx / sec_offset into rnglists — resolved later by CU context. */
    data class SecOffset(val v: Long) : AttrValue()
    data class Ref(val globalOffset: Long) : AttrValue()
    data class Strx(val index: Long) : AttrValue()
    data class Addrx(val index: Long) : AttrValue()
    data class UnknownForm(val form: Int, val rawLen: Int) : AttrValue()
}

data class DieAttr(val name: Int, val form: Int, val value: AttrValue)

class DieNode(
    val offset: Long,           // global .debug_info offset of this DIE
    val tag: Int,
    val depth: Int,
    val attrs: MutableList<DieAttr>,
    val children: MutableList<DieNode> = mutableListOf(),
    var parent: DieNode? = null,
    /** Filled after range resolution. */
    val ranges: MutableList<AddressRange> = mutableListOf(),
    var cu: CompUnit? = null
) {
    fun attr(name: Int): DieAttr? = attrs.firstOrNull { it.name == name }
    fun num(name: Int): Long? = (attr(name)?.value as? AttrValue.Number)?.v
        ?: (attr(name)?.value as? AttrValue.Addr)?.v
    fun str(name: Int): String? = (attr(name)?.value as? AttrValue.Str)?.v
}

data class AddressRange(
    val start: Long,
    val end: Long,             // inclusive-exclusive; may equal start for zero-length
    val zeroLength: Boolean,
    val source: RangeSource,
    val dieOffset: Long
) {
    val width: Long get() = end - start
    fun contains(vaddr: Long): Boolean =
        if (zeroLength) vaddr == start else vaddr >= start && vaddr < end
}

enum class RangeSource { LOW_HIGH_PC, DEBUG_RANGES, RANGLISTS, ZERO_PC }

data class LineFile(val id: Int, val name: String, val dirIndex: Int)

data class LineRow(
    val address: Long,
    val opIndex: Int,
    val fileId: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
    val sequenceId: Int
)

data class LineEvent(
    val seqPos: Int,
    val address: Long,
    val file: String,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val kind: String,   // special / standard op name / extended op name
    val opcodeDetail: String
)

data class LineSequence(
    val id: Int,
    val cuOffset: Long,
    val startAddress: Long,
    val endAddress: Long,         // PC of end_sequence row
    val rows: List<LineRow>,
    val events: List<LineEvent>,
    val files: List<LineFile>,
    val dirs: List<String>,
    val dwarfVersion: Int,
    val segmented: Boolean
) {
    fun fileOf(fileId: Int): String? {
        val f = files.firstOrNull { it.id == fileId } ?: return null
        val dir = dirs.getOrNull(f.dirIndex)
        return if (dir.isNullOrEmpty() || dir == ".") f.name else "$dir/${f.name}"
    }
}

data class CompUnit(
    val offset: Long,
    val length: Int,
    val version: Int,
    val unitType: Int,
    val abbrevOffset: Long,
    val addressSize: Int,
    val root: DieNode?,
    val dieByOffset: Map<Long, DieNode>,
    val isDwo: Boolean,
    val dwoId: Long?,
    val dwoName: String?,
    var dwoResolved: Boolean = false,
    /** skeleton CU associated dwo CU */
    var splitCu: CompUnit? = null,
    /** when this is a split CU, back-link to skeleton */
    var skeletonCu: CompUnit? = null
) {
    val isSkeleton: Boolean get() = version >= 5 && unitType == DW_UT.SKELETON
}

data class ParseDiagnostic(
    val severity: String,  // ERROR | WARNING | INFO
    val code: String,
    val message: String,
    val section: String?,
    val offset: Long?
)

class ParseResult(
    val cus: List<CompUnit>,
    val sequences: List<LineSequence>,
    val diagnostics: MutableList<ParseDiagnostic> = mutableListOf()
)
