package compass.dwarf

/**
 * Fully parsed, in-memory view of one debug-object (an executable, a .debug file or a .dwo).
 * All offsets are section-relative; addresses are link-time (unrelocated) values.
 */
class DebugObject(
    val sourceName: String,
    val sections: Map<String, ByteArray>,
    val littleEndian: Boolean,
    val addressSize: Int,
    /** SHA-256 of the originating file. */
    val sha256: String,
    val isDwo: Boolean,
    val isExecutableLike: Boolean,
    val preferredImageBase: Long,
) {
    val cus = mutableListOf<CompilationUnit>()
    val linePrograms = mutableListOf<LineProgram>()
    val issues = mutableListOf<DebugIssue>()
    /** Resolved split companion keyed by dwo id (skeleton) / index of split CU. */
    val dwoById = mutableMapOf<ULong, DebugObject>()
    val dwoByPath = mutableMapOf<String, DebugObject>()

    fun section(name: String): ByteArray? = sections[name]
}

data class DebugIssue(
    val severity: Severity,
    val kind: String,
    val message: String,
    val cuOffset: Long? = null,
    val section: String? = null,
) {
    enum class Severity { WARNING, ERROR }
}

class AbbrevDecl(
    val code: ULong,
    val tag: Int,
    val hasChildren: Boolean,
    val attrs: List<Pair<Int, Int>>, // attr, form
    /** Raw bytes following the attr list, e.g. implicit_const value for DW_FORM_implicit_const. */
    val implicitConst: Long? = null,
)

class CompilationUnit(
    val obj: DebugObject,
    val sectionOffset: Long,
    val length: Long,
    val is64BitDwarf: Boolean,
    val version: Int,
    val unitType: Int,
    val addressSize: Int,
    val debugAbbrevOffset: Long,
    val abbrevs: List<AbbrevDecl>,
    /** CU DIE first; a flat list preserving DFS order plus each DIE's depth. */
    val dies: List<Die>,
    val root: Die,
    val issues: MutableList<DebugIssue> = mutableListOf(),
    /** True when structural parsing failed: the CU must not be treated as authoritative. */
    var corrupt: Boolean = false,
    var dwoId: ULong? = null,
    var dwoName: String? = null,
    var isSkeleton: Boolean = false,
    var isSplit: Boolean = false,
    var skeletonCompanion: CompilationUnit? = null,
) {
    /** section-relative offset sizes for references of this CU. */
    val refAddrSize: Int get() = if (is64BitDwarf) 8 else 4

    fun abbrev(code: ULong): AbbrevDecl? = abbrevs.firstOrNull { it.code == code }
}

class Die(
    val cu: CompilationUnit,
    val offset: Long,
    val tag: Int,
    val depth: Int,
    val attrs: Map<Int, AttrValue>,
) {
    val children = mutableListOf<Die>()
    var parent: Die? = null

    fun attr(a: Int): AttrValue? = attrs[a]
}

/** Attribute value as decoded, retaining enough information for later string/address resolution. */
sealed class AttrValue {
    data class Addr(val v: Long) : AttrValue()
    data class Constant(val v: Long) : AttrValue()
    data class UConstant(val v: ULong) : AttrValue()
    data class Str(val v: String) : AttrValue()
    /** .debug_str / .debug_line_str offset (section kind carried alongside). */
    data class StrPtr(val offset: Long, val lineString: Boolean) : AttrValue()
    /** strx*/strxN: index into the CU's string-offsets table. */
    data class StrIndex(val index: ULong) : AttrValue()
    /** addrx* / GNU_addr_index: index into the .debug_addr contribution. */
    data class AddrIndex(val index: ULong) : AttrValue()
    data class Block(val v: ByteArray) : AttrValue()
    /** ref1/2/4/8 within .debug_info, ref_addr (global), ref_sig8 (split type units). */
    data class Ref(val offset: ULong, val global: Boolean, val signature: Boolean = false) : AttrValue()
    /** sec_offset for rnglists/loclists/stmt_list etc. */
    data class SecOffset(val offset: Long) : AttrValue()
    data class RngListIndex(val index: ULong) : AttrValue()
    data object Flag : AttrValue()
}

data class LineFile(val name: String, val directoryIndex: Int, val fullPath: String)

data class LineRow(
    val address: Long,
    val segment: Long,
    val fileIndex: Int,
    val file: LineFile?,
    val line: Int,
    val column: Int,
    val isStatement: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
    /** Human-readable description of what the program did to reach this row. */
    val trace: List<String>,
)

/** One contiguous run of the line program ended by DW_LNE_end_sequence. */
data class LineSequence(
    val program: LineProgram,
    val rows: List<LineRow>,
) {
    val startAddress: Long get() = rows.firstOrNull()?.address ?: 0L
    /** Half-open: address of the end_sequence row is exclusive when it differs from last code row. */
    val endAddress: Long get() = rows.lastOrNull()?.address ?: 0L
    val isEmpty: Boolean get() = rows.size <= 1
}

class LineProgram(
    val cu: CompilationUnit?,
    val sectionOffset: Long,
    val version: Int,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val minimumInstructionLength: Int,
    val maximumOperationsPerInstruction: Int,
    val defaultIsStatement: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val standardOpcodeLengths: IntArray,
    val directories: List<String>,
    val files: List<LineFile>,
    val sequences: List<LineSequence>,
    val issues: MutableList<DebugIssue> = mutableListOf(),
    var corrupt: Boolean = false,
) {
    fun file(index: Int): LineFile? = files.getOrNull(index)
}

/** Resolved address range, half-open [start,end). start==end is a zero-length range. */
data class AddressRange(
    val start: Long,
    val end: Long,
    val kind: RangeKind,
    val source: String,
) {
    val isZeroLength: Boolean get() = start == end
    val width: Long get() = end - start
    fun contains(addr: Long, segment: Long = 0L, rangeSegment: Long = 0L): Boolean =
        segment == rangeSegment && addr >= start && addr < end
}

enum class RangeKind {
    /** DW_AT_low_pc + DW_AT_high_pc constant/address pair. */
    LOW_HIGH_PC,
    /** Entry PC + range (DW_AT_entry_pc). */
    ENTRY_PC,
    /** .debug_ranges (DWARF <=4) offset pair. */
    RANGES_V4,
    /** .debug_rnglists (DWARF 5). */
    RANGES_V5,
}

/** A function-ish DIE with its fully resolved ranges and inline metadata. */
class FunctionDie(
    val die: Die,
    val name: String?,
    val linkageName: String?,
    val ranges: List<AddressRange>,
    val inlineDepth: Int,
    val callFile: String?,
    val callLine: Int,
    val callColumn: Int,
    val abstractRoot: FunctionDie?,
    val cu: CompilationUnit,
) {
    val effectiveName: String? get() = linkageName ?: name ?: abstractRoot?.effectiveName
    val narrowestWidth: Long get() = ranges.filter { !it.isZeroLength }.minOfOrNull { it.width } ?: Long.MAX_VALUE
}
