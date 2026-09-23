package compass.dwarf

/** A raw attribute value. Indexed forms are resolved at query time (addr/rng/str bases). */
sealed class AttrValue {
    data class Addr(val v: Long) : AttrValue()
    data class Num(val v: Long) : AttrValue()
    data class Str(val v: String) : AttrValue()
    data class Bytes(val v: ByteArray) : AttrValue()
    /** Global (per-section) offset reference (DW_FORM_ref_addr). */
    data class RefGlobal(val v: Long) : AttrValue()
    /** CU-relative reference; combined with cuOffset to get a global offset. */
    data class RefLocal(val v: Long) : AttrValue()
    /** Unresolved indexed value (addrx/rnglistx/strx). Kept raw for context resolution. */
    data class Indexed(val kind: IndexKind, val idx: Long) : AttrValue()
    data class SecOffset(val v: Long) : AttrValue()
    data object Flag : AttrValue()

    enum class IndexKind { ADDRX, RNGLISTX, STRX }
}

data class DAttribute(val name: Int, val form: Int, val value: AttrValue)

data class DieNode(
    val offset: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val attributes: List<DAttribute>,
    val parentOffset: Long,
    val depth: Int,
    val cuId: Int,
) {
    fun attr(name: Int): DAttribute? = attributes.firstOrNull { it.name == name }
    fun name(): String? = (attr(Attr.NAME)?.value as? AttrValue.Str)?.v
}

data class LineFile(val id: Int, val name: String, val dir: String, val mtime: Long, val size: Long)

data class LineRow(
    val address: Long,
    val segment: Long,
    val file: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val endSequence: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
    val opIndex: Int,
)

data class LineSequence(
    val startAddress: Long,
    val endAddress: Long,
    val segment: Long,
    val rows: List<LineRow>,
    /** First emitted (lowest-address) row's file/line, for quick display. */
    val startFile: Int,
    val startLine: Int,
)

data class LineProgram(
    val cuId: Int,
    val sectionOffset: Long,
    val version: Int,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val files: List<LineFile>,
    val directories: List<String>,
    val sequences: List<LineSequence>,
    /** One copy of rows flattened in program order, for the UI state view. */
    val orderedRows: List<LineRow>,
)

/** A [start, end) pair; zero-length pairs are allowed and retained. */
data class AddressRange(
    val start: Long,
    val end: Long,
    val segment: Long = 0,
    val dieOffset: Long = 0,
    val cuId: Int = 0,
    /** true when sourced from a dwo CU's DW_AT_ranges via skeleton addr base. */
    val fromDwo: Boolean = false,
) {
    val length: Long get() = end - start
    fun contains(addr: Long): Boolean = addr in start until end
}

data class CompileUnit(
    val id: Int,
    val sectionOffset: Long,
    val length: Long,
    val version: Int,
    val dwarf64: Boolean,
    val addressSize: Int,
    val unitType: Int,
    val debugAbbrevOffset: Long,
    val name: String?,
    val compDir: String?,
    val compName: String?,
    val lowPc: Long?,
    val stmtListOffset: Long?,
    val dwoName: String?,
    val dwoId: Long?,
    val isSkeleton: Boolean,
    val dwoVersionId: Int?,
    val dies: List<DieNode>,
    /** Ranges resolved from DW_AT_low_pc/high_pc and range lists (skeleton side). */
    val ranges: List<AddressRange>,
    val lineProgram: LineProgram?,
    val warnings: List<String>,
    /** Offset where DIE parsing stopped due to corruption (== end when clean). */
    val parsedUntil: Long,
    val strOffsetsBase: Long?,
    val addrBase: Long?,
    val rnglistsBase: Long,
    /** Index of the CU in .debug_info when resolving global refs. */
    val siblingVersionId: Int? = null,
) {
    fun containsOffset(off: Long): Boolean =
        off in sectionOffset until sectionOffset + length
}

data class ParsedSections(
    val cus: List<CompileUnit>,
    /** CU that owns each DIE global offset. */
    val dieByOffset: Map<Long, DieNode>,
    val cuByOffset: Map<Long, CompileUnit>,
    val parseErrors: List<String>,
    val sectionSummaries: Map<String, SectionSummary>,
)

data class SectionSummary(
    val name: String,
    val type: Long,
    val address: Long,
    val fileOffset: Long,
    val size: Long,
    val sha256: String?,
    val note: String?,
)
