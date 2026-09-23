package compass.dwarf

/** A half-open address range [start, end). Zero-length ranges are kept. */
data class AddrRange(val start: Long, val end: Long, val source: String = "") : Comparable<AddrRange> {
    val length: Long get() = end - start
    val isZeroLength: Boolean get() = start == end
    fun contains(addr: Long): Boolean = addr in start until end
    override fun compareTo(other: AddrRange): Int =
        compareValuesBy(this, other, AddrRange::start, AddrRange::end, AddrRange::source)
}

/** Raw attribute value plus enough context to resolve strings/refs later. */
data class Attribute(val name: Int, val form: Int, val raw: Any?) {
    fun asLong(): Long? = when (raw) {
        is Long -> raw; is Int -> raw.toLong(); is Boolean -> if (raw) 1L else 0L
        is ByteArray -> raw.size.toLong(); else -> null
    }
}

/** A parsed debugging information entry. */
data class Die(
    val offset: Long,
    val tag: Int,
    val children: Boolean,
    val attrs: List<Attribute>,
    val cuIndex: Int,
    var parent: Die? = null,
) {
    val childrenList: MutableList<Die> = mutableListOf()
    fun attr(name: Int): Attribute? = attrs.firstOrNull { it.name == name }
    fun name(): String? = attr(DW.AT_name)?.raw as? String
    fun depth(): Int = generateSequence(parent) { it.parent }.count()
}

data class LineFile(val id: Int, val path: String, val dir: String = "") {
    val display: String get() = if (dir.isNotEmpty() && !path.startsWith('/')) "$dir/$path" else path
}

/** One emitted row of a line number program. */
data class LineRow(
    val address: Long,
    val file: LineFile?,
    val line: Int,
    val column: Int,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val isStatement: Boolean,
    val isa: Int,
    val discriminator: Int,
)

/** A maximal run of rows ending with DW_LNE_end_sequence. */
data class LineSequence(
    val cuIndex: Int,
    val rows: List<LineRow>,
) {
    val startAddress: Long get() = rows.firstOrNull()?.address ?: 0L
    val endAddress: Long get() = rows.lastOrNull()?.address ?: 0L
    fun covers(addr: Long): Boolean {
        if (rows.isEmpty()) return false
        val lo = rows.minOf { it.address }
        val hi = rows.maxOf { it.address }
        return addr in lo..hi
    }
}

data class CompilationUnit(
    val index: Int,
    val offset: Long,
    val length: Long,
    val version: Int,
    val dwarfVersion: String,         // "DWARF 4" / "DWARF 5"
    val unitType: Int,
    val is64BitDwarf: Boolean,
    val addressSize: Int,
    val debugAbbrevOffset: Long,
    val root: Die?,
    val name: String?,
    val compDir: String?,
    val dwoName: String?,
    val dwoId: Long?,
    val lowPc: Long?,
    val ranges: List<AddrRange>,
    val stmtListOffset: Long?,
    val sequences: List<LineSequence>,
    val addrBase: Long,
    val strOffsetsBase: Long,
    val rangesBase: Long,
    val warnings: List<String>,
    val parseError: String?,
    val skeleton: Boolean,
    val split: Boolean,
    val dies: List<Die>,
) {
    /** Narrowest containing range, for candidate ranking; null if only zero-length. */
    fun containingRange(addr: Long): AddrRange? =
        ranges.filter { it.contains(addr) }.minWithOrNull(compareBy<AddrRange> { it.length }.thenBy { it.start })
}

/** A section the importer saw, with provenance and byte digest. */
data class SectionInfo(
    val name: String,
    val size: Long,
    val fileOffset: Long,
    val vma: Long,
    val sha256: String,
    val present: Boolean,
)

/** One frame of an inlined call chain, innermost-last. */
data class InlineFrame(
    val dieOffset: Long,
    val name: String,
    val file: String?,
    val line: Int?,
    val column: Int?,
    val depth: Int,
    val range: AddrRange?,
)

/** A single address resolution with every legal interpretation kept. */
data class Resolution(
    val runtimeAddress: Long,
    val fileRelativeAddress: Long,
    val loadBias: Long?,
    val moduleName: String?,
    val generationId: Long?,
    val candidates: List<Candidate>,
    val diagnostics: List<String>,
    val confident: Boolean,
)

/** One legal interpretation (CU/sequence/inline chain) of an address. */
data class Candidate(
    val fileId: Long,
    val versionId: Long,
    val fileName: String?,
    val cuIndex: Int,
    val cuName: String?,
    val dwarfVersion: String,
    val sourceFile: String?,
    val line: Int?,
    val column: Int?,
    val sequenceStart: Long,
    val sequenceEnd: Long,
    val inlineChain: List<InlineFrame>,
    val containingRange: AddrRange?,
    val matchBasis: String,
    val rankNarrowness: Long,
    val rankInlineDepth: Int,
    val rankExplicit: Int,
    val trusted: Boolean,
    val notes: List<String>,
)
