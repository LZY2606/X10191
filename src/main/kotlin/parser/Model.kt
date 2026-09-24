package parser

/** Raw/normalized address range, half-open [start, end). Zero-length ranges are kept. */
data class AddrRange(val start: Long, val end: Long, val section: Long = 0) {
    val length: Long get() = end - start
    val zeroLength: Boolean get() = end == start
    fun contains(addr: Long): Boolean = addr in start until end
}

data class LineFile(val id: Int, val path: String, val dirIndex: Int = 0, val md5: String? = null)

data class LineRow(
    val address: Long,
    val file: Int,
    val line: Int,
    val column: Int,
    val endSequence: Boolean,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
    val opIndex: Int,
)

data class LineSequence(
    val index: Int,
    val low: Long,
    val high: Long,          // end_sequence address is exclusive
    val version: Int,
    val rows: List<LineRow>,
    val segmentSelectorSize: Int,
)

data class Attribute(val name: Int, val form: Int, val rawValue: Long, val strValue: String?, val block: ByteArray?) {
    override fun equals(other: Any?) = other is Attribute && other.name == name
    override fun hashCode() = name
}

data class Die(
    val offset: Long,
    val tag: Int,
    val children: Boolean,
    val attrs: List<Attribute>,
    val depth: Int,
    val childDIEs: MutableList<Die> = mutableListOf(),
    var parent: Die? = null,
) {
    fun attr(name: Int): Attribute? = attrs.firstOrNull { it.name == name }
    fun name(): String? = attr(DW.AT_NAME)?.strValue
        ?: attr(DW.AT_LINKAGE_NAME)?.strValue
        ?: attr(DW.AT_DWO_NAME)?.strValue
        ?: attr(DW.AT_GNU_DWO_NAME)?.strValue
}

data class CompilationUnit(
    val headerOffset: Long,
    val firstDieOffset: Long,
    val version: Int,            // 2,3,4,5
    val unitType: Int,           // DW_UT_*
    val addressSize: Int,
    val debugAbbrevOffset: Long,
    val name: String,
    val compDir: String?,
    val producer: String?,
    val language: Long?,
    val dwoName: String?,
    val stmtList: Long?,
    val strOffsetsBase: Long?,
    val addrBase: Long?,
    val rngListsBase: Long?,
    val locListsBase: Long?,
    val rangeLists: List<AddrRange>,
    val dies: List<Die>,
    val rootDie: Die?,
    val skeletonDwo: String?,
    val warnings: List<String>,
)

/** Section byte summary persisted per import. */
data class SectionSummary(
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val sha256: String,
)

data class ParseReport(
    val elf: ElfFile,
    val sections: List<SectionSummary>,
    val cus: List<CompilationUnit>,
    val sequences: List<ParsedSequence>,
    val warnings: List<String>,
    val tableVersions: List<Int>,
    val hasDwoReference: Boolean,
) {
    data class ParsedSequence(
        val cuHeaderOffset: Long,
        val cuName: String,
        val stmtList: Long,
        val sequence: LineSequence,
        val files: List<LineFile>,
        val dirs: List<String>,
        val addressSize: Int,
        val version: Int,
    )
}
