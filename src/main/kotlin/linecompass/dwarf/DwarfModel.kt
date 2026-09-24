package linecompass.dwarf

/* ---------- DWARF constants (subset used by the parser) ---------- */

object Tag {
    const val COMPILE_UNIT = 0x11
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val LEXICAL_BLOCK = 0x0b
    const val COMPILE_UNIT_SKELETON = 0x11 // same tag as CU; distinguished by DW_AT_dwo_name
}

object Form {
    const val ADDR = 0x01
    const val BLOCK2 = 0x03
    const val BLOCK4 = 0x04
    const val DATA2 = 0x05
    const val DATA4 = 0x06
    const val DATA8 = 0x07
    const val STRING = 0x08
    const val BLOCK = 0x09
    const val BLOCK1 = 0x0a
    const val DATA1 = 0x0b
    const val FLAG = 0x0c
    const val SDATA = 0x0d
    const val STRP = 0x0e
    const val UDATA = 0x0f
    const val REF_ADDR = 0x10
    const val REF1 = 0x11
    const val REF2 = 0x12
    const val REF4 = 0x13
    const val REF8 = 0x14
    const val REF_UDATA = 0x15
    const val INDIRECT = 0x16
    const val SEC_OFFSET = 0x17
    const val EXPRLOC = 0x18
    const val FLAG_PRESENT = 0x19
    const val STRX = 0x1a
    const val ADDRX = 0x1b
    const val REF_SUP4 = 0x1c
    const val STRP_SUP = 0x1d
    const val DATA16 = 0x1e
    const val LINE_STRP = 0x1f
    const val REF_SIG8 = 0x20
    const val IMPLICIT_CONST = 0x21
    const val LOCLISTX = 0x22
    const val RNGLISTX = 0x23
    const val REF_SUP8 = 0x24
    const val STRX1 = 0x25
    const val STRX2 = 0x26
    const val STRX3 = 0x27
    const val STRX4 = 0x28
    const val ADDRX1 = 0x29
    const val ADDRX2 = 0x2a
    const val ADDRX3 = 0x2b
    const val ADDRX4 = 0x2c
    const val LOCLISTX1 = 0x2d
    const val LOCLISTX2 = 0x2e
    const val LOCLISTX3 = 0x2f
    const val LOCLISTX4 = 0x30
    const val RNGLISTX1 = 0x31
    const val RNGLISTX2 = 0x32
    const val RNGLISTX3 = 0x33
    const val RNGLISTX4 = 0x34
}

object Attr {
    const val SIBLING = 0x01
    const val LOCATION = 0x02
    const val NAME = 0x03
    const val BYTE_SIZE = 0x0b
    const val STMT_LIST = 0x10
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val COMP_DIR = 0x1b
    const val RANGES = 0x55
    const val ABSTRACT_ORIGIN = 0x31
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val CALL_COLUMN = 0x57
    const val INLINE = 0x20
    const val DW_AT_rnglists_base = 0x74
    const val STR_OFFSETS_BASE = 0x72
    const val ADDR_BASE = 0x73
    const val DWO_NAME = 0x76
    const val DWO_ID = 0x2133 // GNU: DW_AT_GNU_dwo_id
    const val COMP_DIR_DW5 = 0x1b
    const val NAME_INDEX_VALUE = 0x1f09 // unused placeholder
    const val LINKAGE_NAME = 0x6e
}

object LineContent {
    const val PATH = 1
    const val DIRECTORY_INDEX = 2
    const val TIMESTAMP = 3
    const val SIZE = 4
    const val MD5 = 5
}

object RangeEntry {
    // DWARF 5 rnglist content types
    const val END_OF_LIST = 0
    const val BASE_ADDRESSX = 1
    const val STARTX_ENDX = 2
    const val STARTX_LENGTH = 3
    const val OFFSET_PAIR = 4
    const val BASE_ADDRESS = 5
    const val START_END = 6
    const val START_LENGTH = 7
}

/** A decoded attribute value. Strings resolved lazily where possible. */
data class DwarfValue(val form: Int, val raw: Any?) {
    val asLong: Long? get() = raw as? Long
    val asString: String? get() = raw as? String
    val asBytes: ByteArray? get() = raw as? ByteArray
}

data class DwarfDie(
    val globalOffset: Int,
    val tag: Int,
    val depth: Int,
    val attrs: Map<Int, DwarfValue>,
    val children: MutableList<DwarfDie> = mutableListOf(),
) {
    fun attr(id: Int): DwarfValue? = attrs[id]
    fun walk(visitor: (DwarfDie) -> Unit) {
        visitor(this)
        children.forEach { it.walk(visitor) }
    }
}

/** A source-file entry of a line program header. */
data class LineFile(val name: String, val directoryIndex: Int, val md5: ByteArray? = null) {
    override fun equals(other: Any?): Boolean = other is LineFile && other.name == name && other.directoryIndex == directoryIndex
    override fun hashCode(): Int = 31 * name.hashCode() + directoryIndex
}

/** One materialised row of a line program state machine. */
data class LineRow(
    val address: Long,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val isStmt: Boolean,
    val isa: Int,
    val discriminator: Int,
    val opIndex: Int,
)

/** A single [start,end) run produced by one DW_LNE_end_sequence. */
data class LineSequence(
    val start: Long,
    val end: Long,
    val version: Int,
    val addressSize: Int,
    val segSelectorSize: Int,
    val rows: List<LineRow>,
    val files: List<LineFile>,
    val directories: List<String>,
    val cuName: String,
) {
    fun contains(addr: Long): Boolean = addr in start until end
    val isZeroLength: Boolean get() = start == end
}

/** A [start,end) pair attached to a CU (from ranges/PC attrs or dwo). */
data class AddressRange(
    val start: Long,
    val end: Long,
    val kind: String, // "ranges" | "pc" | "rnglist"
    val zeroLength: Boolean = start == end,
)

/** A function-like scope used in address matching: root subprogram or inline. */
data class FuncScope(
    val die: DwarfDie,
    val start: Long?,
    val end: Long?,
    val ranges: List<AddressRange>,
    val inlineDepth: Int,
    val name: String,
    val isInline: Boolean,
    val callFile: String?,
    val callLine: Int?,
    val abstractName: String?,
    val cuName: String,
    val dwoLinked: Boolean,
) {
    fun contains(addr: Long): Boolean {
        if (start != null && end != null && addr in start until end) return true
        return ranges.any { !it.zeroLength && addr in it.start until it.end }
    }
    fun width(): Long? {
        val vals = buildList {
            if (start != null && end != null) add(end - start)
            addAll(ranges.filter { !it.zeroLength }.map { it.end - it.start })
        }
        return if (vals.isEmpty()) null else vals.filter { it >= 0 }.minOrNull()
    }
}

data class CompilationUnit(
    val sectionOffset: Int,
    val version: Int,
    val isDwarf64: Boolean,
    val unitType: Int,
    val addressSize: Int,
    val debugAbbrevOffset: Long,
    val name: String,
    val compDir: String?,
    val dwoName: String?,
    val dwoId: Long?,
    val root: DwarfDie?,
    val stmtListOffset: Long?,
    val ranges: List<AddressRange>,
    val corrupt: Boolean,
    val warnings: List<String>,
    val sourceFileHint: String?,
) {
    val isSkeleton: Boolean get() = version >= 5 && unitType == 4 || dwoName != null
    val isSplitFull: Boolean get() = version >= 5 && unitType == 5
}

/** Everything decoded from one ELF file (or dwo companion). */
data class ParsedDebugInfo(
    val units: List<CompilationUnit>,
    val sequences: List<LineSequence>,
    val sections: Map<String, SectionSummary>,
    val warnings: List<String>,
    val dwoUnresolved: List<String>,
    val sourceFiles: List<SourceFileEntry>,
)

data class SectionSummary(
    val name: String,
    val offset: Long,
    val size: Long,
    val sha256: String,
    val allocated: Boolean,
    val addr: Long,
)

data class SourceFileEntry(
    val path: String,
    val directory: String?,
    val cuName: String,
    val md5: ByteArray? = null,
)

/** A fully decoded range-list table (DWARF 5 .debug_rnglists header + lists). */
data class RngListTable(
    val offset: Int,
    val version: Int,
    val addressSize: Int,
    val segmentSize: Int,
    val offsetEntrySize: Int,
    val lists: Map<Long, List<AddressRange>>,
)
