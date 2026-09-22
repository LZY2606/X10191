@file:Suppress("ConstPropertyName", "MemberVisibilityCanBePrivate")

package compass.dwarf

/** DWARF tag / attribute / form / line-opcode constants (DWARF 2-5). */
object Tag {
    const val COMPILE_UNIT = 0x11
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val PARTIAL_UNIT = 0x3c
    const val TYPE_UNIT = 0x41
    const val COMPILATION_UNIT_DWO = 0x8001
}

object Attr {
    const val SIBLING = 0x01
    const val NAME = 0x03
    const val STMT_LIST = 0x10
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val FLAGS = 0x13
    const val COMP_DIR = 0x1b
    const val ABSTRACT_ORIGIN = 0x31
    const val SPECIFICATION = 0x47
    const val RANGES = 0x55
    const val STR_OFFSETS_BASE = 0x72
    const val GNU_DWO_NAME = 0x2130
    const val DWO_NAME = 0x76
    const val DW_AT_dwo_id = 0x35 // DW_AT_GNU_dwo_id
    const val DW_AT_rnglists_base = 0x74
    const val STR_OFFSETS_BASE_NONSTANDARD = 0x72
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val CALL_COLUMN = 0x57
    const val EXTERNAL = 0x3f
    const val DECL_FILE = 0x3a
    const val DECL_LINE = 0x3b
    const val LINKAGE_NAME = 0x6e
    const val ARTIFICIAL = 0x34
    const val INLINE = 0x20
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
    const val GNU_ADDR_INDEX = 0x1f01
    const val GNU_STR_INDEX = 0x1f02
    const val GNU_RANGELIST_INDEX = 0x1f03
    const val GNU_REF_DWO = 0x1f24
}

object LineOp {
    const val COPY = 0x01
    const val ADVANCE_PC = 0x02
    const val ADVANCE_LINE = 0x03
    const val SET_FILE = 0x04
    const val SET_COLUMN = 0x05
    const val NEGATE_STMT = 0x06
    const val SET_BASIC_BLOCK = 0x07
    const val CONST_ADD_PC = 0x08
    const val FIXED_ADVANCE_PC = 0x09
    const val SET_PROLOGUE_END = 0x0a
    const val SET_ISA = 0x0b
}

object LineExt {
    const val END_SEQUENCE = 0x01
    const val SET_ADDRESS = 0x02
    const val DEFINE_FILE = 0x03
    const val SET_DISCRIMINATOR = 0x04
    const val SET_IS_STMT = 0x05 // DWARF5
    const val SET_BASIC_BLOCK = 0x06 // DWARF5 (renamed semantic)
    const val SET_PROLOGUE_END = 0x07 // DWARF5
}

object RngListEntryV5 {
    const val END_OF_LIST = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val STARTX_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val START_END = 0x06
    const val START_LENGTH = 0x07
}

object RngListEntryV4 {
    const val END_OF_LIST = 0L
    const val BASE_ADDRESS = 0xffffffffffffffffL.toLong()
}

object Charset { /* placeholder */ }

enum class RangeKind { EXPLICIT_PC, RANGELIST }

data class AddrRange(
    val low: Long,
    val high: Long,
    val kind: RangeKind,
    val index: Int = 0,
) {
    val isZeroLength: Boolean get() = low == high
    fun contains(addr: Long): Boolean = java.lang.Long.compareUnsigned(addr, low) >= 0 &&
        java.lang.Long.compareUnsigned(addr, high) < 0
    val width: Long get() = high - low
}

/** Raw attribute value after decoding; form retained for diagnostics. */
data class AttrValue(val attr: Int, val form: Int, val value: Long?, val str: String? = null, val rawRef: Long? = null) {
    fun asLong(): Long? = value
    fun asString(): String? = str
}

data class DwarfDie(
    val globalIndex: Int,
    val tag: Int,
    val depth: Int,
    val parentIndex: Int,
    val offset: Long,
    val attrs: List<AttrValue>,
    val childrenIndices: MutableList<Int> = mutableListOf(),
) {
    fun attr(name: Int): AttrValue? = attrs.firstOrNull { it.attr == name }
    val name: String? get() = attr(Attr.NAME)?.str ?: attr(Attr.LINKAGE_NAME)?.str
}

data class LineSourceFile(val id: Long, val name: String, val dirIndex: Long, val dir: String?)

data class LineRow(
    val address: Long,
    val file: Long?,
    val fileName: String?,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val endSequence: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val discriminator: Int,
    val opIndex: Long,
)

data class LineSequence(
    val startAddress: Long,
    val endSequenceAddress: Long?,
    val rows: List<LineRow>,
    val orderInUnit: Int,
    val segment: Long = 0L,
)

data class LineProgram(
    val unitIndex: Int,
    val version: Int,
    val offset: Long,
    val files: List<LineSourceFile>,
    val sequences: List<LineSequence>,
    val includeDirs: List<String>,
    val addressSize: Int,
    val segmentSize: Int,
) {
    fun fileOf(id: Long?): LineSourceFile? = id?.let { v -> files.firstOrNull { it.id == v } }
}

data class DwarfUnit(
    val index: Int,
    val offset: Long,
    val version: Int,
    val dwarf64: Boolean,
    val addressSize: Int,
    val unitType: Int?,
    val name: String?,
    val compDir: String?,
    val dies: List<DwarfDie>,
    val rootIndex: Int,
    val ranges: List<ResolvedRange>,
    val lineProgram: LineProgram?,
    val isSkeleton: Boolean,
    val isSplit: Boolean,
    val dwoName: String?,
    val dwoId: Long?,
    val dwoAvailable: Boolean,
    val stmtListOffset: Long?,
    val abbrevOffset: Long,
    val warnings: List<String>,
    val lineTableVersion: Int?,
)

data class ResolvedRange(
    val dieGlobalIndex: Int,
    val unitIndex: Int,
    val low: Long,
    val high: Long,
    val kind: RangeKind,
    val tag: Int,
    val name: String?,
    val depth: Int,
    val rangeIndex: Int,
) {
    fun contains(addr: Long): Boolean = java.lang.Long.compareUnsigned(addr, low) >= 0 &&
        java.lang.Long.compareUnsigned(addr, high) < 0
    val width: Long get() = high - low
    val isZeroLength: Boolean get() = low == high
}

data class DwarfProgram(
    val units: List<DwarfUnit>,
    val allRanges: List<ResolvedRange>,
    val warnings: List<String>,
    val hasDebugTypes: Boolean,
)
