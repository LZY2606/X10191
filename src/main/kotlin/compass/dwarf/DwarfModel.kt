package compass.dwarf

/** 单个地址范围 [start, end)；zeroLength=true 时为 [start, start]，仅精确匹配 start。 */
data class AddrRange(val start: Long, val end: Long) {
    val length: Long get() = end - start
    val zeroLength: Boolean get() = start == end
    fun contains(addr: Long): Boolean = if (zeroLength) addr == start else addr in start until end
}

/** DWARF 行号表版本。 */
enum class LineTableVersion { DWARF2_4, DWARF5 }

data class LineFileEntry(val id: Long, val name: String, val dirIndex: Long, val md5: String?)

/** line program 的每个已发射 row（end_sequence 的 row 不产生文件行，但标记 sequence 结束地址）。 */
data class LineRow(
    val address: Long,
    val segment: Long,
    val file: String?,
    val fileId: Long?,
    val directory: String?,
    val line: Int,
    val column: Int,
    val endSequence: Boolean,
    val isa: Long,
    val discriminator: Long
)

data class LineSequence(
    val index: Int,
    val startAddress: Long,
    val endAddress: Long,
    val section: Long,
    val rows: List<LineRow>
)

/** 状态机轨迹中的一次变化，供 UI 展示 line program 状态变化。 */
data class StateTrace(
    val step: Int,
    val opcode: String,
    val address: String,
    val file: String?,
    val line: Int,
    val column: Int,
    val emitted: Boolean
)

data class LineProgram(
    val version: Int,
    val tableVersion: LineTableVersion,
    val cuOffset: Long,
    val headerLength: Long,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val directories: List<String>,
    val files: List<LineFileEntry>,
    val sequences: List<LineSequence>,
    val traces: List<StateTrace>,
    val errors: List<String>
)

/** DIE 简化模型：只保留地址解析需要的信息。 */
data class DwarfDie(
    val offset: Long,
    val tag: Int,
    val tagName: String,
    val children: MutableList<DwarfDie> = mutableListOf(),
    /** 关键属性值（name / linkageName / declaration / inline / ranges 等元信息）。 */
    val attrs: Map<Int, AttrValue> = emptyMap(),
    /** 解析出的地址范围（ranges / low_pc+high_pc），可能多个。 */
    var ranges: List<AddrRange> = emptyList(),
    /** abstract_origin / specification / 内联调用相关引用。 */
    val abstractOrigin: Long? = null,
    val specification: Long? = null,
    val callFile: Int? = null,
    val callLine: Int? = null,
    val inlineCode: Int? = null
) {
    fun name(): String? = (attrs[DW_AT_name] as? AttrValue.Str)?.value
    fun linkageName(): String? = (attrs[DW_AT_linkage_name] as? AttrValue.Str)?.value
        ?: (attrs[DW_AT_MIPS_linkage_name] as? AttrValue.Str)?.value
}

sealed class AttrValue {
    data class Str(val value: String) : AttrValue()
    data class Num(val value: Long) : AttrValue()
    data class Addr(val value: Long) : AttrValue()
    data class Ref(val offset: Long) : AttrValue()
    data class SecOffset(val offset: Long) : AttrValue()
    data class RangesRef(val offset: Long) : AttrValue()
    data class UnknownForm(val form: Int) : AttrValue()
}

data class CompilationUnit(
    val offset: Long,
    val version: Int,
    val dwarf64: Boolean,
    val abbrevOffset: Long,
    val addressSize: Int,
    val compDir: String?,
    val name: String?,
    val language: Long?,
    val root: DwarfDie?,
    val lineProgram: LineProgram?,
    val rangeListBase: Long,      // DWARF5: .debug_rnglists 基址（CU header offset 后的 rnglists_base）
    val strOffsetsBase: Long,
    val locListsBase: Long,
    val isSkeleton: Boolean,
    val dwoName: String?,
    val dwoId: Long?,
    val errors: List<String>,
    val warnings: List<String>
)

data class DwarfBundle(
    val elfFileName: String,
    val buildId: String?,
    val sha256: String,
    val units: List<CompilationUnit>,
    /** section 原始字节摘要：name -> (size, sha256, headHex)。 */
    val sectionDigests: Map<String, SectionDigest>,
    val parseErrors: List<String>,
    val hasDwoSections: Boolean
)

data class SectionDigest(val name: String, val size: Int, val sha256: String, val headHex: String, val present: Boolean)

// DW_AT / DW_TAG / DW_FORM 常量（只列用到的）
const val DW_TAG_compile_unit = 0x11
const val DW_TAG_skeleton_unit = 0x4a
const val DW_TAG_subprogram = 0x2e
const val DW_TAG_inlined_subroutine = 0x1d
const val DW_TAG_entry_point = 0x03

const val DW_AT_name = 0x03
const val DW_AT_stmt_list = 0x10
const val DW_AT_low_pc = 0x11
const val DW_AT_high_pc = 0x12
const val DW_AT_ranges = 0x55
const val DW_AT_rnglists_base = 0x74
const val DW_AT_str_offsets_base = 0x72
const val DW_AT_comp_dir = 0x1b
const val DW_AT_language = 0x13
const val DW_AT_abstract_origin = 0x31
const val DW_AT_specification = 0x47
const val DW_AT_call_file = 0x58
const val DW_AT_call_line = 0x59
const val DW_AT_inline = 0x20
const val DW_AT_declaration = 0x3c
const val DW_AT_GNU_dwo_name = 0x2130
const val DW_AT_dwo_name = 0x76
const val DW_AT_GNU_dwo_id = 0x2131
const val DW_AT_GNU_addr_base = 0x2133
const val DW_AT_GNU_ranges_base = 0x2132
const val DW_AT_addr_base = 0x73
const val DW_AT_strx_base_hint = 0x72
const val DW_AT_MIPS_linkage_name = 0x2007
const val DW_AT_linkage_name = 0x6e
const val DW_AT_call_column = 0x57
const val DW_AT_external = 0x3f
const val DW_AT_artificial = 0x34

fun tagName(tag: Int): String = when (tag) {
    DW_TAG_compile_unit -> "DW_TAG_compile_unit"
    DW_TAG_skeleton_unit -> "DW_TAG_skeleton_unit"
    DW_TAG_subprogram -> "DW_TAG_subprogram"
    DW_TAG_inlined_subroutine -> "DW_TAG_inlined_subroutine"
    0x13 -> "DW_TAG_structure_type"
    0x15 -> "DW_TAG_pointer_type"
    0x24 -> "DW_TAG_base_type"
    0x2f -> "DW_TAG_compile_unit?"
    0x00 -> "DW_TAG_null"
    else -> "DW_TAG_0x${tag.toString(16)}"
}
