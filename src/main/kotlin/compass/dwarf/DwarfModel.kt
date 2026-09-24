package compass.dwarf

/** 属性值统一表示。引用保存全局偏移（在所属 info section 内），表单保留以便解释。 */
sealed class AttrValue {
    data class Address(val value: Long) : AttrValue()
    data class Constant(val value: Long, val signed: Boolean) : AttrValue()
    data class Text(val value: String) : AttrValue()
    data class Reference(val globalOffset: Long) : AttrValue()
    data class SecOffset(val value: Long, val sectionHint: String) : AttrValue()
    data class Signature(val value: Long) : AttrValue()
    data class Bytes(val value: ByteArray) : AttrValue() {
        override fun equals(other: Any?) = other is Bytes && value.contentEquals(other.value)
        override fun hashCode() = value.contentHashCode()
    }
    data class Flag(val value: Boolean) : AttrValue()
    /** 未知 form 已经跳过字节数，标记后调用方决定隔离范围；offset 是属性在 section 中的位置。 */
    data class Unknown(val form: Int, val rawLength: Int, val atOffset: Int) : AttrValue()
}

data class Attribute(val name: Int, val form: Int, val value: AttrValue)

data class Die(
    val offset: Long,
    val tag: Int,
    val attrs: List<Attribute>,
    var parentIndex: Int = -1,
    val childIndices: MutableList<Int> = mutableListOf(),
) {
    fun attr(name: Int): Attribute? = attrs.firstOrNull { it.name == name }
    fun attrValue(name: Int): AttrValue? = attr(name)?.value
    val name: String? get() = (attrValue(DW.AT_NAME) as? AttrValue.Text)?.value
        ?: (attrValue(DW.AT_LINKAGE_NAME) as? AttrValue.Text)?.value
}

data class LineFile(val id: Int, val path: String, val directoryIndex: Int)

data class LineRow(
    val address: Long,
    val selector: Long,
    val file: Int,
    val line: Long,
    val column: Long,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val isStmt: Boolean,
    val isa: Long,
    val discriminator: Long,
    val opIndex: Long,
)

data class LineProgram(
    val version: Int,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val addressSize: Int,
    val selectorSize: Int,
    val directories: List<String>,
    val files: List<LineFile>,
    val rows: List<LineRow>,
    val segmentSelectorSize: Int,
    /** 该程序对应的 .debug_line 节内偏移（CU DW_AT_stmt_list）。 */
    val sectionOffset: Long,
) {
    /** 拆分为多个 end_sequence 序列。 */
    fun sequences(): List<LineSequence> {
        val out = mutableListOf<LineSequence>()
        var startIdx = 0
        for ((i, row) in rows.withIndex()) {
            if (row.endSequence) {
                out.add(LineSequence(rows.subList(startIdx, i + 1).toList(), startIdx))
                startIdx = i + 1
            }
        }
        if (startIdx < rows.size) out.add(LineSequence(rows.subList(startIdx, rows.size).toList(), startIdx))
        return out
    }
}

data class LineSequence(val rows: List<LineRow>, val firstRowIndex: Int) {
    val startAddress: Long get() = rows.firstOrNull()?.address ?: 0L
    val endAddress: Long get() = rows.lastOrNull()?.address ?: 0L
    /** 区间为 [start, end)；单行序列时退化为空区间，仅在精确地址命中时有效。 */
    val length: Long get() = if (rows.size >= 2) endAddress - startAddress else 0L
}

/** 解析出的地址区间（DIE 自带或 rangelist）。selector 用于分段地址；zeroLength 保留用于展示。 */
data class DwarfRange(
    val start: Long,
    val end: Long,
    val selector: Long = 0L,
    val zeroLength: Boolean = false,
)

data class CompUnit(
    val globalOffset: Long,
    val sectionName: String,        // .debug_info / .debug_types
    val version: Int,
    val unitType: Int,
    val addressSize: Int,
    val dwarf64: Boolean,
    val dies: List<Die>,
    val rootIndex: Int,
    val stmtListOffset: Long?,
    val compDir: String?,
    val name: String?,
    val dwoId: Long?,
    val dwoName: String?,
    val isSkeleton: Boolean,
    val isSplit: Boolean,
    /** 每个 DIE 的展平区间（含 low/high_pc 与 range list 解析结果）。 */
    val dieRanges: Map<Long, List<DwarfRange>>,
    /** 与 stmtListOffset 关联的行程序，解析后注入。 */
    var lineProgram: LineProgram? = null,
    /** skeleton <-> split 配对后注入。 */
    var linkedUnitOffset: Long? = null,
    var linkedFromSkeleton: Boolean = false,
    val warnings: MutableList<String> = mutableListOf(),
) {
    val root: Die get() = dies[rootIndex]
    fun dieAt(offset: Long): Die? = dies.firstOrNull { it.offset == offset }
}

/** 解析隔离结果：成功数据 + 该文件级别的告警/损坏说明。 */
data class DwarfParseResult(
    val units: List<CompUnit>,
    val linePrograms: Map<Long, LineProgram>,   // key = stmt_list offset
    val warnings: List<String>,
    val sectionsPresent: Set<String>,
    val sectionsMissing: Set<String>,
)
