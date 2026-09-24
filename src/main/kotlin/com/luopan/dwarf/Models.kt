package com.luopan.dwarf

/** 属性值（强类型）。未知 form 不会产生此表之外的值。 */
sealed class AttrVal {
    data class Addr(val v: Long) : AttrVal()
    data class Const(val v: Long) : AttrVal()
    data class Str(val v: String) : AttrVal()
    data class Strp(val offset: Int) : AttrVal()
    data class LineStrp(val offset: Int) : AttrVal()
    data class Strx(val index: Int) : AttrVal()
    data class Addrx(val index: Int) : AttrVal()
    data class Ref(val offset: Int, val global: Boolean) : AttrVal()
    data class SecOffset(val offset: Long) : AttrVal()
    data class Expr(val bytes: ByteArray) : AttrVal()
    data class Flag(val v: Boolean) : AttrVal()
    data class Sig(val v: Long) : AttrVal()
}

/** 一段地址范围（可能零长度）。segment 用于分段地址。 */
data class AddrRange(val start: Long, val end: Long, val segment: Long = 0L) {
    val length: Long get() = end - start
    fun contains(addr: Long): Boolean = addr in start until end
}

/** 一个已解析的 compilation unit / type unit。 */
class CompileUnit(
    val name: String,
    val compDir: String?,
    val version: Int,
    val unitType: String,
    val dwarf64: Boolean,
    val addressSize: Int,
    val offsetSize: Int,
    val sectionOffset: Int,
    val unitLength: Int,
    val abbrevOffset: Int,
    val cuBase: Long,
    val stmtList: Long?,
    val dwoId: Long?,
    val dwoName: String?,
    val isSkeleton: Boolean,
    val isSplit: Boolean,
    val strOffsetsBase: Long?,
    val addrBase: Long?,
    val dies: List<Die>,
    val ranges: List<DieRange>,
    val language: Long?,
    val producer: String?,
)

/** DIE 的扁平节点，parent 为父在 dies 列表中的下标（根 CU DIE 的 parent = -1）。 */
class Die(
    val index: Int,
    val offset: Int,
    val tag: Int,
    val tagName: String,
    val parent: Int,
    val depth: Int,
    val attrs: Map<Int, AttrVal>,
) {
    fun attr(name: Int): AttrVal? = attrs[name]
}

/** DIE 经 DW_AT_ranges / low_pc+high_pc 解析后的范围。dieIndex 指向 CU.dies。 */
class DieRange(
    val dieIndex: Int,
    val range: AddrRange,
    val source: String, // "ranges", "low_high", "low_const"
)

class LineFile(val dir: String, val name: String) {
    val path: String get() = if (dir.isEmpty()) name else "$dir/$name"
}

/** line program 执行产生的一行（状态机快照）。 */
class LineRow(
    val address: Long,
    val segment: Long,
    val file: LineFile?,
    val line: Int,
    val column: Int,
    val endSequence: Boolean,
    val isStmt: Boolean,
    val isa: Int,
    val discriminator: Int,
    val opIndex: Int,
)

/** 一个 line sequence（同一 end_sequence 边界内的行集合）。 */
class LineSequence(
    val cuName: String,
    val cuOffset: Int,
    val version: Int,
    val segSelectorSize: Int,
    val addressSize: Int,
    val startAddress: Long,
    val endAddress: Long,
    val rows: List<LineRow>,
)

/** 内联调用链的一帧，由内向外排序（0 = 最深的内联点）。 */
class InlineFrame(
    val depth: Int,
    val functionName: String,
    val file: String?,
    val line: Int?,
    val dieOffset: Int,
    val abstractOriginOffset: Int?,
    val inlineCode: Long?,
)

/** section 级别诊断。severity 决定结论可信度。 */
data class Diagnostic(
    val severity: String, // ERROR | WARNING
    val scope: String,    // file | section | cu | line | ranges
    val message: String,
    val cuName: String? = null,
)

/** section 地图条目（供浏览器展示）。 */
class SectionMapEntry(
    val name: String, val type: Int, val addr: Long, val offset: Long,
    val size: Long, val flags: Long,
)
