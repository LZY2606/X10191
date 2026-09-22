package compass.dwarf

/** section 字节提取结果（原始字节摘要与视图）。 */
data class SectionBlob(val name: String, val addr: Long, val bytes: ByteArray) {
    val size: Int get() = bytes.size
    fun view(): ByteView = ByteView(bytes)
}

/** 单个地址区间，半开 [start, end)；length 可为 0（零长度范围必须保留）。 */
data class AddrRange(val start: Long, val end: Long, val sectionIndex: Int? = null) {
    val length: Long get() = end - start
    fun contains(addr: Long): Boolean = addr in start until end
    /** 零长度范围只在精确等于 start 时匹配（DWARF 对空范围的惯例）。 */
    fun matchesZeroLen(addr: Long): Boolean = start == end && addr == start
}

/** 源文件记录（line program file entry）。 */
data class LineFile(val id: Int, val name: String, val dirIndex: Int, val dir: String, val md5: String? = null)

/** line program 产生的一条行表记录。 */
data class LineRow(
    val address: Long,
    val opIndex: Int,
    val file: LineFile?,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
)

/** line program 执行轨迹中的一次状态变化（浏览器"状态机"视图用）。 */
data class LineStep(
    val seq: Int,
    val pc: Long,
    val opIndex: Int,
    val fileIdx: Int?,
    val line: Int?,
    val column: Int?,
    val isStmt: Boolean,
    val emitted: Boolean,
    val endSequence: Boolean,
    val opcodeDesc: String,
)

/** 一个 line sequence：从 set_address/初始地址到 end_sequence 的行记录段。 */
data class LineSequence(
    val index: Int,
    val startAddress: Long,
    val endAddress: Long,
    val segment: Long?,
    val rows: List<LineRow>,
    val dwarfVersion: Int,
)

data class LineProgram(
    val cuOffset: Long?,
    val offset: Long,
    val dwarfVersion: Int,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val compDir: String?,
    val files: List<LineFile>,
    val directories: List<String>,
    val sequences: List<LineSequence>,
    val steps: List<LineStep>,
    val warnings: List<String>,
) {
    fun fileAt(idx: Int): LineFile? = files.getOrNull(idx)
}

/** 属性值：保留我们关心的几类；未知/跳过的用 RawBytes 隔离。 */
sealed class AttrValue {
    data class Num(val v: Long) : AttrValue()
    data class Str(val v: String) : AttrValue()
    data class Bytes(val v: ByteArray) : AttrValue() {
        override fun equals(other: Any?) = other is Bytes && v.contentEquals(other.v)
        override fun hashCode() = v.contentHashCode()
    }
    data class UnknownForm(val form: Long) : AttrValue()
}

data class DieAttribute(val attr: Long, val form: Long, val value: AttrValue)

/** 解析后的 DIE（树形结构，递归深度受解析器限制）。 */
class DieNode(
    val offset: Long,
    val tag: Long,
    val children: MutableList<DieNode> = mutableListOf(),
    val attributes: MutableList<DieAttribute> = mutableListOf(),
    var parent: DieNode? = null,
) {
    fun attr(a: Long): DieAttribute? = attributes.firstOrNull { it.attr == a }
    fun num(a: Long): Long? = (attr(a)?.value as? AttrValue.Num)?.v
    fun str(a: Long): String? = (attr(a)?.value as? AttrValue.Str)?.v
    fun walk(depthLimit: Int = 64): Sequence<DieNode> = sequence {
        val stack = ArrayDeque<Pair<DieNode, Int>>()
        stack.addLast(this@DieNode to 0)
        while (stack.isNotEmpty()) {
            val (node, depth) = stack.removeLast()
            yield(node)
            if (depth < depthLimit) {
                node.children.asReversed().forEach { stack.addLast(it to depth + 1) }
            }
        }
    }
}

/** 解析后的 compilation unit（或 type unit）。 */
data class CompilationUnit(
    val headerOffset: Long,
    val dwarfVersion: Int,
    val unitType: Int?,
    val addressSize: Int,
    val debugAbbrevOffset: Long,
    val dieOffset: Long,
    val nextOffset: Long,
    val is64BitDwarf: Boolean,
    val root: DieNode?,
    val dwoId: Long?,
    val name: String?,
    val compDir: String?,
    val producer: String?,
    val ranges: List<AddrRange>,
    val warnings: List<String>,
    /** DWARF5 .debug_addr base 索引（DW_AT_addr_base 给出的首个索引，一般 0）。 */
    val addrBase: Long,
    val rnglistsBase: Long?,
    val dwoName: String?,
    val stmtList: Long?,
    val sourceLanguage: Long?,
)

/** 内联调用链中的一帧。 */
data class InlineFrame(
    val depth: Int,
    val dieOffset: Long,
    val name: String,
    val tag: Long,
    val declFile: String?,
    val declLine: Int?,
    val callFile: String?,
    val callLine: Int?,
    val callColumn: Int?,
    val range: AddrRange?,
    val abstract: Boolean,
)

/** 地址命中的一个候选（函数/DIE + 行表位置）。所有合法候选都保留。 */
data class AddressCandidate(
    val rank: Int,
    val primary: Boolean,
    val cuName: String?,
    val cuHeaderOffset: Long,
    val dwarfVersion: Int,
    val lineTableVersion: Int,
    val lineFile: String?,
    val line: Int?,
    val column: Int?,
    val endSequenceHit: Boolean,
    val sequenceStart: Long,
    val sequenceEnd: Long,
    val sequenceIndex: Int,
    val symbolName: String?,
    val dieOffset: Long,
    val dieRange: AddrRange?,
    val rangeWidth: Long,
    val inlineDepth: Int,
    val inlineChain: List<InlineFrame>,
    val segment: Long?,
    val matchedZeroLenRange: Boolean,
    val explicitPriority: Int,
)

/** 一次地址查询的完整解释。 */
data class AddressExplanation(
    val inputAddress: Long,
    val moduleName: String?,
    val loadBias: Long?,
    val runtimeBase: Long?,
    val relativeAddress: Long,
    val candidates: List<AddressCandidate>,
    val confidence: String,
    val notes: List<String>,
)

/** 模块加载快照（固定一次崩溃的重定位代次）。 */
data class ModuleSnapshot(
    val id: Long?,
    val batchId: Long?,
    val moduleName: String,
    val debugFileVersion: Long,
    val runtimeBase: Long?,
    val loadBias: Long?,
    val preferredBase: Long?,
    val segmentSelector: Long?,
    val createdAt: String,
)
