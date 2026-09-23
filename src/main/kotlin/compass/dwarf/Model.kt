package compass.dwarf

import compass.elf.ByteReader

/** 解析过程中产生的非致命（或隔离后）提示，前端用于标注哪些结论仍然可信。 */
data class ParseNotice(
    val severity: String, // "warn" | "error"
    val section: String,
    val offset: Long,
    val message: String,
)

/** 带“段选择子 + 偏移”的地址；selector!=0 用于分段地址空间。 */
data class SegAddr(val selector: Long, val offset: Long) : Comparable<SegAddr> {
    override fun compareTo(other: SegAddr): Int {
        val c = selector.compareTo(other.selector)
        return if (c != 0) c else offset.compareTo(other.offset)
    }
    companion object {
        fun flat(offset: Long) = SegAddr(0L, offset)
    }
}

/** 地址区间 [start, end)，zeroLen 标记零长度范围（合法但无法包含任何地址）。 */
data class AddrRange(
    val start: SegAddr,
    val end: SegAddr,
    val zeroLen: Boolean = false,
) {
    fun contains(a: SegAddr): Boolean =
        !zeroLen && start.selector == a.selector && a.offset >= start.offset && a.offset < end.offset
    fun width(): Long = end.offset - start.offset
}

sealed class FormValue {
    data class Addr(val a: SegAddr) : FormValue()
    data class Number(val v: Long) : FormValue()
    data class Str(val text: String) : FormValue()
    data class Ref(val offset: Long, val inSplit: Boolean = false) : FormValue()
    data class Sig(val signature: Long) : FormValue()
    data class Block(val bytes: ByteArray) : FormValue() {
        override fun equals(other: Any?) = other is Block && bytes.contentEquals(other.bytes)
        override fun hashCode() = bytes.contentHashCode()
    }
    /** DW_FORM_* 无法解码（如未知 form / 缺 section），携带原始 form 编码。 */
    data class Problem(val form: Int, val reason: String) : FormValue()
}

data class DieAttr(val name: Int, val form: Int, val value: FormValue)

data class DieNode(
    val cuIndex: Int,
    val globalOffset: Long,
    val tag: Int,
    val depth: Int,
    val parentGlobalOffset: Long?,
    val attrs: List<DieAttr>,
) {
    fun attr(name: Int): DieAttr? = attrs.firstOrNull { it.name == name }
    fun numeric(name: Int): Long? = (attr(name)?.value as? FormValue.Number)?.v
    fun string(name: Int): String? = (attr(name)?.value as? FormValue.Str)?.text
    fun addr(name: Int): SegAddr? = (attr(name)?.value as? FormValue.Addr)?.a
}

data class FileEntry(val id: Int, val path: String, val directory: String?, val md5: String?)

data class RowState(
    val address: SegAddr,
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
)

/** line program 中的一次状态变迁（供前端逐步回放）。 */
data class LineEvent(
    val index: Int,
    val pcOffset: Int,
    val opcode: Int,
    val opcodeName: String,
    val operandSummary: String,
    val emitted: Boolean,
    val state: RowState,
)

data class LineSequence(
    val index: Int,
    val rows: List<RowState>,
    val events: List<LineEvent>,
)

enum class UnitKind { COMPILE, SKELETON, SPLIT_COMPILE, PARTIAL, TYPE, OTHER }

data class CompileUnit(
    val index: Int,
    val fileSha: String,
    val sectionOffset: Long,
    val length: Long,
    val version: Int,
    val is64BitDwarf: Boolean,
    val dwarfAddressSize: Int,
    val unitKind: UnitKind,
    val abbrevOffset: Long,
    val dwoId: Long?,
    val compName: String?,
    val compDir: String?,
    val stmtListOffset: Long?,
    val strOffsetsBase: Long,
    val addrBase: Long,
    val rnglistsBase: Long,
    val dies: List<DieNode>,
    val sequences: List<LineSequence>,
    val files: List<FileEntry>,
    val notices: List<ParseNotice>,
) {
    /** 所有 DIE 中显式声明的范围（含零长度），不做去重，保留全部候选。 */
    val diesByOffset: Map<Long, DieNode> by lazy { dies.associateBy { it.globalOffset } }
}
