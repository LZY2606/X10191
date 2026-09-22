package compass.dwarf

data class RangeEntry(val begin: Long, val end: Long) {
    val width: Long get() = end - begin
    fun contains(addr: Long) = addr in begin until end
    val isZeroLength: Boolean get() = begin == end
}

data class LineRow(
    val sequence: Int,
    val address: Long,
    val endAddress: Long,
    val fileIndex: Int,
    val file: String,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Long,
    val discriminator: Long,
) {
    val isZeroLength: Boolean get() = address == endAddress
    fun contains(addr: Long) = !endSequence && !isZeroLength && addr in address until endAddress
}

data class InlineEntry(
    val dieOffset: Long,
    val parentIndex: Int, // index into cu.inlines, -1 = root
    val depth: Int,
    val name: String,
    val callFile: String?,
    val callLine: Long?,
    val ranges: List<RangeEntry>,
)

data class DieAttr(
    val attr: Int,
    val form: Int,
    val value: AttrValue,
)

sealed class AttrValue {
    data class Addr(val v: Long) : AttrValue()
    data class Data(val v: Long) : AttrValue()
    data class SData(val v: Long) : AttrValue()
    data class Str(val s: String) : AttrValue()
    data class StrRef(val offset: Long, val table: String) : AttrValue() // table: str / line_str / strx / sup
    data class Flag(val v: Boolean) : AttrValue()
    data class Ref(val offset: Long) : AttrValue() // CU-relative
    data class SecOffset(val v: Long) : AttrValue()
    data class Block(val bytes: ByteArray) : AttrValue()
    data class Indexed(val kind: String, val index: Long) : AttrValue() // addrx / strx / rnglistx / loclistx
    data object Unresolved : AttrValue()
}

data class Die(
    val offset: Long, // absolute offset in .debug_info
    val depth: Int,
    val tag: Int,
    val attrs: List<DieAttr>,
    val children: List<Die>,
) {
    fun firstAttr(attr: Int): AttrValue? = attrs.firstOrNull { it.attr == attr }?.value
}

data class CompilationUnit(
    val offset: Long,
    val version: Int,
    val unitType: Int,
    val addrSize: Int,
    val dwarf64: Boolean,
    val name: String?,
    val compDir: String?,
    val lowPc: Long?,
    val ranges: List<RangeEntry>,
    val stmtListOffset: Long?,
    val lineVersion: Int?,
    val rnglistsVersion: Int?,
    val lineRows: List<LineRow>,
    val inlines: List<InlineEntry>,
    val dwoName: String?,
    val dwoMissing: Boolean,
    val truncated: Boolean,
    val issues: List<String>,
) {
    val contentKey: String
        get() = "%x:%s:%s".format(offset, name ?: "", ranges.joinToString(",") { "%x-%x".format(it.begin, it.end) })
}

data class ParsedDwarf(
    val units: List<CompilationUnit>,
    val issues: List<String>,
)

/** Limits guarding recursion, length and reference jumps. */
data class DwarfLimits(
    val maxDieDepth: Int = 64,
    val maxDiesPerUnit: Int = 200_000,
    val maxAbbrevAttrs: Int = 512,
    val maxAbbrevs: Int = 65_535,
    val maxLineRows: Int = 2_000_000,
    val maxRanges: Int = 1_000_000,
    val maxIndirectDepth: Int = 1,
)
