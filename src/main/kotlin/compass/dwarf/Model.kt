package compass.dwarf

/** 分段地址：segment 为 0 表示普通平坦地址。 */
data class SegAddr(val segment: Long, val offset: Long) : Comparable<SegAddr> {
    override fun compareTo(other: SegAddr): Int {
        if (segment != other.segment) return segment.compareTo(other.segment)
        return offset.compareTo(other.offset)
    }
    override fun toString(): String = if (segment == 0L) "0x%x".format(offset) else "0x%x:0x%x".format(segment, offset)
}

/** [start, end) 半开区间；zeroLength 时 end==start，表示精确落在该点。 */
data class AddrRange(val start: SegAddr, val end: SegAddr) {
    val zeroLength: Boolean get() = start == end
    fun contains(a: SegAddr): Boolean = when {
        zeroLength -> a == start
        else -> a.segment == start.segment && a.offset >= start.offset && a.offset < end.offset
    }
    val length: Long get() = end.offset - start.offset
}

data class ByteSummary(val size: Int, val sha256: String, val head16: String, val tail16: String) {
    companion object {
        private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
        fun of(bytes: ByteArray): ByteSummary = ByteSummary(
            bytes.size,
            java.security.MessageDigest.getInstance("SHA-256").digest(bytes).let(::hex),
            hex(bytes.copyOfRange(0, minOf(16, bytes.size))),
            hex(bytes.copyOfRange(maxOf(0, bytes.size - 16), bytes.size))
        )
    }
}

data class SectionInfo(
    val name: String,
    val fileOffset: Long,
    val address: Long,
    val size: Long,
    val link: Int,
    val infoLink: Int,
    val entsize: Long,
    val summary: ByteSummary?
) {
    /** sh_addr 非 0 的分配段，其 section 内偏移等于虚拟地址相对偏移。 */
    val allocated: Boolean get() = address != 0L
}

data class SegmentInfo(val type: Long, val offset: Long, val vaddr: Long, val fileSize: Long, val memSize: Long, val flags: Long)

enum class RelocKind { NONE, ABSOLUTE, RELATIVE, UNKNOWN }

data class Relocation(val offset: Long, val kind: RelocKind, val addend: Long, val symbolValue: Long, val type: Long)

data class ElfImage(
    val elfClass: Int,                 // 1 或 2
    val littleEndian: Boolean,
    val machine: Int,
    val isSharedObject: Boolean,
    val entryVaddr: Long,
    val sections: List<SectionInfo>,
    val segments: List<SegmentInfo>,
    val relocations: Map<String, List<Relocation>>,
    val sectionBytes: Map<String, ByteArray>,
    val issues: List<ParseIssue>
) {
    fun section(name: String): ByteArray? = sectionBytes[name]
    fun sectionInfo(name: String): SectionInfo? = sections.firstOrNull { it.name == name }
}

data class ParseIssue(val severity: Severity, val code: String, val message: String, val section: String = "", val offset: Long = -1) {
    enum class Severity { ERROR, WARNING, NOTICE }
}

sealed class AttrValue {
    data class Address(val value: Long) : AttrValue()
    data class Uconstant(val value: Long, val form: Int) : AttrValue()
    data class Sconstant(val value: Long) : AttrValue()
    data class Str(val value: String) : AttrValue()
    data class Flag(val value: Boolean) : AttrValue()
    data class Bytes(val value: ByteArray) : AttrValue()
    data class Ref(val unitOffset: Long, val form: Int) : AttrValue()
    data class SecOff(val offset: Long, val form: Int) : AttrValue()
    /** 无法识别的 form：保留 form 编号与已安全跳过的字节数，不猜测含义。 */
    data class Unknown(val form: Int, val skipped: Int) : AttrValue()

    fun asLong(): Long? = when (this) {
        is Address -> value
        is Uconstant -> value
        is Sconstant -> value
        is Flag -> if (value) 1L else 0L
        else -> null
    }
    fun asString(): String? = (this as? Str)?.value
}

data class Die(
    val offset: Long,
    val tag: Int,
    val attrs: Map<Int, AttrValue>,
    val children: MutableList<Die> = mutableListOf(),
    var parent: Die? = null
) {
    fun attr(a: Int): AttrValue? = attrs[a]
    fun walk(depth: Int = 0, visitor: (Die, Int) -> Unit) {
        visitor(this, depth)
        children.forEach { it.walk(depth + 1, visitor) }
    }
}

data class LineFile(val id: Int, val path: String, val dirIndex: Int)

data class LineRow(
    val sequence: Int,
    val address: SegAddr,
    val fileId: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
    val endSequence: Boolean
)

data class LineSequence(val index: Int, val start: SegAddr, val end: SegAddr)

data class LineProgram(
    val sectionOffset: Long,
    val unitLength: Long,
    val version: Int,
    val dwarf64: Boolean,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val minInstructionLength: Int,
    val maxOperationsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val files: List<LineFile>,
    val directories: List<String>,
    val rows: List<LineRow>,
    val sequences: List<LineSequence>,
    val issues: List<ParseIssue>,
    val truncated: Boolean
)

data class CompUnit(
    val sectionOffset: Long,
    val unitLength: Long,
    val version: Int,
    val dwarf64: Boolean,
    val unitType: Int,
    val addressSize: Int,
    val abbrevOffset: Long,
    val dwoId: Long?,
    val name: String,
    val compDir: String,
    val language: Long?,
    val root: Die?,
    val lineProgram: LineProgram?,
    val stmtListOffset: Long?,
    val strOffsetsBase: Long?,
    val addrBase: Long?,
    val rangesBase: Long?,
    val dwoName: String?,
    val issues: List<ParseIssue>,
    val corrupted: Boolean
)

/** 一个导入文件解析后的完整产物（解析结果在内存中缓存，原始字节落盘 + 摘要入库）。 */
data class ParsedDebugFile(
    val elf: ElfImage,
    val units: List<CompUnit>,
    val rangeLists: RangeLists,
    val issues: List<ParseIssue>,
    val dwoLinks: List<DwoLink>
)

data class DwoLink(val skeletonOffset: Long, val dwoName: String?, val dwoId: Long, val resolvedFileId: Long?, val reason: String)

/** 收集 DWARF 4/5 的范围表；地址解析延后到查询时（需要 CU base 与 .debug_addr）。 */
class RangeLists(
    val v4Entries: Map<Long, List<RngV4Entry>>,
    val v5Lists: Map<Long, RngV5List>,
    val issues: List<ParseIssue>
)

sealed class RngV4Entry {
    data class Pair(val begin: Long, val end: Long) : RngV4Entry()
    data class Base(val addr: Long) : RngV4Entry()   // begin == maxAddr
    object End : RngV4Entry()
    data class Indexed(val index: Long, val begin: Long, val end: Long) : RngV4Entry()
}

/** DWARF5 一个 rnglist（键为其在 .debug_rnglists 内的绝对偏移），条目保持原始语义。 */
data class RngV5List(val addressSize: Int, val segmentSize: Int, val items: List<RngV5Item>)
sealed class RngV5Item {
    object EndList : RngV5Item()
    data class BaseAddressX(val index: Long) : RngV5Item()
    data class StartxEndx(val startIndex: Long, val endIndex: Long) : RngV5Item()
    data class StartxLength(val startIndex: Long, val length: Long) : RngV5Item()
    data class OffsetPair(val segment: Long, val startOffset: Long, val endOffset: Long) : RngV5Item()
    data class BaseAddress(val address: Long) : RngV5Item()
    data class StartEnd(val segment: Long, val start: Long, val end: Long) : RngV5Item()
    data class StartLength(val segment: Long, val start: Long, val length: Long) : RngV5Item()
}
