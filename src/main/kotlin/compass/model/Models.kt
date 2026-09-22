package compass.model

/** A resolved linked address: optional x86 real-mode/segment selector plus 64-bit offset. */
data class SegmentedAddress(val selector: Long, val offset: Long) : Comparable<SegmentedAddress> {
    override fun compareTo(other: SegmentedAddress): Int {
        val s = selector.compareTo(other.selector)
        if (s != 0) return s
        return unsignedCompare(offset, other.offset)
    }
    companion object {
        fun plain(off: Long) = SegmentedAddress(0L, off)
        fun unsignedCompare(a: Long, b: Long): Int =
            a.compareTo(b) // Long natural order is wrong for unsigned; replace below
    }
}

/** unsigned [a] vs [b] */
fun unsignedCompare(a: Long, b: Long): Int {
    val aa = a xor Long.MIN_VALUE
    val bb = b xor Long.MIN_VALUE
    return aa.compareTo(bb)
}

data class SectionInfo(
    val name: String,
    val nameOffset: Int,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val fileOffset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val data: ByteArray,
) {
    val isDebug: Boolean get() = name.startsWith(".debug") || name.startsWith(".zdebug")
    override fun equals(other: Any?) = this === other
    override fun hashCode() = name.hashCode()
}

/** [start, end) pair carrying the segment selector. */
data class AddrRange(val selector: Long, val start: Long, val end: Long) {
    val length: Long get() = end - start
    fun contains(otherSelector: Long, addr: Long): Boolean =
        selector == otherSelector && unsignedCompare(addr, start) >= 0 && unsignedCompare(addr, end) < 0
    fun containsInclusive(otherSelector: Long, addr: Long): Boolean =
        selector == otherSelector && unsignedCompare(addr, start) >= 0 && unsignedCompare(addr, end) <= 0
    infix fun overlaps(other: AddrRange): Boolean =
        selector == other.selector && unsignedCompare(start, other.end) < 0 && unsignedCompare(other.start, end) < 0
}

data class LoadSegment(
    val type: Int,
    val flags: Int,
    val fileOffset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
) {
    fun contains(runtimeAddr: Long): Boolean =
        unsignedCompare(runtimeAddr, vaddr) >= 0 && unsignedCompare(runtimeAddr, vaddr + memsz) < 0
}

data class ElfFile(
    val pathHint: String,
    val elfClass: ElfClass,
    val littleEndian: Boolean,
    val machine: Int,
    val entry: Long,
    val type: Int,
    val sections: List<SectionInfo>,
    val segments: List<LoadSegment>,
    val rawBytes: ByteArray,
    val buildId: String?,
) {
    fun section(name: String): SectionInfo? = sections.firstOrNull { it.name == name }
    fun sectionData(name: String): ByteArray? = section(name)?.data
}

enum class AttrForm(val code: Int) {
    ADDR(0x01),
    BLOCK2(0x03), BLOCK4(0x04), DATA2(0x05), DATA4(0x06), DATA8(0x07),
    STRING(0x08), BLOCK(0x09), BLOCK1(0x0a), DATA1(0x0b), FLAG(0x0c),
    SDATA(0x0d), STRP(0x0e), UDATA(0x0f), REF_ADDR(0x10), REF1(0x11), REF2(0x12),
    REF4(0x13), REF8(0x14), REF_UDATA(0x15), INDIRECT(0x16),
    SEC_OFFSET(0x17), EXPRLOC(0x18), FLAG_PRESENT(0x19), STRX(0x1a),
    ADDRX(0x1b), REF_SUP4(0x1c), STRP_SUP(0x1d), DATA16(0x1e),
    LINE_STRP(0x1f), REF_SIG8(0x20), IMPLICIT_CONST(0x21),
    LOCLISTX(0x22), RNGLISTX(0x23), REF_SUP8(0x24), STRX1(0x25),
    STRX2(0x26), STRX3(0x27), STRX4(0x28), ADDRX1(0x29), ADDRX2(0x2a),
    ADDRX3(0x2b), ADDRX4(0x2c);

    companion object {
        fun from(code: Int): AttrForm? = entries.firstOrNull { it.code == code }
    }
}

/** Attribute value already normalized by the CU's str_offsets/addr base machinery. */
sealed class AttrValue {
    data class Str(val value: String) : AttrValue()
    data class Addr(val value: Long) : AttrValue()
    data class Num(val value: Long) : AttrValue()
    data class Bool(val value: Boolean) : AttrValue()
    /** section-offset reference into .debug_info (absolute CU-section offset) */
    data class InfoRef(val offset: Long) : AttrValue()
    /** .debug_ranges / .debug_rnglists offset */
    data class RangeRef(val offset: Long, val indexed: Boolean) : AttrValue()
    data class StrOffsetsRef(val base: Long, val index: Long) : AttrValue()
    data class AddrIndex(val base: Long, val index: Long) : AttrValue()
    data class Sig8(val signature: Long) : AttrValue()
    data class Raw(val bytes: ByteArray) : AttrValue()
    data class UnknownForm(val formCode: Int) : AttrValue()
}

data class Attribute(val name: Int, val formCode: Int, val value: AttrValue)

data class Die(
    val offset: Long,
    val tag: Int,
    val depth: Int,
    val attributes: List<Attribute>,
    val childrenOffsets: MutableList<Long> = mutableListOf(),
    var parentOffset: Long = -1L,
) {
    fun attr(name: Int): Attribute? = attributes.firstOrNull { it.name == name }
    fun num(name: Int): Long? = (attr(name)?.value as? AttrValue.Num)?.value
    fun str(name: Int): String? = (attr(name)?.value as? AttrValue.Str)?.value
    fun addr(name: Int): Long? = (attr(name)?.value as? AttrValue.Addr)?.value
}

data class RangeListTable(
    val version: Int,
    /** offset-relative base (DWARF5 rnglists_base) */
    val baseOffset: Long,
    val ranges: Map<Long, List<AddrRange>>,
)

data class CompilationUnit(
    val version: Int,
    val unitType: Int,
    val is64Bit: Boolean,
    val headerOffset: Long,
    val abbrevOffset: Long,
    val addressSize: Int,
    val segmentSize: Int,
    val firstDieOffset: Long,
    val nextUnitOffset: Long,
    /** DW_AT_name or comp_dir for display */
    val name: String?,
    val compDir: String?,
    val dies: Map<Long, Die>,
    val root: Die?,
    val dwoId: Long?,
    val dwoName: String?,
    val isSkeleton: Boolean,
    val isSplit: Boolean,
    val rangeLists: List<AddrRange>,
    val rnglistsBase: Long,
    val strOffsetsBase: Long,
    val addrBase: Long,
    val sourceLanguage: Int?,
)

data class FileEntry(val id: Int, val name: String, val dirIndex: Int, val mtime: Long, val size: Long)

data class LineRow(
    val address: Long,
    val selector: Long,
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

data class LineEvent(
    val seqIndex: Int,
    val row: LineRow,
    /** human-readable reason the state machine emitted/changed */
    val trigger: String,
)

data class LineSequence(val index: Int, val rows: List<LineRow>, val cuHeaderOffset: Long) {
    val start: Long get() = rows.first().address
    val end: Long get() = rows.last().address
    val selector: Long get() = rows.first().selector
    val isEmpty: Boolean get() = rows.size < 2
    fun range(): AddrRange = AddrRange(selector, start, if (rows.size >= 2) end else start)
}

data class LineProgram(
    val version: Int,
    val cuHeaderOffset: Long,
    val files: List<FileEntry>,
    val dirs: List<String>,
    val sequences: List<LineSequence>,
    val events: List<LineEvent>,
    val defaultIsStmt: Boolean,
    val minimumInstructionLength: Int,
    val maximumOperationsPerInstruction: Int,
)

data class ParseIssue(
    val severity: String, // ERROR | WARNING | INFO
    val code: String,
    val message: String,
    val section: String? = null,
    val offset: Long? = null,
)

data class ParsedDebugFile(
    val elf: ElfFile,
    val units: List<CompilationUnit>,
    val linePrograms: List<LineProgram>,
    val issues: List<ParseIssue>,
    val sectionSha: Map<String, String>,
    val fileSha: String,
    /** dwo signature -> CU (parsed .dwp or imported dwo units) */
    val dwoUnits: Map<Long, CompilationUnit>,
    val hasSplitRefs: Boolean,
)
