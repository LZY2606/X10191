package compass.dwarf

import compass.Ref

/** All raw debug sections relevant to parsing. Missing sections stay null. */
class DwarfSections(
    val info: ByteArray? = null,
    val abbrev: ByteArray? = null,
    val line: ByteArray? = null,
    val str: ByteArray? = null,
    val lineStr: ByteArray? = null,
    val ranges: ByteArray? = null,
    val rnglists: ByteArray? = null,
    val addr: ByteArray? = null,
    val strOffsets: ByteArray? = null,
    val infoDwo: ByteArray? = null,
    val abbrevDwo: ByteArray? = null,
    val lineDwo: ByteArray? = null,
    val strDwo: ByteArray? = null,
    val strOffsetsDwo: ByteArray? = null,
) {
    companion object {
        val DEBUG_SECTION_NAMES = listOf(
            ".debug_info", ".debug_abbrev", ".debug_line", ".debug_str", ".debug_line_str",
            ".debug_ranges", ".debug_rnglists", ".debug_addr", ".debug_str_offsets",
            ".debug_info.dwo", ".debug_abbrev.dwo", ".debug_line.dwo",
            ".debug_str.dwo", ".debug_str_offsets.dwo",
        )
    }
}

sealed class AttrValue {
    data class Addr(val v: Long) : AttrValue()
    data class Num(val v: Long) : AttrValue()
    data class Str(val v: String) : AttrValue()
    /** Index into .debug_str_offsets (resolved against the CU str-offsets base). */
    data class StrIndex(val index: Long) : AttrValue()
    /** Index into .debug_addr (resolved against the CU addr base, supplied by the skeleton). */
    data class AddrIndex(val index: Long) : AttrValue()
    data class Bytes(val v: ByteArray) : AttrValue() {
        override fun equals(other: Any?) = other is Bytes && v.contentEquals(other.v)
        override fun hashCode() = v.contentHashCode()
    }
    data class Reference(val ref: Ref) : AttrValue()
    data class Flag(val v: Boolean) : AttrValue()
    data class SecOffset(val v: Long) : AttrValue()
    data class Unknown(val form: Int) : AttrValue()
}

data class Attribute(val name: Int, val form: Int, val value: AttrValue) {
    fun asLong(): Long? = when (value) {
        is AttrValue.Addr -> value.v
        is AttrValue.Num -> value.v
        is AttrValue.StrIndex -> value.index
        is AttrValue.AddrIndex -> value.index
        is AttrValue.SecOffset -> value.v
        is AttrValue.Flag -> if (value.v) 1 else 0
        else -> null
    }
    fun asString(): String? = (value as? AttrValue.Str)?.v
    fun asRef(): Ref? = (value as? AttrValue.Reference)?.ref
}

class Die(
    val offset: Long,
    val tag: Int,
    val attrs: List<Attribute>,
    val children: List<Die>,
) {
    fun attr(name: Int): Attribute? = attrs.firstOrNull { it.name == name }

    /** Walk the whole subtree depth-first. */
    fun walk(visit: (Die, depth: Int) -> Unit) {
        val stack = ArrayDeque<Pair<Die, Int>>()
        stack.addLast(this to 0)
        var guard = 0
        while (stack.isNotEmpty()) {
            if (++guard > 1_000_000) throw IllegalStateException("DIE walk limit exceeded")
            val (die, depth) = stack.removeLast()
            visit(die, depth)
            for (i in die.children.indices.reversed()) stack.addLast(die.children[i] to depth + 1)
        }
    }
}

data class AbbrevDecl(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val spec: List<Pair<Int, Int>>, // attr name -> form
)

/** A segment+offset address (segment is 0 for ordinary addresses). */
data class SegAddr(val segment: Long, val offset: Long)

data class AddressRange(
    val start: SegAddr,
    val end: SegAddr,
    val source: RangeSource,
    /** Zero length ranges are legal and match nothing but must be shown. */
    val zeroLength: Boolean = end.offset == start.offset,
)

enum class RangeSource { LOW_HIGH_PC, DEBUG_RANGES, DEBUG_RNGLISTS, LINE_PROGRAM, EMPTY_HINT }

data class CompileUnit(
    val cuOffset: Long,
    val version: Int,
    val dwarfVersion: Int,
    val unitType: Int,
    val addressSize: Int,
    val segmentSize: Int,
    val abbrevOffset: Long,
    val name: String?,
    val compDir: String?,
    val dwoName: String?,
    val root: Die,
    val isSkeleton: Boolean,
    val isSplit: Boolean,
    val stmtList: Long?,
    val warnings: List<String>,
)

/** A file entry inside a line program header. */
data class LineFile(
    val id: Int,
    val name: String,
    val dir: String,
    val dirIndex: Int,
    val timestamp: Long?,
    val size: Long?,
    val md5: String?,
)

data class LineRow(
    val address: SegAddr,
    val file: LineFile,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val endSequence: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
)

data class LineSequence(
    val index: Int,
    val rows: List<LineRow>,
    val startAddress: SegAddr,
    val endAddress: SegAddr,
) {
    /** Half-open [start, end); zero-length sequences contain a lone end row. */
    fun contains(addr: SegAddr): Boolean =
        startAddress.segment == addr.segment &&
            addr.offset >= startAddress.offset && addr.offset < endAddress.offset
}

data class LineProgram(
    val cuOffset: Long,
    val version: Int,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val files: List<LineFile>,
    val sequences: List<LineSequence>,
    /** Every state change, in program order, for the UI timeline. */
    val events: List<LineEvent>,
    val warnings: List<String>,
)

data class LineEvent(
    val kind: String,
    val address: SegAddr,
    val file: String?,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val detail: String,
)
