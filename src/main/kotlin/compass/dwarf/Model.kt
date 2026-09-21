package compass.dwarf

import compass.elf.ElfSection

/** Address range. start/end are section-relative (unrelocated) virtual addresses. */
data class AddrRange(val start: Long, val end: Long) {
    val length: Long get() = end - start
    fun contains(a: Long): Boolean = a in start until end
}

sealed class AttrValue {
    data class Num(val value: Long, val isAddress: Boolean = false) : AttrValue()
    data class Str(val value: String) : AttrValue()
    data class Ref(val offset: Long) : AttrValue()          // .debug_info global offset
    data class SecOffset(val offset: Long) : AttrValue()
    data class Bytes(val value: ByteArray) : AttrValue() {
        override fun equals(other: Any?) = other is Bytes && value.contentEquals(other.value)
        override fun hashCode() = value.contentHashCode()
    }
    data class Flag(val value: Boolean) : AttrValue()
    data class AddrIndex(val index: Long, val baseAttr: Int) : AttrValue()
    data class StrIndex(val index: Long, val baseAttr: Int) : AttrValue()
    data class RangeListIndex(val index: Long) : AttrValue()
}

data class Die(
    val offset: Long,
    val tag: Int,
    val abbrevCode: Long,
    val children: List<Die>,
    val attrs: Map<Int, AttrValue>,
    val cuIndex: Int,
    /** depth within the DIE tree (0 = CU DIE). */
    val depth: Int,
) {
    fun attr(name: Int): AttrValue? = attrs[name]
}

data class FileEntry(val name: String, val dirIndex: Int, val fullPath: String)

data class LineRow(
    val address: Long,
    val file: Int,
    val line: Int,
    val column: Int,
    val isStatement: Boolean,
    val endSequence: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
)

/** One contiguous run of rows terminated by end_sequence. */
data class LineSequence(
    val index: Int,
    val rows: List<LineRow>,
    val startAddress: Long,
    val endAddress: Long, // exclusive
    val cuIndex: Int,
) {
    fun rowFor(address: Long): LineRow? {
        if (address !in startAddress until endAddress) return null
        var best: LineRow? = null
        for (row in rows) {
            if (row.endSequence) continue
            if (row.address <= address) {
                if (best == null || row.address >= best.address) best = row
            }
        }
        return best
    }
}

data class LineProgram(
    val cuIndex: Int,
    val version: Int,
    val files: List<FileEntry>,
    val includeDirs: List<String>,
    val sequences: List<LineSequence>,
    val defaultIsStmt: Boolean,
    val minimumInstructionLength: Int,
    val maximumOperationsPerInstruction: Int,
)

data class CompUnit(
    val index: Int,
    val version: Int,           // 4 or 5
    val is64Bit: Boolean,
    val offset: Long,           // header start in .debug_info
    val length: Long,           // excludes initial length
    val unitType: Int,
    val debugAbbrevOffset: Long,
    val addressSize: Int,
    val root: Die,
    val dies: Map<Long, Die>,
    val lineProgram: LineProgram?,
    val stmtListOffset: Long?,
    val dwoName: String?,
    val warnings: List<String>,
    /** Effective .debug_addr base for addrx (DW_AT_addr_base / GNU). */
    val addrBase: Long?,
    val strOffsetsBase: Long?,
    val rangesBase: Long?,
    val tableVersion: String,
)

data class SectionDigest(
    val name: String,
    val ordinal: Int,
    val type: Int,
    val offset: Long,
    val size: Long,
    val address: Long,
    val sha256: String,
    val present: Boolean,
)

data class DwarfSections(
    val info: ByteArray?,
    val abbrev: ByteArray?,
    val line: ByteArray?,
    val ranges: ByteArray?,
    val rnglists: ByteArray?,
    val str: ByteArray?,
    val lineStr: ByteArray?,
    val addr: ByteArray?,
    val strOffsets: ByteArray?,
    val loclists: ByteArray?,
    val sectionMeta: List<ElfSection>,
)
