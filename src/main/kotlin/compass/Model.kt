package compass

import kotlinx.serialization.Serializable

/** Segmented (x86 real-mode / SPU-style) address. segment selector 0 means flat. */
@Serializable
data class TargetAddress(val offset: Long, val segment: Int = 0) : Comparable<TargetAddress> {
    override fun compareTo(other: TargetAddress): Int {
        if (segment != other.segment) return segment.compareTo(other.segment)
        return java.lang.Long.compareUnsigned(offset, other.offset)
    }
    val hex: String get() = if (segment != 0) "0x${segment.toString(16)}:0x${unsignedHex(offset)}" else "0x${unsignedHex(offset)}"
    companion object {
        fun unsignedHex(v: Long): String = java.lang.Long.toUnsignedString(v, 16)
    }
}

/** Half-open [start, end) target-address range; zero length allowed for boundary tests. */
@Serializable
data class AddrRange(val start: TargetAddress, val end: TargetAddress) {
    val length: Long get() = end.offset - start.offset
    fun contains(a: TargetAddress): Boolean =
        a.segment == start.segment &&
            java.lang.Long.compareUnsigned(a.offset, start.offset) >= 0 &&
            java.lang.Long.compareUnsigned(a.offset, end.offset) < 0
    /** [start,end] inclusive — needed for zero-length range points (end==start). */
    fun containsInclusive(a: TargetAddress): Boolean =
        a.segment == start.segment &&
            java.lang.Long.compareUnsigned(a.offset, start.offset) >= 0 &&
            java.lang.Long.compareUnsigned(a.offset, end.offset) <= 0
}

enum class RangeOrigin { LOW_HIGH_PC, RANGES_V4, RNGLIST_V5, IMPLICIT_SINGLE_POINT }

@Serializable
data class RangeWithOrigin(val range: AddrRange, val origin: RangeOrigin)

data class AttrValue(val raw: Any?) {
    fun longValue(): Long? = raw as? Long
    fun stringValue(): String? = raw as? String
    fun addrValue(): TargetAddress? = raw as? TargetAddress
    fun bytesValue(): ByteArray? = raw as? ByteArray
}

@Serializable
data class DieAttr(val name: String, val form: String, val display: String)

@Serializable
data class DieNode(
    val globalOffset: Long,
    val tag: String,
    val tagCode: Long,
    val depth: Int,
    val parentOffset: Long?,
    val childOffsets: List<Long>,
    val attrs: Map<String, DieAttr>,
    val ranges: List<RangeWithOrigin>,
    val name: String?,
    val declFileIndex: Long?,
    val declLine: Long?,
    val declColumn: Long?,
    val callFileIndex: Long?,
    val callLine: Long?,
    val callColumn: Long?,
    val inlineCode: Long?,
    val abstractOriginGlobal: Long?,
    val specificationGlobal: Long?,
    val hasRangesAttr: Boolean,
    val rangesValid: Boolean,
)

@Serializable
data class LineFile(val index: Long, val name: String, val fullPath: String)

@Serializable
data class LineRow(
    val address: TargetAddress,
    val endSequence: Boolean,
    val fileIndex: Long,
    val line: Long,
    val column: Long,
    val isStmt: Boolean,
    val isa: Long,
    val discriminator: Long,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val opIndex: Long,
)

@Serializable
data class LineSequence(
    val index: Int,
    val start: TargetAddress,
    val end: TargetAddress,
    val rows: List<LineRow>,
    val sectionOffset: Long,
)

@Serializable
data class LineProgram(
    val version: Int,
    val dwarf5: Boolean,
    val addressSize: Int,
    val selectorSize: Int,
    val defaultIsStmt: Boolean,
    val segmentSelectorSize: Int,
    val files: List<LineFile>,
    val directories: List<String>,
    val sequences: List<LineSequence>,
    val sectionOffset: Long,
)

enum class DwoStatus { FULL, SKELETON_NO_DWO, SPLIT_COMPANION, COMPANION_PRESENT, NO_DEBUG_INFO }

@Serializable
data class CompilationUnit(
    val globalOffset: Long,
    val version: Int,
    val dwarf5: Boolean,
    val unitType: String,
    val unitTypeCode: Int,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val dwoName: String?,
    val dwoId: Long?,
    val compDir: String?,
    val name: String?,
    val producer: String?,
    val language: Long?,
    val stmtListOffset: Long?,
    val dieCount: Int,
    val dies: Map<Long, DieNode>,
    val rootOffset: Long,
    val dieOrder: List<Long>,
    val ranges: List<RangeWithOrigin>,
    val lineProgram: LineProgram?,
    val dwoStatus: String,
    val trustLevel: String,
    val warnings: List<String>,
)

@Serializable
data class ParseWarning(val area: String, val severity: String, val message: String)

@Serializable
data class ParsedVersion(
    val label: String,
    val files: List<ParsedFile>,
    val warnings: List<ParseWarning>,
)

@Serializable
data class ParsedFile(
    val id: Long? = null,
    val fileName: String,
    val kind: String,
    val buildId: String?,
    val elfClass: String?,
    val machine: Int?,
    val sha256: String?,
    val sections: List<SectionDigest>,
    val loads: List<LoadSegment>,
    val cus: List<CompilationUnit>,
    val hasDwarf: Boolean,
)

// ---------- resolution ----------

@Serializable
data class InlineFrame(
    val function: String,
    val tag: String,
    val dieOffset: Long,
    val depth: Int,
    val declarationFile: String?,
    val declarationLine: Long?,
    val declarationColumn: Long?,
    val callFile: String?,
    val callLine: Long?,
    val callColumn: Long?,
    val rangeStart: TargetAddress?,
    val rangeEnd: TargetAddress?,
    val rangeOrigin: String?,
    val abstractName: String?,
)

@Serializable
data class AddressCandidate(
    val runtimeAddress: TargetAddress,
    val relativeAddress: TargetAddress,
    val loadBias: Long,
    val loadBiasHex: String,
    val matched: Boolean,
    val file: String,
    val fileIndex: Int,
    val buildId: String?,
    val cuOffset: Long,
    val cuName: String?,
    val cuUnitType: String,
    val dwarfVersion: Int,
    val lineTableVersion: Int,
    val sequenceIndex: Int?,
    val sequenceStart: TargetAddress?,
    val sequenceEnd: TargetAddress?,
    val sourceFile: String?,
    val line: Long?,
    val column: Long?,
    val endSequence: Boolean?,
    val inlineChain: List<InlineFrame>,
    val functionName: String?,
    val rangeStart: TargetAddress?,
    val rangeEnd: TargetAddress?,
    val rangeWidth: Long?,
    val rangeOrigin: String?,
    val inlineDepth: Int,
    val explicitPriority: Long,
    val scoreBreakdown: Map<String, Long>,
    val trustLevel: String,
    val notes: List<String>,
)

@Serializable
data class BatchResolution(
    val snapshotId: Long?,
    val snapshotLabel: String?,
    val results: List<AddressCandidate>,
    val unmatched: List<TargetAddress>,
)
