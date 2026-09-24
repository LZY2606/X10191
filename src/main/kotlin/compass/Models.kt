package compass

import java.math.BigInteger

data class Warning(val stage: String, val message: String, val offset: Long? = null, val severity: String = "warning")

data class SectionInfo(
    val ordinal: Int,
    val name: String,
    val type: Long,
    val flags: Long,
    val address: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val alignment: Long,
    val entrySize: Long,
    val sha256: String
)

data class ElfFile(
    val elfClass: Int,
    val endian: Int,
    val machine: Int,
    val entry: Long,
    val sections: List<SectionInfo>,
    val bytes: ByteArray
) {
    fun section(name: String): SectionInfo? = sections.firstOrNull { it.name == name }
    fun sectionBytes(name: String): ByteArray = section(name)?.let { sectionBytes(it) } ?: ByteArray(0)
    fun sectionBytes(section: SectionInfo): ByteArray {
        if (section.offset < 0 || section.size < 0 || section.offset + section.size > bytes.size) return ByteArray(0)
        return bytes.copyOfRange(section.offset.toInt(), (section.offset + section.size).toInt())
    }
}

data class AttrValue(val form: String, val raw: BigInteger?, val text: String? = null)

data class DieAttr(val name: String, val attr: Int, val form: Int, val value: AttrValue)

data class RangeEdge(val start: Long, val end: Long, val segment: Int = 0, val source: String = "die", val ordinal: Int = 0) {
    val width: Long get() = end - start
    fun contains(address: Long, segment: Int?): Boolean {
        val segmentMatches = segment == null || segment == this.segment
        if (!segmentMatches) return false
        return if (start == end) address == start else address >= start && address < end
    }
}

data class DwarfUnit(
    val ordinal: Int,
    val offset: Long,
    val size: Long,
    val headerSize: Int,
    val version: Int,
    val unitType: Int,
    val addressSize: Int,
    val segmentSize: Int,
    val abbrevOffset: Long,
    val lineOffset: Long?,
    val lowPc: Long?,
    val name: String?,
    val compDir: String?,
    val dwoName: String?,
    val dwoId: Long?,
    val splitStatus: String,
    val rangeOffset: Long?,
    val nodes: List<DwarfNode>
)

data class DwarfNode(
    val ordinal: Int,
    val offset: Long,
    val tag: Int,
    val tagName: String,
    val depth: Int,
    val parentOffset: Long?,
    val name: String?,
    val linkageName: String?,
    val lowPc: Long?,
    val highPc: Long?,
    val rangesOffset: Long?,
    val callFile: Int?,
    val callLine: Int?,
    val inlineValue: Int?,
    val abstractOrigin: Long?,
    val specification: Long?,
    val attributes: List<DieAttr>,
    val ranges: List<RangeEdge>
)

data class SourceFile(val ordinal: Int, val name: String, val directory: String) {
    val path: String get() = if (directory.isBlank()) name else "$directory/$name"
}

data class LineRow(
    val ordinal: Int,
    val address: Long,
    val segment: Int,
    val fileOrdinal: Int?,
    val fileName: String?,
    val line: Int,
    val column: Int,
    val isa: Int,
    val discriminator: Int,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val endSequence: Boolean
)

data class LineSequence(val ordinal: Int, val startAddress: Long, val endAddress: Long, val segment: Int, val rows: List<LineRow>)

data class UnitLines(
    val cuOrdinal: Int,
    val version: Int,
    val addressSize: Int,
    val segmentSize: Int,
    val offset: Long,
    val files: List<SourceFile>,
    val sequences: List<LineSequence>,
    val warnings: List<Warning>
)

data class DwarfInfo(
    val units: List<DwarfUnit>,
    val linesByCu: Map<Int, UnitLines>,
    val warnings: List<Warning>
)

data class ParsedFile(val elf: ElfFile, val dwarf: DwarfInfo, val sha256: String)
