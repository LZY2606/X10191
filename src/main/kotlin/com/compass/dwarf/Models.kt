package com.compass.dwarf

import kotlinx.serialization.Serializable

@Serializable
data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val fileOffset: Long,
    val fileSize: Long,
    val virtualAddress: Long,
    val link: Int,
    val info: Int,
    val addressAlignment: Long,
    val entrySize: Long,
    val sha256: String
)

@Serializable
data class ElfSummary(
    val elfClass: Int,
    val littleEndian: Boolean,
    val type: Int,
    val machine: Int,
    val entry: Long,
    val buildId: String? = null,
    val programBase: Long? = null,
    val sections: List<ElfSection> = emptyList()
)

@Serializable
data class LineFile(val index: Int, val name: String, val directoryIndex: Int? = null)

@Serializable
data class LineRow(
    val index: Int,
    val segment: Long,
    val address: Long,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val endSequence: Boolean,
    val isStatement: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
    val operationIndex: Int
)

@Serializable
data class LineSequence(
    val index: Int,
    val segment: Long,
    val startAddress: Long,
    val endAddress: Long,
    val rows: List<LineRow>
)

@Serializable
data class LineProgram(
    val cuOffset: Long,
    val sectionOffset: Long,
    val version: Int,
    val minimumInstructionLength: Int,
    val maximumOperationsPerInstruction: Int,
    val defaultIsStatement: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val files: List<LineFile>,
    val directories: List<String>,
    val sequences: List<LineSequence>,
    val allRows: List<LineRow>
)

@Serializable
data class DwarfRange(
    val start: Long,
    val end: Long,
    val segment: Long = 0,
    val dieOffset: Long,
    val tag: Int,
    val name: String?,
    val inlineDepth: Int = 0,
    val zeroLength: Boolean = start == end,
    val source: String = "die"
) {
    val width: Long get() = end - start
}

@Serializable
data class DieAttribute(val attr: Int, val form: Int, val value: AttrValue)

@Serializable
sealed class AttrValue {
    @Serializable data class AddressValue(val value: Long) : AttrValue()
    @Serializable data class NumberValue(val value: Long) : AttrValue()
    @Serializable data class TextValue(val value: String) : AttrValue()
    @Serializable data class BooleanValue(val value: Boolean) : AttrValue()
    @Serializable data class BytesValue(val value: ByteArray) : AttrValue() {
        override fun equals(other: Any?): Boolean = other is BytesValue && value.contentEquals(other.value)
        override fun hashCode(): Int = value.contentHashCode()
    }
    @Serializable data class ReferenceValue(val offset: Long) : AttrValue()
    @Serializable data class UnknownFormValue(val form: Int) : AttrValue()
}

@Serializable
data class DieNode(
    val offset: Long,
    val tag: Int,
    val depth: Int,
    val parentOffset: Long?,
    val attributes: List<DieAttribute>
) {
    fun attr(name: Int): DieAttribute? = attributes.firstOrNull { it.attr == name }
    fun number(name: Int): Long? = (attr(name)?.value as? AttrValue.NumberValue)?.value
    fun address(name: Int): Long? = (attr(name)?.value as? AttrValue.AddressValue)?.value
    fun text(name: Int): String? = (attr(name)?.value as? AttrValue.TextValue)?.value
    fun flag(name: Int): Boolean = (attr(name)?.value as? AttrValue.BooleanValue)?.value == true
    fun reference(name: Int): Long? = (attr(name)?.value as? AttrValue.ReferenceValue)?.offset
}

@Serializable
data class CompilationUnit(
    val offset: Long,
    val size: Long,
    val version: Int,
    val dwarf64: Boolean,
    val unitType: Int,
    val addressSize: Int,
    val segmentSize: Int = 0,
    val abbrevOffset: Long,
    val name: String?,
    val compilationDirectory: String?,
    val dwoName: String?,
    val dwoId: Long?,
    val statementListOffset: Long,
    val isSkeleton: Boolean,
    val isSplit: Boolean,
    val ranges: List<DwarfRange>,
    val lineProgram: LineProgram?,
    val dies: List<DieNode>,
    val warnings: List<String>
)

@Serializable
data class DebugDocument(
    val elf: ElfSummary,
    val compilationUnits: List<CompilationUnit>,
    val warnings: List<String>
)
