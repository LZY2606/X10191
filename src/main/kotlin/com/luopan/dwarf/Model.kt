package com.luopan.dwarf

import java.time.Instant

enum class Endianness { LE, BE }
enum class ElfClassB { ELF32, ELF64 }
enum class ModuleKind { EXECUTABLE, DWO, DWP, OBJECT, UNKNOWN }
enum class NoticeLevel { ERROR, WARN, INFO }

data class ParseNotice(
    val level: NoticeLevel,
    val area: String,
    val message: String,
    val cuOffset: Long? = null,
)

data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val entsize: Long,
    val sha256: String,
)

data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
)

data class ParsedElf(
    val elfClass: ElfClassB,
    val endian: Endianness,
    val machine: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val buildId: String?,
    val sectionsByName: Map<String, ElfSection>,
    val data: Map<String, ByteArray>,
)

sealed class AttrValue {
    data class Addr(val v: Long) : AttrValue()
    data class UConst(val v: Long) : AttrValue()
    data class SConst(val v: Long) : AttrValue()
    data class Str(val text: String) : AttrValue()
    data class SecOffset(val offset: Long) : AttrValue()
    data class Ref(val globalOffset: Long) : AttrValue()
    data class Flag(val on: Boolean) : AttrValue()
    data class Expr(val ops: ByteArray) : AttrValue()
    data class Block(val bytes: ByteArray) : AttrValue()
}

data class Die(
    val offset: Long,
    val tag: Int,
    val attrs: Map<Int, AttrValue>,
    val children: List<Die>,
) {
    fun attr(name: Int): AttrValue? = attrs[name]
}

data class CompilationUnit(
    val cuOffset: Long,
    val unitLength: Long,
    val version: Int,
    val unitType: Int,
    val is64: Boolean,
    val debugAbbrevOffset: Long,
    val addrSize: Int,
    val root: Die?,
    val flatDies: List<Die>,
    val parseError: String?,
    val name: String?,
    val compDir: String?,
    val producer: String?,
    val language: Long?,
    val dwoId: Long?,
    val lineOffset: Long?,
    val skeleton: Boolean,
    val dwo: Boolean,
    val dwoName: String?,
    val strOffsetsBase: Long?,
    val addrBase: Long?,
    val rnglistsBase: Long?,
    val loclistsBase: Long?,
    val cuRanges: List<AddrRange>,
    val cuRangeNotice: String?,
)

data class LineFile(val dir: String, val name: String) {
    val full: String get() = if (dir.isBlank() || dir == ".") name else "$dir/$name"
}

data class LineRow(
    val address: Long,
    val segment: Long,
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

data class LineSequence(
    val rows: List<LineRow>,
    val startAddress: Long,
    val endAddress: Long,
    val segment: Long,
)

data class LineProgram(
    val headerOffset: Long,
    val version: Int,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Int,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val segmentSelectorSize: Int,
    val files: List<LineFile>,
    val sequences: List<LineSequence>,
    val parseError: String?,
)

data class AddrRange(val start: Long, val end: Long, val segment: Long = 0) {
    val length: Long get() = end - start
    val zeroLength: Boolean get() = end == start
    fun contains(addr: Long): Boolean = addr in start until end
    fun containsInclusive(addr: Long): Boolean = zeroLength && addr == start || contains(addr)
}

data class SectionSummary(
    val name: String,
    val offset: Long,
    val size: Long,
    val sha256: String,
    val present: Boolean,
)

data class DebugFile(
    val id: String,
    val versionId: String,
    val importTime: Instant,
    val fileName: String,
    val fileSize: Long,
    val sha256: String,
    val buildId: String?,
    val kind: ModuleKind,
    val elf: ParsedElf,
    val cus: List<CompilationUnit>,
    val lines: Map<Long, LineProgram>,
    val summaries: List<SectionSummary>,
    val notices: List<ParseNotice>,
    val rawBytes: ByteArray?,
)
