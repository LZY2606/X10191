package compass.model

/**
 * Core domain model of the "行址罗盘" (Address Compass).
 * Everything produced by the local ELF/DWARF parser is represented here;
 * nothing here shells out to addr2line or any system debugger.
 */

/** Index of a byte region inside one file (e.g. a section). */
data class ByteRegion(val fileOffset: Long, val size: Long)

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
)

/** ELF program segment (for load bias / vaddr mapping). */
data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
) {
    val isLoad: Boolean get() = type == 1 // PT_LOAD
}

enum class ElfClass(val bytes: Int) { ELF32(1), ELF64(2) }
enum class Endian(val big: Boolean) { LITTLE(false), BIG(true) }

data class ElfFile(
    val elfClass: ElfClass,
    val endian: Endian,
    val machine: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val sectionDigest: Map<String, String>,
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }
}

/** One row produced by executing a DWARF line program. */
data class LineRow(
    val address: Long,
    val fileIndex: Int,
    val file: String?,
    val line: Int,
    val column: Int,
    val endSequence: Boolean,
    val isa: Int,
    val discriminator: Int,
    val opIndex: Int,
)

/**
 * One "sequence" (run of rows terminated by DW_LNE_end_sequence).
 * startAddress/endAddress are bounds; the end row address is exclusive-ish
 * but we keep it explicitly since the end_sequence row address is meaningful.
 */
data class LineSequence(
    val id: Long,
    val cuId: Long,
    val version: Int,
    val startAddress: Long,
    val endAddress: Long,
    val rows: List<LineRow>,
)

/** One compilation unit summary. */
data class CompilationUnit(
    val id: Long,
    val offset: Long,
    val version: Int,                 // 4 or 5
    val dwarf64: Boolean,
    val compDir: String?,
    val name: String?,
    val language: String?,
    val lowPc: Long?,
    val isSkeleton: Boolean,
    val dwoName: String?,
    val dwoId: Long?,
    val skeletonForId: Long?,        // id of the split CU providing full info, if resolved
    val producer: String?,
)

/** A parsed DIE that carries address/range/inline information. */
data class DieNode(
    val id: Long,
    val cuId: Long,
    val bundle: String,
    val offset: Long,
    val tag: Int,
    val tagName: String,
    val depth: Int,
    val parentId: Long?,
    val name: String?,
    val linkageName: String?,
    val lowPc: Long?,
    /** For constant-form high_pc this is size; for address-form it's absolute end. */
    val highPc: Long?,
    val highPcIsAddress: Boolean,
    val rangesOffset: Long?,
    val rangesBase: Long?,           // rnglists base (DWARF5)
    val inlineValue: Int,            // DW_INL_* (0 = not inlined)
    val callFile: String?,
    val callLine: Int,
    val declFile: String?,
    val declLine: Int,
    val abstractOrigin: Long?,       // global offset -> DieNode resolved later
    val specification: Long?,
    val external: Boolean,
) {
    val isFunctionLike: Boolean
        get() = tag == 0x2e || // DW_TAG_subprogram
            tag == 0x2f ||    // DW_TAG_inlined_subroutine
            tag == 0x1d       // DW_TAG_common_block (rare); kept harmless
    val isInlinedSubroutine: Boolean get() = tag == 0x2f
}

/** A concrete [start,end) interval owned by a DIE. Zero-length intervals are kept. */
data class DieRange(
    val id: Long,
    val dieId: Long,
    val cuId: Long,
    val start: Long,
    val end: Long,
    val source: String, // "high_pc" | "rnglist" | "rnglists5"
    val index: Int,
)

data class SectionWarning(
    val section: String,
    val cuOffset: Long?,
    val message: String,
)

/** Everything parsed from one binary (+ its resolved .dwo files). */
data class ParsedDebugInfo(
    val elf: ElfFile,
    val cus: List<CompilationUnit>,
    val dies: List<DieNode>,
    val ranges: List<DieRange>,
    val sequences: List<LineSequence>,
    val warnings: List<SectionWarning>,
    /** .dwo file names that were referenced but could not be found/parsed. */
    val missingDwos: List<String>,
)
