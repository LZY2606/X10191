package com.linecompass.dwarf

/** A single decoded DW_AT_* attribute value, kept form-aware for diagnostics. */
sealed class AttrValue {
    data class Addr(val value: Long) : AttrValue()
    data class Number(val value: Long) : AttrValue()
    data class Text(val value: String) : AttrValue()
    data class SectionOffset(val value: Long) : AttrValue()
    /** Resolved reference to a DIE global offset; resolution may be null if out of bounds. */
    data class Ref(val targetOffset: Long, val resolved: Boolean) : AttrValue()
    data class Expr(val opcodes: ByteArray) : AttrValue()
    data class Unknown(val formCode: Int) : AttrValue()
}

data class Attr(val name: Int, val form: Int, val value: AttrValue)

data class DieNode(
    val offset: Long,
    val tag: Int,
    val attributes: List<Attr>,
    val children: List<DieNode>,
    var cu: CompilationUnit?,
    val parent: DieNode?
) {
    fun attr(name: Int): Attr? = attributes.firstOrNull { it.name == name }
    fun num(name: Int): Long? = (attr(name)?.value as? AttrValue.Number)?.value
    fun addr(name: Int): Long? = when (val v = attr(name)?.value) {
        is AttrValue.Addr -> v.value
        is AttrValue.Number -> v.value
        else -> null
    }
    fun text(name: Int): String? = (attr(name)?.value as? AttrValue.Text)?.value

    val isInline: Boolean get() = tag == DW.TAG_inlined_subroutine
    val isSubprogram: Boolean get() = tag == DW.TAG_subprogram

    /**
     * Numeric name preference for stable ordering (no locale ordering surprises).
     * DIEs without names sort after named ones.
     */
    fun nameOrNull(): String? = text(DW.AT_name)
}

enum class RangeKind { LINE_TABLE, SUBPROGRAM, INLINED, SCOPE, RANGE_LIST }

data class AddressRange(
    val start: Long,
    val end: Long,
    val segment: Int = 0,
    val kind: RangeKind,
    val die: DieNode? = null,
    val cu: CompilationUnit? = die?.cu,
    /** Explicit source priority; smaller is stronger (1 = explicit DW_AT_ranges). */
    val explicitPriority: Int = 3,
    val zeroLength: Boolean = java.lang.Long.compareUnsigned(end, start) == 0
) {
    val width: Long get() = end - start // only meaningful when not zeroLength
    fun contains(seg: Int, addr: Long): Boolean {
        if (seg != segment) return false
        return java.lang.Long.compareUnsigned(addr, start) >= 0 &&
            java.lang.Long.compareUnsigned(addr, end) < 0
    }
    fun containsVaddr(addr: Long): Boolean = contains(segment, addr)
}

data class FileEntry(val name: String, val dirIndex: Int, val fullPath: String)

data class LineRow(
    val address: Long,
    val segment: Int,
    val fileIndex: Int,
    val file: FileEntry,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val endSequence: Boolean,
    val isa: Int,
    val discriminator: Int,
    val order: Int
)

data class LineSequence(
    val startAddress: Long,
    val endAddress: Long,
    val segment: Int,
    val rows: List<LineRow>,
    val cu: CompilationUnit
) {
    fun contains(seg: Int, addr: Long): Boolean = seg == segment &&
        java.lang.Long.compareUnsigned(addr, startAddress) >= 0 &&
        java.lang.Long.compareUnsigned(addr, endAddress) <= 0
}

data class LineProgram(
    val cu: CompilationUnit,
    val version: Int,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val files: List<FileEntry>,
    val includeDirs: List<String>,
    val sequences: List<LineSequence>
)

enum class CuKind { COMPILE, SKELETON, SPLIT_COMPILE, TYPE, PARTIAL, OTHER }

data class CompilationUnit(
    val offset: Long,
    val length: Long,
    val version: Int,
    val is64BitDwarf: Boolean,
    val unitType: Int,
    val kind: CuKind,
    val addressSize: Int,
    val abbrevOffset: Long,
    val dwoId: Long?,
    var root: DieNode?,
    var dieByOffset: Map<Long, DieNode>,
    var lineProgram: LineProgram?,
    var ranges: List<AddressRange>,
    val littleEndian: Boolean,
    /** For skeleton CUs, the paired split CU (same dwo_id) after matching. */
    var splitCu: CompilationUnit? = null,
    var splitMissing: Boolean = false,
    // Section offsets to indexed tables, read from the root DIE during the scan.
    var strOffsetsBase: Long = 0L,
    var addrBase: Long = 0L
) {
    val name: String get() = root?.text(DW.AT_name) ?: ("cu@0x" + offset.toString(16))
    val compDir: String? get() = root?.text(DW.AT_comp_dir)
    val producer: String? get() = root?.text(DW.AT_producer)
    val lowPc: Long? get() = root?.addr(DW.AT_low_pc)
    val stmtListOffset: Long? get() = (root?.attr(DW.AT_stmt_list)?.value as? AttrValue.SectionOffset)?.value
}

data class ParseIssue(
    val section: String,
    val severity: String, // ERROR | WARNING
    val code: String,
    val message: String,
    val offset: Long? = null,
    val cuOffset: Long? = null
)

data class SectionBlob(val name: String, val bytes: ByteArray, val vaddr: Long)

data class DebugSections(
    val sections: Map<String, SectionBlob>,
    val elf: com.linecompass.elf.ElfFile?
) {
    fun blob(name: String): SectionBlob? = sections[name]
}

data class ParsedDebugFile(
    val sections: DebugSections,
    val cus: List<CompilationUnit>,
    val issues: List<ParseIssue>,
    val rangeIndex: List<AddressRange>,
    val rawSectionSummary: Map<String, String>,
    val fileSummary: String
)
