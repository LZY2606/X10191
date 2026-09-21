package com.compass.dwarf

/** A diagnostic that downgrades confidence instead of aborting the whole import. */
data class ParseIssue(val scope: String, val message: String, val severity: String = "warn") {
    fun serial() = mapOf("scope" to scope, "message" to message, "severity" to severity)
}

data class AddrRange(val low: Long, val high: Long, val zeroLength: Boolean = false) {
    val length: Long get() = high - low
    fun contains(addr: Long) = !zeroLength && addr in low until high
    fun serial() = mapOf(
        "low" to "0x${low.toULong().toString(16)}",
        "high" to "0x${high.toULong().toString(16)}",
        "length" to "0x${(high - low).toULong().toString(16)}",
        "zeroLength" to zeroLength
    )
}

data class SourceFile(val index: Int, val name: String, val dirIndex: Int)

data class LineRow(val address: Long, val fileIndex: Int, val line: Int, val column: Int,
                   val endSequence: Boolean, val discriminator: Int, val isa: Int, val stmt: Boolean,
                   val basicBlock: Boolean, val prologueEnd: Boolean)

data class LineSequence(val index: Int, val startAddress: Long, val endAddress: Long, val rows: List<LineRow>)

data class LineTable(val cuOffset: Long, val version: Int, val dwarf64: Boolean,
                     val files: List<SourceFile>, val dirs: List<String>,
                     val sequences: List<LineSequence>, val issues: List<ParseIssue>,
                     val minimumInstructionLength: Int, val defaultIsStmt: Boolean) {
    fun resolveFile(index: Int): String {
        if (index < 0 || index >= files.size) return "<unknown file #$index>"
        val f = files[index]
        val dir = if (f.dirIndex in dirs.indices) dirs[f.dirIndex] else ""
        return if (dir.isEmpty()) f.name else "$dir/${f.name}"
    }
}

/** Raw DIE entry retained for the inline tree / range index. */
class DieRecord(
    val offset: Int,
    val tag: Int,
    val parentOffset: Int,
    val depth: Int,
    val attrs: Map<Int, AttrValue>,
    var ranges: List<AddrRange> = emptyList(),
    var resolvedName: String? = null,
    var linkageName: String? = null,
    var callFileResolved: String? = null
) {
    val tagName: String get() = DieRecord.tagNames[tag] ?: "DW_TAG_0x${tag.toString(16)}"
    fun attr(a: Int): AttrValue? = attrs[a]

    companion object {
        val tagNames = mapOf(
            DW_TAG_compile_unit to "compile_unit", DW_TAG_skeleton_unit to "skeleton_unit",
            DW_TAG_type_unit to "type_unit", DW_TAG_partial_unit to "partial_unit",
            DW_TAG_subprogram to "subprogram", DW_TAG_inlined_subroutine to "inlined_subroutine",
            DW_TAG_lexical_block to "lexical_block"
        )
    }
}

class CuInfo(
    val offset: Long,
    val version: Int,
    val dwarf64: Boolean,
    val unitType: Int,
    val isSplit: Boolean,
    val dwoId: Long?,
    val compDir: String?,
    val name: String?,
    val lowPc: Long?,
    val ranges: List<AddrRange>,
    val dies: List<DieRecord>,
    val lineTable: LineTable?,
    val issues: MutableList<ParseIssue>,
    var dwoResolved: Boolean = false
) {
    val dieByOffset: Map<Int, DieRecord> = dies.associateBy { it.offset }

    fun cuRangeContains(addr: Long) = ranges.any { it.contains(addr) }

    /** Most specific DIE chain (leaf -> ancestors) covering [addr], or empty. */
    fun inlineChainAt(addr: Long): List<DieRecord> {
        val candidates = dies.filter { d ->
            (d.tag == DW_TAG_subprogram || d.tag == DW_TAG_inlined_subroutine ||
                d.tag == DW_TAG_lexical_block) && d.ranges.any { it.contains(addr) }
        }
        if (candidates.isEmpty()) return emptyList()
        val leaf = candidates.sortedWith(
            compareByDescending<DieRecord> { it.depth }
                .thenBy { d -> d.ranges.filter { it.contains(addr) }.minOf { it.length } }
                .thenBy { it.offset }
        ).first()
        val chain = mutableListOf<DieRecord>()
        var cur: DieRecord? = leaf
        val guard = HashSet<Int>()
        while (cur != null && guard.add(cur.offset)) {
            if (cur.tag == DW_TAG_compile_unit || cur.tag == DW_TAG_skeleton_unit) break
            chain += cur
            cur = dieByOffset[cur.parentOffset]
        }
        return chain
    }
}

/** Everything extracted from one ELF import (main binary or .dwo). */
class ParsedDebug(
    val elf: ElfFile,
    val cus: List<CuInfo>,
    val issues: List<ParseIssue>,
    val sectionsParsed: List<String>,
    val isDwo: Boolean,
    val dwoIds: Set<Long>
)
