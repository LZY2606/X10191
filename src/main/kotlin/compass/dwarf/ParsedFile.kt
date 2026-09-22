package compass.dwarf

import compass.elf.ElfFile

/** A code-bearing scope DIE (subprogram / inlined subroutine / entry point). */
class ScopeDie(
    val unit: CompUnit,
    val die: DieNode,
    /** Flattened ranges from low_pc/high_pc or a range list. */
    val ranges: List<AddressRange>,
    /** 0 for concrete subprograms; inlined_subroutine depth within its chain. */
    val inlineDepth: Int
) {
    val globalKey: String get() = "${unit.fileId}:${unit.unitOffset}:${die.offset}"
}

/** Full parse outcome for one imported ELF file. */
class ParsedFile(
    val id: Long,
    val elf: ElfFile,
    val sections: DwarfSections,
    val ctx: ParseContext,
    val units: List<CompUnit>,
    val fileIssues: MutableList<ParseIssue> = mutableListOf(),
    val scopes: MutableList<ScopeDie> = mutableListOf(),
    /** (CU, parsed line program) cache, populated lazily. */
    val lineCache: HashMap<Long, LineProgram> = HashMap(),
    var linked: Boolean = false
) {
    val sha256: String get() = elf.fileSha256

    fun allIssues(): List<ParseIssue> = fileIssues + units.flatMap { it.issues }

    fun unitAtOffset(offset: Long): CompUnit? =
        units.firstOrNull { offset in it.unitOffset until it.nextOffset }

    /** Resolve a section-global info offset within this file. */
    fun dieAtGlobalOffset(offset: Long): Pair<CompUnit, DieNode>? {
        val unit = unitAtOffset(offset) ?: return null
        return unit.findDie(offset)?.let { unit to it }
    }

    /** Parse (or reuse) the line program referenced by a CU's DW_AT_stmt_list. */
    fun lineProgramFor(unit: CompUnit): LineProgram? {
        val stmt = unit.root.attr(DW.AT_stmt_list)?.value as? FormValue.SectionOffset ?: return null
        return lineCache.getOrPut(stmt.value) {
            val sec = sections.line
                ?: throw DwarfParseException("DW_AT_stmt_list present but no .debug_line")
            LineParser(sec, { idx -> resolveUnitStrx(unit, idx) }, { off ->
                sections.lineStr?.stringAt(off.toInt())
            }).parseAt(stmt.value)
        }
    }

    private fun resolveUnitStrx(unit: CompUnit, idx: Long): String? {
        // strx in line header indexes same str_offsets contribution as the CU
        val so = sections.strOffsets ?: return null
        val base = unit.strOffsetsBase
        val entrySize = unit.addressSize.coerceAtLeast(4)
        val at = (base + idx * entrySize).toInt()
        if (at + entrySize > so.size) return null
        val rr = so.subReader(at, entrySize)
        val strOff = if (entrySize == 4) rr.u4().toLong() and 0xffffffffL else rr.u8()
        return sections.str?.stringAt(strOff.toInt())
    }
}
