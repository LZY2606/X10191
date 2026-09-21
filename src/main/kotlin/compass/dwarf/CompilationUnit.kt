package compass.dwarf

import compass.elf.Cursor
import compass.elf.SliceOutOfBoundsException

class CompilationUnit(
    val index: Int,
    val data: DwarfData,
    val isDwo: Boolean,
    val sectionOffset: Int,
    val version: Int,
    val unitLength: Long,
    val is64: Boolean,
    val abbrevOffset: Long,
    val addressSize: Int,
    val dwoId: ULong?,
    val root: Die,
    val abbrev: AbbrevTable,
    /** CU-relative offset of the DIE area (after the header). */
    val dieAreaStart: Int,
    val strOffsetsBase: Long,
    val addrBaseRelative: Long,
    val rnglistsBaseRelative: Long,
) {
    val name: String?
        get() = root.attr(Attr.NAME)?.value?.asString
            ?: root.attr(Attr.COMP_DIR)?.value?.asString
    val compDir: String? get() = root.attr(Attr.COMP_DIR)?.value?.asString
    val stmtList: Long? get() = root.attr(Attr.STMT_LIST)?.value?.asLong
}
