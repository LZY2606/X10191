@file:Suppress("ArrayInDataClass")
package compass.dwarf

import compass.elf.ByteReader
import compass.elf.ElfFile

/** Anything that went wrong while parsing a unit, kept with the result. */
data class ParseIssue(val severity: String, val where: String, val message: String)

/** Resolved value carried by one DIE attribute. */
sealed class FormValue {
    data class Address(val value: Long) : FormValue()
    data class Number(val value: Long, val signed: Boolean = false) : FormValue()
    data class Text(val value: String) : FormValue()
    data class Blob(val value: ByteArray) : FormValue()
    /** Offset into some debug info section (local CU / global / type signature). */
    data class Reference(val offset: Long, val kind: RefKind) : FormValue()
    data class SectionOffset(val value: Long) : FormValue()
    data class Flag(val value: Boolean) : FormValue()
    /** Resolved after skeleton<->split linking (DW_FORM_addrx in a .dwo). */
    data class DeferredAddrIndex(val index: Long) : FormValue()
    data class DeferredStrIndex(val index: Long) : FormValue()
    /** Form recognised by constant but unsupported in this implementation. */
    data class UnsupportedForm(val form: Int) : FormValue()
}

enum class RefKind { LOCAL_INFO, GLOBAL_INFO, TYPE_SIGNATURE, EXTERNAL_SUP }

data class DieAttribute(val attr: Int, val form: Int, var value: FormValue)

class DieNode(
    val offset: Long,
    val tag: Int,
    val parent: DieNode?,
    val children: MutableList<DieNode> = mutableListOf(),
    val attributes: MutableMap<Int, DieAttribute> = LinkedHashMap()
) {
    var depth: Int = 0
        internal set
    val isScopeWithCode: Boolean
        get() = tag == DW.TAG_subprogram || tag == DW.TAG_inlined_subroutine ||
            tag == DW.TAG_entry_point

    fun attr(a: Int): DieAttribute? = attributes[a]
    fun num(a: Int): Long? = (attr(a)?.value as? FormValue.Number)?.value
        ?: (attr(a)?.value as? FormValue.Address)?.value
}

/** One resolved [start,end) code range, potentially zero length. */
data class AddressRange(val start: Long, val end: Long, val segment: Int = 0) {
    val length: Long get() = end - start
    val zeroLength: Boolean get() = end == start
    fun contains(addr: Long): Boolean = addr in start until end
    /** Zero-length ranges only match their exact start address. */
    fun matches(addr: Long): Boolean = if (zeroLength) addr == start else contains(addr)
}

/** Header of one .debug_info (or .debug_info.dwo) compilation/type unit. */
class CompUnit(
    val fileId: Long,
    val isDwoFile: Boolean,
    val unitOffset: Long,
    val length: Long,
    val version: Int,
    val unitType: Int,
    val addressSize: Int,
    val debugAbbrevOffset: Long,
    val nextOffset: Long,
    val dwoId: Long?,
    val typeSignature: Long?,
    val typeOffset: Long?,
    val root: DieNode,
    val issues: MutableList<ParseIssue> = mutableListOf(),
    /** DIEs keyed by section-global offset (for reference resolution). */
    val diesByOffset: MutableMap<Long, DieNode> = LinkedHashMap(),
    var strOffsetsBase: Long = 0,
    var addrBase: Long = 0,
    var rnglistsBase: Long = 0,
    /** Set for skeleton CUs once a matching split unit is found. */
    var linkedDwoFileId: Long? = null,
    var linkedDwoUnitOffset: Long? = null
) {
    val tag: Int get() = root.tag
    val isSkeleton: Boolean
        get() = version >= 5 && tag == DW.TAG_skeleton_unit ||
            (version <= 4 && root.attr(DW.AT_GNU_dwo_name) != null)
    val isSplit: Boolean
        get() = version >= 5 && tag == DW.TAG_split_compile_unit ||
            (version <= 4 && isDwoFile && tag == DW.TAG_compile_unit)

    fun name(): String? = rootStringAttr(DW.AT_name)
    fun compDir(): String? = rootStringAttr(DW.AT_comp_dir)
    fun dwoName(): String? = rootStringAttr(DW.AT_dwo_name) ?: rootStringAttr(DW.AT_GNU_dwo_name)

    private fun rootStringAttr(a: Int): String? = (root.attr(a)?.value as? FormValue.Text)?.value

    fun findDie(globalOffset: Long): DieNode? = diesByOffset[globalOffset]
}

/** Accessor bundle for the (possibly suffixed) DWARF sections of one ELF file. */
class DwarfSections(val elf: ElfFile) {
    private fun reader(name: String): ByteReader? = elf.dwarfSection(name)?.let { ByteReader(it.data) }

    val info: ByteReader? = reader(".debug_info")
    val abbrev: ByteReader? = reader(".debug_abbrev")
    val line: ByteReader? = reader(".debug_line")
    val str: ByteReader? = reader(".debug_str")
    val strOffsets: ByteReader? = reader(".debug_str_offsets")
    val addr: ByteReader? = reader(".debug_addr")
    val lineStr: ByteReader? = reader(".debug_line_str")
    val ranges: ByteReader? = reader(".debug_ranges")
    val rnglists: ByteReader? = reader(".debug_rnglists")

    val isDwoContainer: Boolean = elf.dwarfSection(".debug_info.dwo") != null

    fun hasAny(): Boolean = info != null
}
