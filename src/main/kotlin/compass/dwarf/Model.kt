package compass.dwarf

import compass.elf.ByteSlice
import compass.elf.ElfFile

/** Byte view of a section inside an ELF image. */
class SectionView(val data: ByteArray, val off: Int, val len: Int) {
    fun slice(): ByteSlice = ByteSlice(data, off, len)
    fun cstring(rel: Int): String? = readCString(slice(), rel)
}

class DebugSections(
    val info: SectionView?,
    val abbrev: SectionView?,
    val line: SectionView?,
    val lineStr: SectionView?,
    val str: SectionView?,
    val strOffsets: SectionView?,
    val ranges: SectionView?,
    val rnglists: SectionView?,
    val addr: SectionView?,
    val infoDwo: SectionView?,
    val abbrevDwo: SectionView?,
    val strDwo: SectionView?,
    val strOffsetsDwo: SectionView?,
    val lineDwo: SectionView?,
    val lineStrDwo: SectionView?,
    val sourceName: String
) {
    fun resolveString(rel: Int): String? {
        str?.cstring(rel)?.let { return it }
        strDwo?.cstring(rel)?.let { return it }
        return null
    }
    fun strOffsetsFor(dwo: Boolean): SectionView? =
        if (dwo) (strOffsetsDwo ?: strOffsets) else (strOffsets ?: strOffsetsDwo)

    fun resolveLineString(rel: Int): String? {
        lineStr?.cstring(rel)?.let { return it }
        lineStrDwo?.cstring(rel)?.let { return it }
        return null
    }

    companion object {
        fun fromElf(elf: ElfFile, split: DebugSections? = null, sourceName: String = ""): DebugSections {
            fun v(name: String, other: SectionView?): SectionView? {
                val s = elf.section(name)?.bytes ?: return other
                return SectionView(s.data, s.offset, s.length)
            }
            return DebugSections(
                info = v(".debug_info", null),
                abbrev = v(".debug_abbrev", null),
                line = v(".debug_line", null),
                lineStr = v(".debug_line_str", null),
                str = v(".debug_str", null),
                strOffsets = v(".debug_str_offsets", null),
                ranges = v(".debug_ranges", null),
                rnglists = v(".debug_rnglists", null),
                addr = v(".debug_addr", null),
                infoDwo = v(".debug_info.dwo", split?.infoDwo),
                abbrevDwo = v(".debug_abbrev.dwo", split?.abbrevDwo),
                strDwo = v(".debug_str.dwo", split?.strDwo),
                strOffsetsDwo = v(".debug_str_offsets.dwo", split?.strOffsetsDwo),
                lineDwo = v(".debug_line.dwo", split?.lineDwo),
                lineStrDwo = v(".debug_line_str.dwo", split?.lineStrDwo),
                sourceName = sourceName
            )
        }
    }
}

fun readCString(slice: ByteSlice, offset: Int): String? {
    if (offset < 0 || offset >= slice.length) return null
    var p = slice.offset + offset
    val limit = slice.offset + slice.length
    while (p < limit && slice.data[p] != 0.toByte()) p++
    if (p >= limit) return null
    return String(slice.data, slice.offset + offset, p - (slice.offset + offset), Charsets.UTF_8)
}

// ---- attribute values ----

sealed class AttrValue {
    data class Num(val v: Long) : AttrValue()
    data class Str(val text: String) : AttrValue()
    data class Ref(val cuRelative: Long) : AttrValue()
    data class SecOffset(val offset: Long) : AttrValue()
    data class AddrIndex(val index: Long) : AttrValue()
    data class RngIndex(val index: Long) : AttrValue()
    data class Unknown(val form: Int) : AttrValue()
}

data class Attr(val name: Int, val form: Int, val value: AttrValue)

class Die(
    val globalOffset: Long,
    val tag: Int,
    val attrs: Map<Int, Attr>,
    val children: List<Die>
) {
    lateinit var cu: CompilationUnit
        internal set
    fun num(name: Int): Long? = (attrs[name]?.value as? AttrValue.Num)?.v
    fun str(name: Int): String? = (attrs[name]?.value as? AttrValue.Str)?.text
    fun ref(name: Int): Long? = (attrs[name]?.value as? AttrValue.Ref)?.cuRelative

    val inlineCode: Long get() = num(DW_AT_inline) ?: 0L
    val isInlinedSubroutine: Boolean get() = tag == DW_TAG_inlined_subroutine
    val isSubprogram: Boolean get() = tag == DW_TAG_subprogram
    val isConcrete: Boolean get() = attrs.containsKey(DW_AT_abstract_origin) ||
        attrs.containsKey(DW_AT_specification)
}

class LineRow(
    val address: Long, val file: Int, val line: Int, val column: Int,
    val endSequence: Boolean, val isStmt: Boolean, val basicBlock: Boolean,
    val prologueEnd: Boolean, val epilogueBegin: Boolean,
    val isa: Int, val discriminator: Int, val opIndex: Int
)

class LineSequence(val rows: List<LineRow>) {
    val start: Long get() = rows.first().address
    val end: Long get() = rows.last().address
    fun contains(addr: Long): Boolean = rows.size >= 2 && addr in start until end
}

class LineFile(val name: String, val dirIndex: Int)

class LineProgram(
    val version: Int,
    val files: List<LineFile>,
    val directories: List<String>,
    val sequences: List<LineSequence>,
    val addressSize: Int,
    val segmentSelectorSize: Int
)

class PcRange(val low: Long, val high: Long, val zeroLength: Boolean = low == high) {
    fun contains(addr: Long): Boolean = if (zeroLength) addr == low else addr in low until high
    val width: Long get() = high - low
}

class CompilationUnit(
    val offset: Long,
    val length: Long,
    val version: Int,
    val dwarf64: Boolean,
    val isSplit: Boolean,
    val unitType: Int,
    val abbrevOffset: Long,
    val addressSize: Int,
    val segmentSize: Int,
    val dwoId: Long?,
    val dwoName: String?,
    val compDir: String?,
    val name: String?,
    val root: Die?,
    val lineProgram: LineProgram?,
    val ranges: List<PcRange>,
    val issues: MutableList<String>,
    val strOffsetsBase: Long,
    val addrBase: Long,
    val rnglistsBase: Long
) {
    /** Offset of the first DIE relative to the CU start (header length). */
    fun dieHeaderLength(): Long =
        if (version >= 5) (if (dwarf64) 27 else 23) else (if (dwarf64) 15 else 11)

    val tableVersion: String get() = "DWARF$version" + if (unitType == DW_UT_skeleton) " skeleton"
        else if (unitType == DW_UT_split_compile || isSplit) " split" else ""
}

class SectionIssue(val section: String, val unitOffset: Long?, val message: String)

class DebugInfo(
    val units: List<CompilationUnit>,
    val issues: List<SectionIssue>,
    val splitStatus: SplitStatus
)

enum class SplitStatus { NONE, RESOLVED, MISSING_DWO }

// ---- DWARF constants ----
const val DW_TAG_compile_unit = 0x11
const val DW_TAG_subprogram = 0x2e
const val DW_TAG_inlined_subroutine = 0x1d
const val DW_TAG_skeleton_unit = 0x4a

const val DW_AT_name = 0x03
const val DW_AT_stmt_list = 0x10
const val DW_AT_low_pc = 0x11
const val DW_AT_high_pc = 0x12
const val DW_AT_comp_dir = 0x1b
const val DW_AT_ranges = 0x55
const val DW_AT_inline = 0x20
const val DW_AT_abstract_origin = 0x31
const val DW_AT_specification = 0x29
const val DW_AT_call_line = 0x6b
const val DW_AT_call_column = 0x57
const val DW_AT_call_file = 0x58
const val DW_AT_GNU_dwo_name = 0x2130
const val DW_AT_dwo_name = 0x76
const val DW_AT_GNU_dwo_id = 0x2131
const val DW_AT_GNU_addr_base = 0x2133
const val DW_AT_str_offsets_base = 0x72
const val DW_AT_addr_base = 0x57
const val DW_AT_rnglists_base = 0x74
const val DW_AT_linkage_name = 0x6e
const val DW_AT_MIPS_linkage_name = 0x2007

const val DW_FORM_addr = 0x01
const val DW_FORM_block2 = 0x03
const val DW_FORM_block4 = 0x04
const val DW_FORM_data2 = 0x05
const val DW_FORM_data4 = 0x06
const val DW_FORM_data8 = 0x07
const val DW_FORM_string = 0x08
const val DW_FORM_block = 0x09
const val DW_FORM_block1 = 0x0a
const val DW_FORM_data1 = 0x0b
const val DW_FORM_flag = 0x0c
const val DW_FORM_sdata = 0x0d
const val DW_FORM_strp = 0x0e
const val DW_FORM_udata = 0x0f
const val DW_FORM_ref_addr = 0x10
const val DW_FORM_ref1 = 0x11
const val DW_FORM_ref2 = 0x12
const val DW_FORM_ref4 = 0x13
const val DW_FORM_ref8 = 0x14
const val DW_FORM_ref_udata = 0x15
const val DW_FORM_indirect = 0x16
const val DW_FORM_sec_offset = 0x17
const val DW_FORM_exprloc = 0x18
const val DW_FORM_flag_present = 0x19
const val DW_FORM_strx = 0x1a
const val DW_FORM_addrx = 0x1b
const val DW_FORM_ref_sup4 = 0x1c
const val DW_FORM_strp_sup = 0x1d
const val DW_FORM_data16 = 0x1e
const val DW_FORM_line_strp = 0x1f
const val DW_FORM_ref_sig8 = 0x20
const val DW_FORM_implicit_const = 0x21
const val DW_FORM_loclistx = 0x22
const val DW_FORM_rnglistx = 0x23
const val DW_FORM_strx1 = 0x25
const val DW_FORM_strx2 = 0x26
const val DW_FORM_strx3 = 0x27
const val DW_FORM_strx4 = 0x29
const val DW_FORM_addrx1 = 0x30
const val DW_FORM_addrx2 = 0x31
const val DW_FORM_addrx3 = 0x32
const val DW_FORM_addrx4 = 0x33

const val DW_UT_compile = 0x01
const val DW_UT_skeleton = 0x04
const val DW_UT_split_compile = 0x05

const val DW_LNS_copy = 0x01
const val DW_LNS_advance_pc = 0x02
const val DW_LNS_advance_line = 0x03
const val DW_LNS_set_file = 0x04
const val DW_LNS_set_column = 0x05
const val DW_LNS_negate_stmt = 0x06
const val DW_LNS_set_basic_block = 0x07
const val DW_LNS_const_add_pc = 0x08
const val DW_LNS_fixed_advance_pc = 0x09
const val DW_LNS_set_prologue_end = 0x0a
const val DW_LNS_set_epilogue_begin = 0x0a
const val DW_LNS_set_isa = 0x0c

const val DW_LNE_end_sequence = 0x01
const val DW_LNE_set_address = 0x02
const val DW_LNE_define_file = 0x03
const val DW_LNE_set_discriminator = 0x04

const val DW_LNCT_path = 0x1
const val DW_LNCT_directory_index = 0x2

const val DW_RLE_end_of_list = 0x00
const val DW_RLE_base_addressx = 0x01
const val DW_RLE_startx_endx = 0x02
const val DW_RLE_startx_length = 0x03
const val DW_RLE_offset_pair = 0x04
const val DW_RLE_base_address = 0x05
const val DW_RLE_start_end = 0x06
const val DW_RLE_start_length = 0x07
