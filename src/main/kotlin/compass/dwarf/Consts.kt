package compass.dwarf

object Tag {
    const val COMPILE_UNIT = 0x11L
    const val SUBPROGRAM = 0x2eL
    const val INLINED_SUBROUTINE = 0x1dL
    const val LEXICAL_BLOCK = 0x0bL
    const val PARTIAL_UNIT = 0x3cL
    const val SKELETON_UNIT = 0x4aL
    val names = mapOf(
        0x11L to "compile_unit", 0x2eL to "subprogram", 0x1dL to "inlined_subroutine",
        0x0bL to "lexical_block", 0x3cL to "partial_unit", 0x4aL to "skeleton_unit",
        0x34L to "variable", 0x05L to "formal_parameter", 0x13L to "base_type",
    )
    fun name(tag: Long) = names[tag] ?: "tag_0x${tag.toString(16)}"
}

object At {
    const val SIBLING = 0x01L
    const val NAME = 0x03L
    const val STMT_LIST = 0x10L
    const val LOW_PC = 0x11L
    const val HIGH_PC = 0x12L
    const val COMP_DIR = 0x1bL
    const val PRODUCER = 0x25L
    const val ABSTRACT_ORIGIN = 0x31L
    const val SPECIFICATION = 0x47L
    const val RANGES = 0x55L
    const val CALL_FILE = 0x58L
    const val CALL_LINE = 0x59L
    const val CALL_COLUMN = 0x57L
    const val LINKAGE_NAME = 0x6eL
    // DWARF5
    const val STR_OFFSETS_BASE = 0x72L
    const val ADDR_BASE = 0x73L
    const val RNGLISTS_BASE = 0x74L
    const val DWO_NAME = 0x76L
    // GNU extensions
    const val GNU_DWO_NAME = 0x2130L
    const val GNU_DWO_ID = 0x2131L
    const val GNU_RANGES_BASE = 0x2132L
    const val GNU_ADDR_BASE = 0x2133L
    val names = mapOf(
        SIBLING to "sibling", NAME to "name", STMT_LIST to "stmt_list", LOW_PC to "low_pc",
        HIGH_PC to "high_pc", COMP_DIR to "comp_dir", PRODUCER to "producer",
        ABSTRACT_ORIGIN to "abstract_origin", SPECIFICATION to "specification",
        RANGES to "ranges", CALL_FILE to "call_file", CALL_LINE to "call_line",
        CALL_COLUMN to "call_column", LINKAGE_NAME to "linkage_name",
        STR_OFFSETS_BASE to "str_offsets_base", ADDR_BASE to "addr_base",
        RNGLISTS_BASE to "rnglists_base", DWO_NAME to "dwo_name",
        GNU_DWO_NAME to "GNU_dwo_name", GNU_ADDR_BASE to "GNU_addr_base",
        GNU_RANGES_BASE to "GNU_ranges_base",
    )
    fun name(at: Long) = names[at] ?: "at_0x${at.toString(16)}"
}

object Form {
    const val ADDR = 0x01L
    const val BLOCK2 = 0x03L
    const val BLOCK4 = 0x04L
    const val DATA2 = 0x05L
    const val DATA4 = 0x06L
    const val DATA8 = 0x07L
    const val STRING = 0x08L
    const val BLOCK = 0x09L
    const val BLOCK1 = 0x0aL
    const val DATA1 = 0x0bL
    const val FLAG = 0x0cL
    const val SDATA = 0x0dL
    const val STRP = 0x0eL
    const val UDATA = 0x0fL
    const val REF_ADDR = 0x10L
    const val REF1 = 0x11L
    const val REF2 = 0x12L
    const val REF4 = 0x13L
    const val REF8 = 0x14L
    const val REF_UDATA = 0x15L
    const val INDIRECT = 0x16L
    const val SEC_OFFSET = 0x17L
    const val EXPLOC = 0x18L
    const val FLAG_PRESENT = 0x19L
    const val STRX = 0x1aL
    const val ADDRX = 0x1bL
    const val REF_SUP4 = 0x1cL
    const val STRP_SUP = 0x1dL
    const val DATA16 = 0x1eL
    const val LINE_STRP = 0x1fL
    const val REF_SIG8 = 0x20L
    const val IMPLICIT_CONST = 0x21L
    const val LOCLISTX = 0x22L
    const val RNGLISTX = 0x23L
    const val REF_SUP8 = 0x24L
    const val STRX1 = 0x25L
    const val STRX2 = 0x26L
    const val STRX3 = 0x27L
    const val STRX4 = 0x28L
    const val ADDRX1 = 0x29L
    const val ADDRX2 = 0x2aL
    const val ADDRX3 = 0x2bL
    const val ADDRX4 = 0x2cL
    const val GNU_ADDR_INDEX = 0x1f01L
    const val GNU_STR_INDEX = 0x1f02L
    val names = mapOf(
        ADDR to "addr", BLOCK2 to "block2", BLOCK4 to "block4", DATA2 to "data2",
        DATA4 to "data4", DATA8 to "data8", STRING to "string", BLOCK to "block",
        BLOCK1 to "block1", DATA1 to "data1", FLAG to "flag", SDATA to "sdata",
        STRP to "strp", UDATA to "udata", REF_ADDR to "ref_addr", REF1 to "ref1",
        REF2 to "ref2", REF4 to "ref4", REF8 to "ref8", REF_UDATA to "ref_udata",
        INDIRECT to "indirect", SEC_OFFSET to "sec_offset", EXPLOC to "exprloc",
        FLAG_PRESENT to "flag_present", STRX to "strx", ADDRX to "addrx",
        LINE_STRP to "line_strp", REF_SIG8 to "ref_sig8", IMPLICIT_CONST to "implicit_const",
        RNGLISTX to "rnglistx", STRX1 to "strx1", STRX2 to "strx2", STRX3 to "strx3",
        STRX4 to "strx4", ADDRX1 to "addrx1", ADDRX2 to "addrx2", ADDRX3 to "addrx3",
        ADDRX4 to "addrx4", DATA16 to "data16",
    )
    fun name(form: Long) = names[form] ?: "form_0x${form.toString(16)}"
}

object Lns {
    const val COPY = 1
    const val ADVANCE_PC = 2
    const val ADVANCE_LINE = 3
    const val SET_FILE = 4
    const val SET_COLUMN = 5
    const val NEGATE_STMT = 6
    const val SET_BASIC_BLOCK = 7
    const val CONST_ADD_PC = 8
    const val FIXED_ADVANCE_PC = 9
    const val SET_PROLOGUE_END = 10
    const val SET_EPILOGUE_BEGIN = 11
    const val SET_ISA = 12
}

object Lne {
    const val END_SEQUENCE = 1
    const val SET_ADDRESS = 2
    const val DEFINE_FILE = 3
    const val SET_DISCRIMINATOR = 4
    const val LO_USER = 0x80
    const val HI_USER = 0xff
}

object Rle {
    const val END_OF_LIST = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val STARTX_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val START_END = 0x06
    const val START_LENGTH = 0x07
}

object UnitType {
    const val COMPILE = 0x01
    const val TYPE = 0x02
    const val PARTIAL = 0x03
    const val SKELETON = 0x04
    const val SPLIT_COMPILE = 0x05
    fun name(ut: Int?) = when (ut) {
        COMPILE -> "compile"; TYPE -> "type"; PARTIAL -> "partial"
        SKELETON -> "skeleton"; SPLIT_COMPILE -> "split_compile"
        null -> "compile(dwarf4)"
        else -> "ut_$ut"
    }
}
