package compass.dwarf

object Tag {
    const val COMPILE_UNIT = 0x11L
    const val SUBPROGRAM = 0x2eL
    const val INLINED_SUBROUTINE = 0x1dL
    const val SKELETON_UNIT = 0x4aL
    fun name(t: Long) = when (t) {
        COMPILE_UNIT -> "DW_TAG_compile_unit"
        SUBPROGRAM -> "DW_TAG_subprogram"
        INLINED_SUBROUTINE -> "DW_TAG_inlined_subroutine"
        SKELETON_UNIT -> "DW_TAG_skeleton_unit"
        else -> "DW_TAG_0x${t.toString(16)}"
    }
}

object At {
    const val NAME = 0x03L
    const val LOW_PC = 0x11L
    const val HIGH_PC = 0x12L
    const val STMT_LIST = 0x10L
    const val COMP_DIR = 0x1bL
    const val RANGES = 0x55L
    const val CALL_FILE = 0x58L
    const val CALL_LINE = 0x59L
    const val CALL_COLUMN = 0x57L
    const val ABSTRACT_ORIGIN = 0x31L
    const val SPECIFICATION = 0x47L
    const val PRODUCER = 0x25L
    const val DWO_NAME = 0x76L
    const val ADDR_BASE = 0x73L
    const val RNG_LISTS_BASE = 0x74L
    const val STR_OFFSETS_BASE = 0x72L
    const val SIBLING = 0x01L
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

    val KNOWN = setOf(
        ADDR, BLOCK2, BLOCK4, DATA2, DATA4, DATA8, STRING, BLOCK, BLOCK1, DATA1,
        FLAG, SDATA, STRP, UDATA, REF_ADDR, REF1, REF2, REF4, REF8, REF_UDATA,
        INDIRECT, SEC_OFFSET, EXPLOC, FLAG_PRESENT, STRX, ADDRX, REF_SUP4, STRP_SUP,
        DATA16, LINE_STRP, REF_SIG8, IMPLICIT_CONST, LOCLISTX, RNGLISTX, REF_SUP8,
        STRX1, STRX2, STRX3, STRX4, ADDRX1, ADDRX2, ADDRX3, ADDRX4,
    )

    fun name(f: Long) = "DW_FORM_0x${f.toString(16)}"
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
}

object Lnct {
    const val PATH = 1L
    const val DIRECTORY_INDEX = 2L
    const val TIMESTAMP = 3L
    const val SIZE = 4L
    const val MD5 = 5L
}

object Rle {
    const val END_OF_LIST = 0
    const val BASE_ADDRESSX = 1
    const val STARTX_ENDX = 2
    const val STARTX_LENGTH = 3
    const val OFFSET_PAIR = 4
    const val BASE_ADDRESS = 5
    const val START_END = 6
    const val START_LENGTH = 7
}

object UnitType {
    const val COMPILE = 1
    const val SKELETON = 4
    const val SPLIT_COMPILE = 2
}

/** Hard safety limits so hostile or corrupt sections cannot hang or crash the parser. */
object Limits {
    const val MAX_DIE_DEPTH = 64
    const val MAX_DIES_PER_CU = 200_000
    const val MAX_REF_JUMPS = 32
    const val MAX_LINE_ROWS = 2_000_000
    const val MAX_ABBREV_ATTRS = 4_096
    const val MAX_RANGE_ENTRIES = 1_000_000
    const val MAX_INDIRECT_FORM = 8
}
