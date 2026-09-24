package compass.dwarf

object Tag {
    const val COMPILE_UNIT = 0x11L
    const val SUBPROGRAM = 0x2eL
    const val INLINED_SUBROUTINE = 0x1dL
    const val PARTIAL_UNIT = 0x3cL
    const val TYPE_UNIT = 0x41L
    fun name(t: Long) = when (t) {
        COMPILE_UNIT -> "DW_TAG_compile_unit"
        SUBPROGRAM -> "DW_TAG_subprogram"
        INLINED_SUBROUTINE -> "DW_TAG_inlined_subroutine"
        PARTIAL_UNIT -> "DW_TAG_partial_unit"
        TYPE_UNIT -> "DW_TAG_type_unit"
        else -> "DW_TAG_0x${t.toString(16)}"
    }
}

object Attr {
    const val NAME = 0x03L
    const val LOW_PC = 0x11L
    const val HIGH_PC = 0x12L
    const val STMT_LIST = 0x10L
    const val COMP_DIR = 0x1bL
    const val RANGES = 0x55L
    const val PRODUCER = 0x25L
    const val CALL_FILE = 0x58L
    const val CALL_LINE = 0x59L
    const val CALL_COLUMN = 0x57L
    const val ABSTRACT_ORIGIN = 0x31L
    const val SPECIFICATION = 0x47L
    const val DWO_NAME = 0x76L
    const val DWO_ID = 0x75L
    const val ADDR_BASE = 0x73L
    const val RNGLISTS_BASE = 0x74L
    const val STR_OFFSETS_BASE = 0x72L
    const val LINKAGE_NAME = 0x6fL
    const val ENTRY_PC = 0x52L
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

    fun name(f: Long) = "DW_FORM_0x${f.toString(16)}"
}

object UnitType {
    const val COMPILE = 1
    const val SKELETON = 4
    const val SPLIT_COMPILE = 2
}

object RngListEntry {
    const val END_OF_LIST = 0x00
    const val BASE_ADDRESSX = 0x01
    const val STARTX_ENDX = 0x02
    const val STARTX_LENGTH = 0x03
    const val OFFSET_PAIR = 0x04
    const val BASE_ADDRESS = 0x05
    const val START_END = 0x06
    const val START_LENGTH = 0x07
}
