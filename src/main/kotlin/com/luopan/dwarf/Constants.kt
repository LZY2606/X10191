package com.luopan.dwarf

object DwarfTag {
    const val COMPILE_UNIT = 0x11
    const val TYPE_UNIT = 0x41
    const val SKELETON_UNIT = 0x41 // DWARF5: unit type encoded in header, tag stays compile_unit
    const val SUBPROGRAM = 0x2e
    const val INLINED_SUBROUTINE = 0x1d
    const val ENTRY_POINT = 0x1e
    const val LEXICAL_BLOCK = 0x0b
    fun name(tag: Int): String = when (tag) {
        COMPILE_UNIT -> "DW_TAG_compile_unit"
        TYPE_UNIT -> "DW_TAG_type_unit"
        SUBPROGRAM -> "DW_TAG_subprogram"
        INLINED_SUBROUTINE -> "DW_TAG_inlined_subroutine"
        ENTRY_POINT -> "DW_TAG_entry_point"
        LEXICAL_BLOCK -> "DW_TAG_lexical_block"
        else -> "DW_TAG_0x%x".format(tag)
    }
}

object DwarfAttr {
    const val SIBLING = 0x01
    const val NAME = 0x03
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val STMT_LIST = 0x10
    const val COMP_DIR = 0x1b
    const val RANGES = 0x55
    const val ABSTRACT_ORIGIN = 0x31
    const val SPECIFICATION = 0x47
    const val INLINE = 0x20
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val DECL_FILE = 0x3a
    const val DECL_LINE = 0x39
    const val DECL_COLUMN = 0x3b
    const val TYPE = 0x49
    const val LANGUAGE = 0x13
    const val PRODUCER = 0x25
    const val STR_OFFSETS_BASE = 0x72
    const val ADDR_BASE = 0x73
    const val RANGES_BASE = 0x74
    const val STR_BASE = 0x72
    const val DWO_NAME = 0x76
    const val DWO_ID = 0x2135 // GNU extension
    const val GNU_DWO_NAME = 0x2130
    const val GNU_DWO_ID = 0x2134
    const val GNU_ADDR_BASE = 0x2133
    const val GNU_STR_OFFSETS_BASE = 0x2132
    const val LOCATION = 0x02
    const val EXTERNAL = 0x3f
    const val ARTIFICIAL = 0x34
    const val DECLARATION = 0x3c
    const val FRAME_BASE = 0x40
    const val ENTRY_PC = 0x52
}

object DwarfForm {
    const val ADDR = 0x01
    const val REF1 = 0x11
    const val REF2 = 0x12
    const val REF4 = 0x13
    const val REF8 = 0x14
    const val REF_UDATA = 0x15
    const val REF_SIG8 = 0x20
    const val DATA1 = 0x0b
    const val DATA2 = 0x05
    const val DATA4 = 0x06
    const val DATA8 = 0x07
    const val DATA_SDATA = 0x0d
    const val DATA_UDATA = 0x0f
    const val STRING = 0x08
    const val STRP = 0x0e
    const val LINE_STRP = 0x1f
    const val BLOCK = 0x09
    const val BLOCK1 = 0x0a
    const val BLOCK2 = 0x03
    const val BLOCK4 = 0x04
    const val BLOCK8 = 0x0c
    const val EXPRLOC = 0x18
    const val FLAG = 0x0c
    const val FLAG_PRESENT = 0x19
    const val SEC_OFFSET = 0x17
    const val STRX = 0x1a
    const val STRX1 = 0x25
    const val STRX2 = 0x26
    const val STRX3 = 0x27
    const val STRX4 = 0x28
    const val ADDRX = 0x1b
    const val ADDRX1 = 0x21
    const val ADDRX2 = 0x22
    const val ADDRX3 = 0x23
    const val ADDRX4 = 0x24
    const val INDIRECT = 0x16
    const val IMPLICIT_CONST = 0x21
    const val GNU_STR_INDEX = 0x1f00 + 0x2a
    const val GNU_ADDR_INDEX = 0x1f00 + 0x2b
    const val GNU_STR_OFFSET = 0x1f01
}

object DwarfUnitType {
    const val COMPILE = 0x01
    const val TYPE = 0x02
    const val PARTIAL = 0x03
    const val SKELETON = 0x04
    const val SPLIT_COMPILE = 0x05
    const val SPLIT_TYPE = 0x06
    fun name(v: Int): String = when (v) {
        COMPILE -> "DW_UT_compile"
        TYPE -> "DW_UT_type"
        PARTIAL -> "DW_UT_partial"
        SKELETON -> "DW_UT_skeleton"
        SPLIT_COMPILE -> "DW_UT_split_compile"
        SPLIT_TYPE -> "DW_UT_split_type"
        else -> "DW_UT_0x%x".format(v)
    }
}

object DwarfLineContent {
    const val PATH = 1
    const val DIRECTORY_INDEX = 2
    const val TIMESTAMP = 3
    const val SIZE = 4
    const val MD5 = 5
}
