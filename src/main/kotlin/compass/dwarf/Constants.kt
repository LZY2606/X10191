package compass.dwarf

/** DWARF 常量：标签 / 属性 / 表单 / 行号操作码等。 */
object DW {
    const val TAG_COMPILE_UNIT = 0x11
    const val TAG_SUBPROGRAM = 0x2e
    const val TAG_INLINED_SUBROUTINE = 0x1d
    const val TAG_LEXICAL_BLOCK = 0x0b
    const val TAG_PARTIAL_UNIT = 0x3c
    const val TAG_SKELETON_UNIT = 0x41

    const val AT_NAME = 0x03
    const val AT_LINKAGE_NAME = 0x6e
    const val AT_LOW_PC = 0x11
    const val AT_HIGH_PC = 0x12
    const val AT_STMT_LIST = 0x10
    const val AT_COMP_DIR = 0x1b
    const val AT_RANGES = 0x55
    const val AT_RNGLISTS = 0x63
    const val AT_ABSTRACT_ORIGIN = 0x31
    const val AT_SPECIFICATION = 0x47
    const val AT_INLINE = 0x20
    const val AT_CALL_FILE = 0x58
    const val AT_CALL_LINE = 0x59
    const val AT_CALL_COLUMN = 0x57
    const val AT_SIBLING = 0x01
    const val AT_EXTERNAL = 0x3f
    const val AT_LANGUAGE = 0x13
    const val AT_ENCODING = 0x3e
    const val AT_PRODUCER = 0x25
    const val AT_ADDR_BASE = 0x73
    const val AT_RNGLISTX = 0x61
    const val AT_GNU_DWO_NAME = 0x2130
    const val AT_GNU_DWO_ID = 0x2131
    const val AT_DWO_NAME = 0x76
    const val AT_DWO_ID = 0x2000 // placeholder, not a real DW_AT; unused
    const val AT_STRN_OFFSETS_BASE = 0x72

    // forms
    const val FORM_ADDR = 0x01
    const val FORM_BLOCK2 = 0x03
    const val FORM_BLOCK4 = 0x04
    const val FORM_DATA2 = 0x05
    const val FORM_DATA4 = 0x06
    const val FORM_DATA8 = 0x07
    const val FORM_STRING = 0x08
    const val FORM_BLOCK = 0x09
    const val FORM_BLOCK1 = 0x0a
    const val FORM_DATA1 = 0x0b
    const val FORM_FLAG = 0x0c
    const val FORM_SDATA = 0x0d
    const val FORM_STRP = 0x0e
    const val FORM_UDATA = 0x0f
    const val FORM_REF_ADDR = 0x10
    const val FORM_REF1 = 0x11
    const val FORM_REF2 = 0x12
    const val FORM_REF4 = 0x13
    const val FORM_REF8 = 0x14
    const val FORM_REF_UDATA = 0x15
    const val FORM_INDIRECT = 0x16
    const val FORM_SEC_OFFSET = 0x17
    const val FORM_EXPRLOC = 0x18
    const val FORM_FLAG_PRESENT = 0x19
    const val FORM_STRX = 0x1a
    const val FORM_ADDRX = 0x1b
    const val FORM_REF_SUP4 = 0x1c
    const val FORM_STRP_SUP = 0x1d
    const val FORM_DATA16 = 0x1e
    const val FORM_LINE_STRP = 0x1f
    const val FORM_REF_SIG8 = 0x20
    const val FORM_IMPLICIT_CONST = 0x21
    const val FORM_LOCLISTX = 0x22
    const val FORM_RNGLISTX = 0x23
    const val FORM_REF_SUP8 = 0x24
    const val FORM_STRX1 = 0x25
    const val FORM_STRX2 = 0x26
    const val FORM_STRX3 = 0x27
    const val FORM_STRX4 = 0x28
    const val FORM_ADDRX1 = 0x29
    const val FORM_ADDRX2 = 0x2a
    const val FORM_ADDRX3 = 0x2b
    const val FORM_ADDRX4 = 0x2c
    const val FORM_GNU_ADDRX = 0x1f01
    const val FORM_GNU_STRX = 0x1f20
    const val FORM_GNU_RANGELISTX = 0x1f21

    const val LN_COPY = 0x01
    const val LN_ADVANCE_PC = 0x02
    const val LN_ADVANCE_LINE = 0x03
    const val LN_SET_FILE = 0x04
    const val LN_SET_COLUMN = 0x05
    const val LN_NEGATE_STMT = 0x06
    const val LN_SET_BASIC_BLOCK = 0x07
    const val LN_CONST_ADD_PC = 0x08
    const val LN_FIXED_ADVANCE_PC = 0x09
    const val LN_SET_PROLOGUE_END = 0x0a
    const val LN_SET_ISA = 0x0b
    // v5
    const val LN_SET_ISA5 = 0x0d
    const val LN_5_SET_FILE = 0x04 // same numeric value in v5 context
    // extended
    const val LNE_END_SEQUENCE = 0x01
    const val LNE_SET_ADDRESS = 0x02
    const val LNE_DEFINE_FILE = 0x03
    const val LNE_SET_DISCRIMINATOR = 0x04
    const val LNE_SET_SEGMENT = 0x05 // v5 extended op 5 (DW_LNE_set_address in v4 is 2)

    // rnglists
    const val RLE_END_OF_LIST = 0x00
    const val RLE_BASE_ADDRESSX = 0x01
    const val RLE_STARTX_ENDX = 0x02
    const val RLE_START_LENGTH = 0x03
    const val RLE_OFFSET_LENGTH = 0x04
    // ranges v4
    const val RANGES_BASE_ADDRESS = 0xffffffffL
    const val RANGES_END_OF_LIST = 0x00000000L

    // ELF
    const val SHT_NULL = 0L
    const val PT_LOAD = 1L
}

object SHT {
    // ELF section types used for .zdebug / mapping decisions
    const val PROGBITS = 1L
    const val NOBITS = 8L
}
