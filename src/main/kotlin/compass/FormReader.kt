package compass

/** Determines whether a form code can be safely skipped/read by the parser. */
object FormReader {
    fun isSkippable(form: Long): Boolean = when (form) {
        Dw.FORM_ADDR, Dw.FORM_BLOCK2, Dw.FORM_BLOCK4, Dw.FORM_DATA2, Dw.FORM_DATA4,
        Dw.FORM_DATA8, Dw.FORM_STRING, Dw.FORM_BLOCK, Dw.FORM_BLOCK1, Dw.FORM_DATA1,
        Dw.FORM_FLAG, Dw.FORM_SDATA, Dw.FORM_STRP, Dw.FORM_UDATA, Dw.FORM_REF_ADDR,
        Dw.FORM_REF1, Dw.FORM_REF2, Dw.FORM_REF4, Dw.FORM_REF8, Dw.FORM_REF_UDATA,
        Dw.FORM_INDIRECT, Dw.FORM_SEC_OFFSET, Dw.FORM_EXPRLOC, Dw.FORM_FLAG_PRESENT,
        Dw.FORM_STRX, Dw.FORM_ADDRX, Dw.FORM_REF_SUP4, Dw.FORM_STRP_SUP, Dw.FORM_DATA16,
        Dw.FORM_LINE_STRP, Dw.FORM_REF_SIG8, Dw.FORM_IMPLICIT_CONST, Dw.FORM_LOCLISTX,
        Dw.FORM_RNGLISTX, Dw.FORM_REF_SUP8, Dw.FORM_STRX1, Dw.FORM_STRX2, Dw.FORM_STRX3,
        Dw.FORM_STRX4, Dw.FORM_ADDRX1, Dw.FORM_ADDRX2, Dw.FORM_ADDRX3, Dw.FORM_ADDRX4,
        Dw.FORM_GNU_ADDR_INDEX, Dw.FORM_GNU_STR_INDEX, Dw.FORM_GNU_REF_ALT,
        Dw.FORM_GNU_STRP_ALT -> true
        else -> false
    }

    fun isConstantForm(form: Long): Boolean = when (form) {
        Dw.FORM_DATA1, Dw.FORM_DATA2, Dw.FORM_DATA4, Dw.FORM_DATA8,
        Dw.FORM_SDATA, Dw.FORM_UDATA, Dw.FORM_IMPLICIT_CONST -> true
        else -> false
    }

    fun isAddressForm(form: Long): Boolean = form == Dw.FORM_ADDR

    fun isReferenceForm(form: Long): Boolean = when (form) {
        Dw.FORM_REF_ADDR, Dw.FORM_REF1, Dw.FORM_REF2, Dw.FORM_REF4,
        Dw.FORM_REF8, Dw.FORM_REF_UDATA -> true
        else -> false
    }

    fun isStringOffsetForm(form: Long): Boolean = when (form) {
        Dw.FORM_STRP, Dw.FORM_LINE_STRP, Dw.FORM_SEC_OFFSET -> true
        else -> false
    }

    /** Fixed block/form byte size; variable forms return -1. */
    fun fixedSize(form: Long, offsetSize: Int, addressSize: Int): Int = when (form) {
        Dw.FORM_ADDR -> addressSize
        Dw.FORM_DATA1, Dw.FORM_FLAG, Dw.FORM_REF1, Dw.FORM_STRX1, Dw.FORM_ADDRX1 -> 1
        Dw.FORM_DATA2, Dw.FORM_REF2, Dw.FORM_STRX2, Dw.FORM_ADDRX2 -> 2
        Dw.FORM_DATA4, Dw.FORM_REF4, Dw.FORM_REF_SUP4, Dw.FORM_STRX4, Dw.FORM_ADDRX4,
        Dw.FORM_BLOCK4 -> 4
        Dw.FORM_DATA8, Dw.FORM_REF8, Dw.FORM_REF_SIG8, Dw.FORM_REF_SUP8 -> 8
        Dw.FORM_SEC_OFFSET, Dw.FORM_STRP -> if (offsetSize == 8) 8 else 4
        Dw.FORM_DATA16 -> 16
        else -> -1
    }
}
