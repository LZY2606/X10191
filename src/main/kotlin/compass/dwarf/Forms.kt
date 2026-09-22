package compass.dwarf

import compass.Limits

object F {
    const val ADDR = 0x01
    const val BLOCK2 = 0x03
    const val BLOCK4 = 0x04
    const val DATA2 = 0x05
    const val DATA4 = 0x06
    const val DATA8 = 0x07
    const val STRING = 0x08
    const val BLOCK = 0x09
    const val BLOCK1 = 0x0a
    const val DATA1 = 0x0b
    const val FLAG = 0x0c
    const val SDATA = 0x0d
    const val STRP = 0x0e
    const val UDATA = 0x0f
    const val REF_ADDR = 0x10
    const val REF1 = 0x11
    const val REF2 = 0x12
    const val REF4 = 0x13
    const val REF8 = 0x14
    const val REF_UDATA = 0x15
    const val INDIRECT = 0x16
    const val SEC_OFFSET = 0x17
    const val EXPLOC = 0x18
    const val FLAG_PRESENT = 0x19
    const val STRX = 0x1a
    const val ADDRX = 0x1b
    const val REF_SUP4 = 0x1c
    const val STRP_SUP = 0x1d
    const val DATA16 = 0x1e
    const val LINE_STRP = 0x1f
    const val REF_SIG8 = 0x20
    const val IMPLICIT_CONST = 0x21
    const val LOCLISTX = 0x22
    const val RNGLISTX = 0x23
    const val REF_SUP8 = 0x24
    const val STRX1 = 0x25
    const val STRX2 = 0x26
    const val STRX3 = 0x27
    const val STRX4 = 0x28
    const val ADDRX1 = 0x29
    const val ADDRX2 = 0x2a
    const val ADDRX3 = 0x2b
    const val ADDRX4 = 0x2c

    fun name(form: Int): String = when (form) {
        ADDR -> "addr"; BLOCK2 -> "block2"; BLOCK4 -> "block4"; DATA2 -> "data2"
        DATA4 -> "data4"; DATA8 -> "data8"; STRING -> "string"; BLOCK -> "block"
        BLOCK1 -> "block1"; DATA1 -> "data1"; FLAG -> "flag"; SDATA -> "sdata"
        STRP -> "strp"; UDATA -> "udata"; REF_ADDR -> "ref_addr"; REF1 -> "ref1"
        REF2 -> "ref2"; REF4 -> "ref4"; REF8 -> "ref8"; REF_UDATA -> "ref_udata"
        INDIRECT -> "indirect"; SEC_OFFSET -> "sec_offset"; EXPLOC -> "exprloc"
        FLAG_PRESENT -> "flag_present"; STRX -> "strx"; ADDRX -> "addrx"
        REF_SUP4 -> "ref_sup4"; STRP_SUP -> "strp_sup"; DATA16 -> "data16"
        LINE_STRP -> "line_strp"; REF_SIG8 -> "ref_sig8"; IMPLICIT_CONST -> "implicit_const"
        LOCLISTX -> "loclistx"; RNGLISTX -> "rnglistx"; REF_SUP8 -> "ref_sup8"
        STRX1 -> "strx1"; STRX2 -> "strx2"; STRX3 -> "strx3"; STRX4 -> "strx4"
        ADDRX1 -> "addrx1"; ADDRX2 -> "addrx2"; ADDRX3 -> "addrx3"; ADDRX4 -> "addrx4"
        else -> "form_0x${form.toString(16)}"
    }
}

object Tag {
    const val COMPILE_UNIT = 0x11
    const val INLINED_SUBROUTINE = 0x1d
    const val SUBPROGRAM = 0x2e
    const val PARTIAL_UNIT = 0x3c
    const val SKELETON_UNIT = 0x4a

    fun name(tag: Int): String = when (tag) {
        COMPILE_UNIT -> "compile_unit"
        INLINED_SUBROUTINE -> "inlined_subroutine"
        SUBPROGRAM -> "subprogram"
        PARTIAL_UNIT -> "partial_unit"
        SKELETON_UNIT -> "skeleton_unit"
        0x01 -> "array_type"; 0x02 -> "class_type"; 0x05 -> "formal_parameter"
        0x0b -> "lexical_block"; 0x0d -> "member"; 0x0f -> "pointer_type"
        0x13 -> "structure_type"; 0x16 -> "typedef"; 0x24 -> "base_type"
        0x28 -> "enumerator"; 0x34 -> "variable"; 0x39 -> "namespace"
        else -> "tag_0x${tag.toString(16)}"
    }
}

object At {
    const val SIBLING = 0x01
    const val NAME = 0x03
    const val STMT_LIST = 0x10
    const val LOW_PC = 0x11
    const val HIGH_PC = 0x12
    const val COMP_DIR = 0x1b
    const val PRODUCER = 0x25
    const val ABSTRACT_ORIGIN = 0x31
    const val SPECIFICATION = 0x47
    const val RANGES = 0x55
    const val CALL_FILE = 0x58
    const val CALL_LINE = 0x59
    const val LINKAGE_NAME = 0x6e
    const val STR_OFFSETS_BASE = 0x72
    const val ADDR_BASE = 0x73
    const val RNGLISTS_BASE = 0x74
    const val DWO_ID = 0x75
    const val DWO_NAME = 0x76
    const val LOCLISTS_BASE = 0x8c

    fun name(attr: Int): String = when (attr) {
        SIBLING -> "sibling"; NAME -> "name"; STMT_LIST -> "stmt_list"
        LOW_PC -> "low_pc"; HIGH_PC -> "high_pc"; COMP_DIR -> "comp_dir"
        PRODUCER -> "producer"; ABSTRACT_ORIGIN -> "abstract_origin"
        SPECIFICATION -> "specification"; RANGES -> "ranges"; CALL_FILE -> "call_file"
        CALL_LINE -> "call_line"; LINKAGE_NAME -> "linkage_name"
        STR_OFFSETS_BASE -> "str_offsets_base"; ADDR_BASE -> "addr_base"
        RNGLISTS_BASE -> "rnglists_base"; DWO_ID -> "dwo_id"; DWO_NAME -> "dwo_name"
        LOCLISTS_BASE -> "loclists_base"
        else -> "at_0x${attr.toString(16)}"
    }
}

/** A decoded attribute value. References keep their raw (section-relative) offset. */
sealed interface AttrValue {
    data class Num(val v: Long) : AttrValue          // dataN/sdata/udata/flag/sec_offset/implicit_const
    data class Str(val s: String) : AttrValue        // inline string
    data class Strp(val offset: Long, val lineStr: Boolean) : AttrValue  // into .debug_str / .debug_line_str
    data class Strx(val index: Long) : AttrValue     // indirect via .debug_str_offsets
    data class Addr(val v: Long) : AttrValue
    data class Addrx(val index: Long) : AttrValue    // indirect via .debug_addr
    data class Ref(val offset: Long) : AttrValue     // section-relative DIE offset
    data class Block(val data: ByteArray) : AttrValue
}

/** Reads one attribute value of the given form, advancing the reader exactly by the
 *  form's encoded size. Unknown forms throw [UnknownFormException] so the caller can
 *  isolate the CU instead of emitting desynchronized garbage. */
fun readFormValue(
    r: Reader,
    form: Int,
    addrSize: Int,
    dwarf64: Boolean,
    implicitConst: Long? = null,
    indirectDepth: Int = 0,
): AttrValue {
    val at = r.pos
    fun needIndirect() {
        if (indirectDepth >= Limits.MAX_INDIRECT)
            throw ParseException("DW_FORM_indirect nesting too deep at 0x${at.toString(16)}")
    }
    return when (form) {
        F.ADDR -> AttrValue.Addr(r.addr(addrSize))
        F.BLOCK1 -> AttrValue.Block(r.bytes(r.u8()))
        F.BLOCK2 -> AttrValue.Block(r.bytes(r.u16()))
        F.BLOCK4 -> { val n = r.u32(); if (n > Int.MAX_VALUE) throw ParseException("block4 too large"); AttrValue.Block(r.bytes(n.toInt())) }
        F.BLOCK, F.EXPLOC -> { val n = r.uleb(); if (n > Limits.MAX_BLOCK) throw ParseException("block too large: $n"); AttrValue.Block(r.bytes(n.toInt())) }
        F.DATA1 -> AttrValue.Num(r.u8().toLong())
        F.DATA2 -> AttrValue.Num(r.u16().toLong())
        F.DATA4 -> AttrValue.Num(r.u32())
        F.DATA8 -> AttrValue.Num(r.u64())
        F.DATA16 -> AttrValue.Block(r.bytes(16))
        F.SDATA -> AttrValue.Num(r.sleb())
        F.UDATA -> AttrValue.Num(r.uleb())
        F.FLAG -> AttrValue.Num((if (r.u8() != 0) 1 else 0).toLong())
        F.FLAG_PRESENT -> AttrValue.Num(1)
        F.IMPLICIT_CONST -> AttrValue.Num(implicitConst ?: 0)
        F.STRING -> AttrValue.Str(r.cstr())
        F.STRP -> AttrValue.Strp(r.offset(dwarf64), lineStr = false)
        F.LINE_STRP -> AttrValue.Strp(r.offset(dwarf64), lineStr = true)
        F.STRP_SUP -> AttrValue.Strp(r.offset(dwarf64), lineStr = false)
        F.STRX -> AttrValue.Strx(r.uleb())
        F.STRX1 -> AttrValue.Strx(r.u8().toLong())
        F.STRX2 -> AttrValue.Strx(r.u16().toLong())
        F.STRX3 -> { val b = r.bytes(3); AttrValue.Strx((b[0].toLong() and 0xFF) or ((b[1].toLong() and 0xFF) shl 8) or ((b[2].toLong() and 0xFF) shl 16)) }
        F.STRX4 -> AttrValue.Strx(r.u32())
        F.ADDRX -> AttrValue.Addrx(r.uleb())
        F.ADDRX1 -> AttrValue.Addrx(r.u8().toLong())
        F.ADDRX2 -> AttrValue.Addrx(r.u16().toLong())
        F.ADDRX3 -> { val b = r.bytes(3); AttrValue.Addrx((b[0].toLong() and 0xFF) or ((b[1].toLong() and 0xFF) shl 8) or ((b[2].toLong() and 0xFF) shl 16)) }
        F.ADDRX4 -> AttrValue.Addrx(r.u32())
        F.SEC_OFFSET -> AttrValue.Num(r.offset(dwarf64))
        F.REF1 -> AttrValue.Ref(r.u8().toLong())
        F.REF2 -> AttrValue.Ref(r.u16().toLong())
        F.REF4 -> AttrValue.Ref(r.u32())
        F.REF8, F.REF_SIG8 -> AttrValue.Ref(r.u64())
        F.REF_UDATA -> AttrValue.Ref(r.uleb())
        F.REF_ADDR -> AttrValue.Ref(r.offset(dwarf64))
        F.REF_SUP4 -> AttrValue.Ref(r.u32())
        F.REF_SUP8 -> AttrValue.Ref(r.u64())
        F.RNGLISTX, F.LOCLISTX -> AttrValue.Num(r.uleb())
        F.INDIRECT -> {
            needIndirect()
            val real = r.uleb()
            if (real > Int.MAX_VALUE) throw UnknownFormException(real, at)
            readFormValue(r, real.toInt(), addrSize, dwarf64, implicitConst, indirectDepth + 1)
        }
        else -> throw UnknownFormException(form.toLong(), at)
    }
}
