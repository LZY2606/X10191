package compass.dwarf

import compass.binary.ByteReader
import compass.binary.DwarfParseException

/**
 * Shared logic for reading DWARF form values. Kept deliberately conservative:
 * unknown forms throw [UnknownFormException] so callers can isolate the unit
 * rather than guessing a length and desynchronising the cursor.
 */
class UnknownFormException(val form: Int) : Exception("unknown form 0x${form.toString(16)}")

/** A str_offsets section header once pre-scanned. */
data class StrOffsetsTable(val dataStart: Int, val entrySize: Int)

object FormIO {
    fun isStringForm(form: Int): Boolean = when (form) {
        DW.FORM.string, DW.FORM.strp, DW.FORM.line_strp,
        DW.FORM.strx, DW.FORM.strx1, DW.FORM.strx2, DW.FORM.strx3, DW.FORM.strx4,
        DW.FORM.GNU_str_index, DW.FORM.GNU_strp_offset, DW.FORM.strp_sup -> true
        else -> false
    }

    fun isAddrIndexForm(form: Int): Boolean = when (form) {
        DW.FORM.addrx, DW.FORM.addrx1, DW.FORM.addrx2, DW.FORM.addrx3, DW.FORM.addrx4,
        DW.FORM.GNU_addr_index -> true
        else -> false
    }

    fun isStrIndexForm(form: Int): Boolean = when (form) {
        DW.FORM.strx, DW.FORM.strx1, DW.FORM.strx2, DW.FORM.strx3, DW.FORM.strx4,
        DW.FORM.GNU_str_index -> true
        else -> false
    }
}

class FormReader(
    val r: ByteReader,
    val sections: DwarfSections,
    val version: Int,
    val offsetSize: Int,
    val addressSize: Int,
    val addrBase: Long?,
    val strOffsetsBase: Long?,
    val strOffsetsTables: Map<Long, StrOffsetsTable>,
    val warnings: MutableList<String>,
) {
    private var indirectDepth = 0

    /** Read an index that the form encodes inline (strx1..4, addrx1..4, or ULEB). */
    private fun indexFor(form: Int): Long = when (form) {
        DW.FORM.strx1, DW.FORM.addrx1 -> r.u8().toLong()
        DW.FORM.strx2, DW.FORM.addrx2 -> r.u16().toLong()
        DW.FORM.strx3, DW.FORM.addrx3 -> read3()
        DW.FORM.strx4, DW.FORM.addrx4 -> r.u32()
        DW.FORM.strx, DW.FORM.addrx, DW.FORM.GNU_addr_index, DW.FORM.GNU_str_index -> r.uleb()
        else -> throw DwarfParseException("not an index form: $form")
    }

    private fun read3(): Long {
        val a = r.u8().toLong(); val b = r.u8().toLong(); val c = r.u8().toLong()
        return a or (b shl 8) or (c shl 16)
    }

    private fun stringAt(section: ByteArray, offset: Int, label: String): String {
        if (offset < 0 || offset >= section.size) {
            warnings.add("$label 越界 offset=$offset size=${section.size}")
            return ""
        }
        var end = offset
        while (end < section.size && section[end].toInt() != 0) end++
        if (end >= section.size) warnings.add("$label 未终止 offset=$offset")
        return String(section, offset, minOf(end, section.size) - offset, Charsets.UTF_8)
    }

    private fun resolveStrIndex(index: Long, base: Long?, baseAttr: Int): String {
        val strSection = sections.str
        if (strSection == null) {
            warnings.add("缺少 .debug_str，字符串索引无法解析")
            return ""
        }
        // base points at the first offset entry (past the 8-byte DWARF32 header).
        val table = strOffsetsTables[base ?: 0L] ?: strOffsetsTables[0L]
        val entrySize = table?.entrySize ?: offsetSize
        val defaultBase = table?.dataStart?.toLong() ?: 0L
        val effectiveBase = base ?: defaultBase
        val offPos = (effectiveBase + index * entrySize).toInt()
        val strOffsets = sections.strOffsets
        if (strOffsets == null) {
            warnings.add("缺少 .debug_str_offsets，strx 索引无法解析")
            return ""
        }
        if (offPos < 0 || offPos + entrySize > strOffsets.size) {
            warnings.add("str_offsets 索引越界 index=$index base=$effectiveBase")
            return ""
        }
        val sr = ByteReader(strOffsets, offPos, offPos + entrySize)
        val strOffset = if (entrySize == 8) sr.u64() else sr.u32()
        return stringAt(strSection, strOffset.toInt(), ".debug_str 引用")
    }

    fun readStringForm(form: Int): String {
        return when (form) {
            DW.FORM.string -> r.cstring()
            DW.FORM.strp -> {
                val s = sections.str ?: run { warnings.add("缺少 .debug_str"); r.seek(r.pos + offsetSize); return "" }
                val off = readOffsetSized().toInt()
                stringAt(s, off, ".debug_str 引用")
            }
            DW.FORM.line_strp -> {
                val s = sections.lineStr ?: sections.str ?: run {
                    warnings.add("缺少 .debug_line_str")
                    r.seek(r.pos + offsetSize); return ""
                }
                val off = readOffsetSized().toInt()
                stringAt(s, off, ".debug_line_str 引用")
            }
            DW.FORM.strp_sup -> {
                warnings.add("DW_FORM_strp_sup 引用外部补充文件，无法解析")
                r.seek(r.pos + offsetSize); ""
            }
            DW.FORM.strx, DW.FORM.strx1, DW.FORM.strx2, DW.FORM.strx3, DW.FORM.strx4, DW.FORM.GNU_str_index ->
                resolveStrIndex(indexFor(form), strOffsetsBase, DW.AT_str_offsets_base)
            else -> throw UnknownFormException(form)
        }
    }

    fun readOffsetSized(): Long = if (offsetSize == 8) r.u64() else r.u32()

    /** Numeric constant / address / offset, used by line file-table entries too. */
    fun readNumeric(form: Int): Long = when (form) {
        DW.FORM.addr -> r.addr(addressSize)
        DW.FORM.data1, DW.FORM.flag -> r.u8().toLong()
        DW.FORM.data2 -> r.u16().toLong()
        DW.FORM.data4 -> r.u32()
        DW.FORM.data8, DW.FORM.ref_sig8 -> r.u64()
        DW.FORM.sdata -> r.sleb()
        DW.FORM.udata -> r.uleb()
        DW.FORM.sec_offset -> readOffsetSized()
        DW.FORM.ref1 -> r.u8().toLong()
        DW.FORM.ref2 -> r.u16().toLong()
        DW.FORM.ref4 -> r.u32()
        DW.FORM.ref8 -> r.u64()
        DW.FORM.ref_udata -> r.uleb()
        DW.FORM.ref_addr -> readOffsetSized()
        else -> throw UnknownFormException(form)
    }

    fun skipBytes(form: Int) {
        when (form) {
            DW.FORM.string -> r.cstring()
            DW.FORM.strp, DW.FORM.sec_offset, DW.FORM.ref_addr -> r.seek(r.pos + offsetSize)
            DW.FORM.line_strp -> r.seek(r.pos + offsetSize)
            DW.FORM.data1, DW.FORM.flag, DW.FORM.ref1 -> r.u8()
            DW.FORM.data2, DW.FORM.ref2 -> r.u16()
            DW.FORM.data4, DW.FORM.ref4, DW.FORM.ref_sup4 -> r.u32()
            DW.FORM.data8, DW.FORM.ref8, DW.FORM.ref_sup8, DW.FORM.ref_sig8 -> r.u64()
            DW.FORM.data16 -> r.readBytes(16)
            DW.FORM.sdata -> r.sleb()
            DW.FORM.udata, DW.FORM.ref_udata -> r.uleb()
            DW.FORM.addr -> r.addr(addressSize)
            DW.FORM.block1 -> { val n = r.u8(); r.readBytes(n) }
            DW.FORM.block2 -> { val n = r.u16(); r.readBytes(n) }
            DW.FORM.block4 -> { val n = r.u32().toInt(); r.readBytes(n) }
            DW.FORM.block, DW.FORM.exprloc -> { val n = r.uleb().toInt(); r.readBytes(n) }
            else -> throw UnknownFormException(form)
        }
    }

    /** Read a file-table style value: prefer string for paths, number otherwise. */
    fun readPathOrNumber(form: Int, contentType: Int): Pair<String?, Long?> {
        if (FormIO.isStringForm(form) || contentType == DW.LNCT.path) {
            val s = readStringForm(form)
            return s to null
        }
        return try {
            null to readNumeric(form)
        } catch (_: UnknownFormException) {
            throw UnknownFormException(form)
        }
    }

    /** Full attribute decode for .debug_info DIEs. */
    fun readAttr(attr: Int, formRaw: Int): AttrValue {
        var form = formRaw
        if (form == DW.FORM.indirect) {
            if (++indirectDepth > MAX_INDIRECT_HOPS) throw DwarfParseException("DW_FORM_indirect 嵌套过深")
            form = r.uleb().toInt()
        }
        when (form) {
            DW.FORM.flag_present -> return AttrValue.Flag(true)
            DW.FORM.flag -> return AttrValue.Flag(r.u8() != 0)
            DW.FORM.string, DW.FORM.strp, DW.FORM.line_strp, DW.FORM.strp_sup ->
                return AttrValue.Str(readStringForm(form))
            DW.FORM.addr -> return AttrValue.Num(r.addr(addressSize), isAddress = true)
            DW.FORM.data1 -> return AttrValue.Num(r.u8().toLong())
            DW.FORM.data2 -> return AttrValue.Num(r.u16().toLong())
            DW.FORM.data4 -> return AttrValue.Num(r.u32())
            DW.FORM.data8 -> return AttrValue.Num(r.u64())
            DW.FORM.data16 -> return AttrValue.Bytes(r.readBytes(16))
            DW.FORM.sdata -> return AttrValue.Num(r.sleb())
            DW.FORM.udata -> return AttrValue.Num(r.uleb())
            DW.FORM.sec_offset -> return AttrValue.SecOffset(readOffsetSized())
            DW.FORM.block1 -> return AttrValue.Bytes(r.readBytes(r.u8()))
            DW.FORM.block2 -> return AttrValue.Bytes(r.readBytes(r.u16()))
            DW.FORM.block4 -> return AttrValue.Bytes(r.readBytes(r.u32().toInt()))
            DW.FORM.block, DW.FORM.exprloc -> return AttrValue.Bytes(r.readBytes(r.uleb().toInt()))
            DW.FORM.ref1 -> return AttrValue.Ref(r.u8().toLong())
            DW.FORM.ref2 -> return AttrValue.Ref(r.u16().toLong())
            DW.FORM.ref4 -> return AttrValue.Ref(r.u32())
            DW.FORM.ref8 -> return AttrValue.Ref(r.u64())
            DW.FORM.ref_udata -> return AttrValue.Ref(r.uleb())
            DW.FORM.ref_addr -> return AttrValue.Ref(readOffsetSized())
            DW.FORM.ref_sup4 -> { warnings.add("DW_FORM_ref_sup4 无法解析（缺少补充文件）"); r.u32(); return AttrValue.Num(0) }
            DW.FORM.ref_sup8 -> { warnings.add("DW_FORM_ref_sup8 无法解析（缺少补充文件）"); r.u64(); return AttrValue.Num(0) }
            DW.FORM.ref_sig8 -> return AttrValue.Num(r.u64())
            DW.FORM.implicit_const -> throw DwarfParseException("implicit_const 由 abbrev 常量提供，不应走到这里")
            DW.FORM.rnglistx -> return AttrValue.RangeListIndex(r.uleb())
            DW.FORM.addrx, DW.FORM.addrx1, DW.FORM.addrx2, DW.FORM.addrx3, DW.FORM.addrx4,
            DW.FORM.GNU_addr_index -> {
                val idx = indexFor(form)
                return AttrValue.AddrIndex(idx, if (form == DW.FORM.GNU_addr_index) DW.AT_GNU_addr_base else DW.AT_addr_base)
            }
            DW.FORM.strx, DW.FORM.strx1, DW.FORM.strx2, DW.FORM.strx3, DW.FORM.strx4,
            DW.FORM.GNU_str_index -> return AttrValue.Str(readStringForm(form))
            else -> throw UnknownFormException(form)
        }
    }

    companion object {
        const val MAX_INDIRECT_HOPS = 5
    }
}
