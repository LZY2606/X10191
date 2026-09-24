package compass

import java.math.BigInteger

data class AbbrevAttr(val attr: Int, val form: Int, val implicit: Long?)
data class Abbreviation(val code: Long, val tag: Int, val hasChildren: Boolean, val attributes: List<AbbrevAttr>)

data class FormValue(val value: AttrValue, val referenceUnitRelative: Boolean = false, val referenceOffset: Long? = null)

object FormReader {
    private val addressForms = setOf(
        DwarfConstants.DW_FORM_addr, DwarfConstants.DW_FORM_addrx, DwarfConstants.DW_FORM_addrx1,
        DwarfConstants.DW_FORM_addrx2, DwarfConstants.DW_FORM_addrx3, DwarfConstants.DW_FORM_addrx4
    )

    fun isAddressForm(form: Int): Boolean = form in addressForms

    fun read(reader: ByteReader, formInput: Int, version: Int, addressSize: Int, endian: Int, indirectDepth: Int = 0): FormValue {
        if (indirectDepth > 8) throw CursorException("DW_FORM_indirect chain too deep")
        val form = if (formInput == DwarfConstants.DW_FORM_indirect) reader.uleb().toInt() else formInput
        val big = { v: Long -> BigInteger.valueOf(v) }
        fun signed(v: Long) = BigInteger.valueOf(v)
        val value = when (form) {
            DwarfConstants.DW_FORM_addr -> AttrValue("addr", big(reader.uint(addressSize, endian)))
            DwarfConstants.DW_FORM_addrx, DwarfConstants.DW_FORM_strx, DwarfConstants.DW_FORM_udata, DwarfConstants.DW_FORM_ref_udata, DwarfConstants.DW_FORM_rnglistx, DwarfConstants.DW_FORM_loclistx ->
                AttrValue("udata", big(reader.uleb()))
            DwarfConstants.DW_FORM_addrx1, DwarfConstants.DW_FORM_strx1, DwarfConstants.DW_FORM_data1, DwarfConstants.DW_FORM_ref1 -> AttrValue("data1", big(reader.u8().toLong()))
            DwarfConstants.DW_FORM_addrx2, DwarfConstants.DW_FORM_strx2, DwarfConstants.DW_FORM_data2, DwarfConstants.DW_FORM_ref2 -> AttrValue("data2", big(reader.u16(endian).toLong()))
            DwarfConstants.DW_FORM_strx3 -> {
                val b = reader.readBytes(3); val ordered = if (endian == 1) b else b.reversedArray()
                var v = 0L; for (byte in ordered) v = (v shl 8) or (byte.toInt() and 255).toLong()
                AttrValue("data3", big(v))
            }
            DwarfConstants.DW_FORM_addrx4, DwarfConstants.DW_FORM_strx4, DwarfConstants.DW_FORM_data4, DwarfConstants.DW_FORM_ref4, DwarfConstants.DW_FORM_ref_sup4 -> AttrValue("data4", big(reader.u32(endian)))
            DwarfConstants.DW_FORM_data8, DwarfConstants.DW_FORM_ref8, DwarfConstants.DW_FORM_ref_sig8, DwarfConstants.DW_FORM_ref_sup8 -> AttrValue("data8", big(reader.u64(endian)))
            DwarfConstants.DW_FORM_sdata -> AttrValue("sdata", signed(reader.sleb()))
            DwarfConstants.DW_FORM_string -> AttrValue("string", null, reader.string())
            DwarfConstants.DW_FORM_strp -> AttrValue("strp", big(reader.uint(if (version >= 5) 4 else 4, endian)))
            DwarfConstants.DW_FORM_line_strp -> AttrValue("line_strp", big(reader.uint(4, endian)))
            DwarfConstants.DW_FORM_sec_offset -> AttrValue("sec_offset", big(reader.uint(if (version >= 5) 4 else 4, endian)))
            DwarfConstants.DW_FORM_ref_addr -> AttrValue("ref_addr", big(reader.uint(if (version == 2 && addressSize == 8) 8 else if (version <= 3) addressSize else 4, endian)))
            DwarfConstants.DW_FORM_flag -> AttrValue("flag", big(reader.u8().toLong()))
            DwarfConstants.DW_FORM_flag_present -> AttrValue("flag_present", BigInteger.ONE)
            DwarfConstants.DW_FORM_exprloc, DwarfConstants.DW_FORM_block -> {
                val len = reader.uleb().toInt(); AttrValue("block", null, reader.readBytes(limited(len, 1_000_000)).joinToString(""))
            }
            DwarfConstants.DW_FORM_block1 -> AttrValue("block1", null, reader.readBytes(limited(reader.u8(), 1_000_000)).joinToString(""))
            DwarfConstants.DW_FORM_block2 -> AttrValue("block2", null, reader.readBytes(limited(reader.u16(endian), 1_000_000)).joinToString(""))
            DwarfConstants.DW_FORM_block4 -> AttrValue("block4", null, reader.readBytes(limited(reader.u32(endian).toInt(), 1_000_000)).joinToString(""))
            DwarfConstants.DW_FORM_data16 -> AttrValue("data16", null, reader.readBytes(16).joinToString(""))
            else -> throw UnknownFormException(form)
        }
        val unitRelative = form == DwarfConstants.DW_FORM_ref1 || form == DwarfConstants.DW_FORM_ref2 || form == DwarfConstants.DW_FORM_ref4 ||
            form == DwarfConstants.DW_FORM_ref8 || form == DwarfConstants.DW_FORM_ref_udata
        val refOffset = if (unitRelative) value.raw?.toLong() else if (form == DwarfConstants.DW_FORM_ref_addr) value.raw?.toLong() else null
        return FormValue(value, unitRelative, refOffset)
    }

    private fun limited(value: Int, max: Int): Int {
        if (value < 0 || value > max) throw CursorException("block size out of supported range")
        return value
    }
}

class UnknownFormException(val form: Int) : RuntimeException("unknown DWARF form 0x${form.toString(16)}")

object AbbrevParser {
    fun parseTable(bytes: ByteArray, offset: Long): Map<Long, Abbreviation> {
        val reader = ByteReader(bytes)
        reader.pos = offset.toInt()
        val result = linkedMapOf<Long, Abbreviation>()
        var guard = 0
        while (reader.remaining() > 0 && guard++ < 1_000_000) {
            val code = reader.uleb()
            if (code == 0L) break
            val tag = reader.uleb().toInt()
            val hasChildren = reader.u8() == 1
            val attrs = mutableListOf<AbbrevAttr>()
            var attrGuard = 0
            while (attrGuard++ < 1_000_000) {
                val attr = reader.uleb().toInt()
                val form = reader.uleb().toInt()
                val implicit = if (form == DwarfConstants.DW_FORM_implicit_const) reader.sleb() else null
                if (attr == 0 && form == 0) break
                attrs += AbbrevAttr(attr, form, implicit)
            }
            result[code] = Abbreviation(code, tag, hasChildren, attrs)
        }
        return result
    }
}
