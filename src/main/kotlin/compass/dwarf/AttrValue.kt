package compass.dwarf

import java.nio.ByteOrder

sealed class AttrValue {
    data class Addr(val v: Long) : AttrValue()
    data class Data(val v: Long) : AttrValue()          // unsigned constant / flag-as-data
    data class SData(val v: Long) : AttrValue()
    /** Section-relative reference into .debug_info. */
    data class Ref(val off: Long) : AttrValue()
    data class Str(val s: String) : AttrValue()
    data class Block(val bytes: ByteArray) : AttrValue() {
        override fun equals(other: Any?) = other is Block && bytes.contentEquals(other.bytes)
        override fun hashCode() = bytes.contentHashCode()
    }
    data class Flag(val v: Boolean) : AttrValue()
    /** Indirect index (addrx/strx/rnglistx) that could not be resolved inline. */
    data class Index(val kind: String, val idx: Long) : AttrValue()

    fun asString(): String? = (this as? Str)?.s
    fun asLong(): Long? = when (this) {
        is Data -> v; is SData -> v; is Addr -> v; is Ref -> off
        is Flag -> if (v) 1L else 0L
        else -> null
    }
}

/** Everything form decoding needs to know about the surrounding file. */
class FormContext(
    val version: Int,
    val addrSize: Int,
    val order: ByteOrder,
    val debugStr: ByteArray?,
    val debugLineStr: ByteArray?,
    val debugAddr: ByteArray?,
    val addrBase: Long = 0L,
    val strOffsets: ByteArray?,
    val strOffsetsBase: Long = 0L,
    val is64Dwarf: Boolean = false,
) {
    private val offSize get() = if (is64Dwarf) 8 else 4

    private fun strAt(section: ByteArray?, off: Long): String {
        if (section == null) return "<str@0x${off.toString(16)}:section-missing>"
        if (off < 0 || off >= section.size) return "<str@0x${off.toString(16)}:out-of-bounds>"
        return ElfCompat.cString(section, off.toInt())
    }

    private fun addrIndex(idx: Long): AttrValue {
        val sec = debugAddr ?: return AttrValue.Index("addrx", idx)
        val entryOff = addrBase + idx * addrSize
        if (entryOff < 0 || entryOff + addrSize > sec.size) return AttrValue.Index("addrx:oob", idx)
        val c = Cursor(sec, entryOff.toInt(), sec.size, order)
        return AttrValue.Addr(c.uintN(addrSize))
    }

    private fun strIndex(idx: Long): AttrValue {
        val sec = strOffsets ?: return AttrValue.Index("strx", idx)
        val entryOff = strOffsetsBase + idx * offSize
        if (entryOff < 0 || entryOff + offSize > sec.size) return AttrValue.Index("strx:oob", idx)
        val c = Cursor(sec, entryOff.toInt(), sec.size, order)
        val off = c.uintN(offSize)
        return AttrValue.Str(strAt(debugStr, off))
    }

    /**
     * Decodes one attribute value, advancing [c] exactly by the form's encoded
     * size. Unknown forms throw [UnknownFormException]; the caller isolates the
     * whole CU instead of guessing a size and desynchronising the cursor.
     */
    fun decode(formIn: Int, c: Cursor): AttrValue {
        var form = formIn
        if (form == Dw.FORM_indirect) form = c.uleb().toInt()
        return when (form) {
            Dw.FORM_addr -> AttrValue.Addr(c.uintN(addrSize))
            Dw.FORM_addrx -> addrIndex(c.uleb())
            Dw.FORM_addrx1 -> addrIndex(c.u8().toLong())
            Dw.FORM_addrx2 -> addrIndex(c.u16().toLong())
            Dw.FORM_addrx3 -> { val v = c.u8() or (c.u8() shl 8) or (c.u8() shl 16); addrIndex(v.toLong()) }
            Dw.FORM_addrx4 -> addrIndex(c.u32())
            Dw.FORM_data1 -> AttrValue.Data(c.u8().toLong())
            Dw.FORM_data2 -> AttrValue.Data(c.u16().toLong())
            Dw.FORM_data4 -> AttrValue.Data(c.u32())
            Dw.FORM_data8 -> AttrValue.Data(c.u64())
            Dw.FORM_data16 -> AttrValue.Block(c.bytes(16))
            Dw.FORM_udata -> AttrValue.Data(c.uleb())
            Dw.FORM_sdata -> AttrValue.SData(c.sleb())
            Dw.FORM_implicit_const -> AttrValue.SData(0L) // patched by caller via AttrSpec
            Dw.FORM_flag -> AttrValue.Flag(c.u8() != 0)
            Dw.FORM_flag_present -> AttrValue.Flag(true)
            Dw.FORM_string -> AttrValue.Str(c.cstring())
            Dw.FORM_strp -> AttrValue.Str(strAt(debugStr, c.uintN(offSize)))
            Dw.FORM_line_strp -> AttrValue.Str(strAt(debugLineStr, c.uintN(offSize)))
            Dw.FORM_strp_sup -> { c.skip(offSize); AttrValue.Str("<sup-str>") }
            Dw.FORM_strx -> strIndex(c.uleb())
            Dw.FORM_strx1 -> strIndex(c.u8().toLong())
            Dw.FORM_strx2 -> strIndex(c.u16().toLong())
            Dw.FORM_strx3 -> { val v = c.u8() or (c.u8() shl 8) or (c.u8() shl 16); strIndex(v.toLong()) }
            Dw.FORM_strx4 -> strIndex(c.u32())
            Dw.FORM_GNU_str_index -> strIndex(c.uleb())
            Dw.FORM_GNU_strp_alt -> { c.skip(offSize); AttrValue.Str("<alt-str>") }
            Dw.FORM_ref1 -> AttrValue.Ref(c.u8().toLong())
            Dw.FORM_ref2 -> AttrValue.Ref(c.u16().toLong())
            Dw.FORM_ref4 -> AttrValue.Ref(c.u32())
            Dw.FORM_ref8 -> AttrValue.Ref(c.u64())
            Dw.FORM_ref_udata -> AttrValue.Ref(c.uleb())
            Dw.FORM_ref_addr -> AttrValue.Ref(c.uintN(if (version >= 3) offSize else addrSize))
            Dw.FORM_ref_sig8 -> AttrValue.Ref(c.u64())
            Dw.FORM_ref_sup4 -> { c.skip(4); AttrValue.Ref(-1) }
            Dw.FORM_ref_sup8 -> { c.skip(8); AttrValue.Ref(-1) }
            Dw.FORM_sec_offset -> AttrValue.Data(c.uintN(offSize))
            Dw.FORM_exprloc -> { val n = c.uleb(); if (n > Int.MAX_VALUE) throw DwarfParseException("exprloc too big"); AttrValue.Block(c.bytes(n.toInt())) }
            Dw.FORM_block -> { val n = c.uleb(); if (n > Int.MAX_VALUE) throw DwarfParseException("block too big"); AttrValue.Block(c.bytes(n.toInt())) }
            Dw.FORM_block1 -> AttrValue.Block(c.bytes(c.u8()))
            Dw.FORM_block2 -> AttrValue.Block(c.bytes(c.u16()))
            Dw.FORM_block4 -> { val n = c.u32(); if (n > Int.MAX_VALUE) throw DwarfParseException("block4 too big"); AttrValue.Block(c.bytes(n.toInt())) }
            Dw.FORM_loclistx -> AttrValue.Index("loclistx", c.uleb())
            Dw.FORM_rnglistx -> AttrValue.Index("rnglistx", c.uleb())
            Dw.FORM_GNU_addr_index -> addrIndex(c.uleb())
            else -> throw UnknownFormException(form)
        }
    }
}

/** Avoid a circular dep on the ELF package for one tiny helper. */
private object ElfCompat {
    fun cString(buf: ByteArray, off: Int): String {
        if (off < 0 || off >= buf.size) return ""
        var end = off
        while (end < buf.size && buf[end] != 0.toByte()) end++
        return String(buf, off, end - off, Charsets.UTF_8)
    }
}
