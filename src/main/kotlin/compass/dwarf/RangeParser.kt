package compass.dwarf

import compass.binfmt.Cursor
import compass.binfmt.DwarfParseException

/**
 * Reads .debug_ranges (DWARF <=4) and .debug_rnglists (DWARF 5).
 * Segmented addresses are handled: base_addressx / startx entries that require
 * .debug_addr are resolved via [addrLookup]; a missing .debug_addr turns the
 * specific list into a warning rather than garbage ranges.
 */
class RangeParser(
    private val sections: DwarfSections,
    private val littleEndian: Boolean,
) {
    fun parseV4(cu: CompUnit, offset: Long, addrLookup: (Long) -> Long?): Pair<List<RangeEntry>, List<String>> {
        val d = sections.ranges ?: return Pair(emptyList<RangeEntry>(), listOf(".debug_ranges section missing"))
        val warnings = mutableListOf<String>()
        if (offset < 0 || offset >= d.size) return Pair(emptyList<RangeEntry>(), listOf("ranges offset $offset out of bounds"))
        val a = cu.addressSize
        val c = Cursor(d, offset.toIntExact(), d.size, offset.toIntExact(), littleEndian)
        val out = mutableListOf<RangeEntry>()
        var base = 0L
        var maxEntries = 1_000_000
        try {
            while (true) {
                if (maxEntries-- <= 0) { warnings.add("ranges entry limit at offset $offset"); break }
                val begin = c.addr(a); val end = c.addr(a)
                if (begin == 0L && end == 0L) break
                if (begin == maxValue(a)) { base = end; continue }
                if (begin + base < begin) warnings.add("base overflow in ranges@$offset")
                val s = begin + base; val e = end + base
                if (end < begin) { warnings.add("inverted range ($s,$e)"); continue }
                out.add(RangeEntry(s, e, s == e))
            }
        } catch (e: DwarfParseException) {
            warnings.add("truncated .debug_ranges at offset $offset: ${e.message}")
        }
        return out to warnings
    }

    fun parseV5(cu: CompUnit, rnglistsOffset: Long, index: Long?, addrLookup: (Long) -> Long?): Pair<List<RangeEntry>, List<String>> {
        val d = sections.rnglists ?: return Pair(emptyList<RangeEntry>(), listOf(".debug_rnglists section missing"))
        val warnings = mutableListOf<String>()
        // find the list start: attribute value is header-relative byte offset (or an index via rnglistx)
        val loc: V5Loc = locateV5List(d, rnglistsOffset, index, cu)
            ?: return Pair(emptyList<RangeEntry>(), listOf("rnglists offset $rnglistsOffset invalid"))
        val listStart = loc.listStart
        val a = if (loc.addrSize in listOf(1,2,4,8)) loc.addrSize else cu.addressSize
        val c = Cursor(d, listStart, d.size, listStart, littleEndian)
        val out = mutableListOf<RangeEntry>()
        var base = 0L
        var n = 0
        try {
            while (n++ < 1_000_000) {
                when (val op = c.u8()) {
                    Dw.RLE_end_of_list -> break
                    Dw.RLE_base_addressx -> {
                        val idx = c.uleb128()
                        val bv = addrLookup(idx)
                        if (bv == null) { warnings.add("base_addressx unresolved (missing .debug_addr index $idx)"); return out to warnings }
                        base = bv
                    }
                    Dw.RLE_startx_endx -> {
                        val si = addrLookup(c.uleb128()); val ei = addrLookup(c.uleb128())
                        if (si == null || ei == null) { warnings.add("startx_endx unresolved (missing .debug_addr)"); return out to warnings }
                        out.add(RangeEntry(si, ei, si == ei))
                    }
                    Dw.RLE_startx_length -> {
                        val si = addrLookup(c.uleb128()); val len = c.uleb128()
                        if (si == null) { warnings.add("startx_length unresolved (missing .debug_addr)"); return out to warnings }
                        out.add(RangeEntry(si, si + len, len == 0L))
                    }
                    Dw.RLE_offset_pair -> {
                        val sOff = c.uleb128(); val eOff = c.uleb128()
                        out.add(RangeEntry(base + sOff, base + eOff, sOff == eOff))
                    }
                    Dw.RLE_base_address -> base = c.addr(a)
                    Dw.RLE_start_end -> {
                        val s = c.addr(a); val e = c.addr(a); out.add(RangeEntry(s, e, s == e))
                    }
                    Dw.RLE_start_length -> {
                        val s = c.addr(a); val len = c.uleb128(); out.add(RangeEntry(s, s + len, len == 0L))
                    }
                    else -> { warnings.add("unknown rnglist entry 0x${op.toString(16)} at ${c.pos - 1}; list stopped"); break }
                }
            }
        } catch (e: DwarfParseException) {
            warnings.add("truncated .debug_rnglists: ${e.message}")
        }
        return out to warnings
    }

    private data class V5Loc(val listStart: Int, val headerEnd: Int, val addrSize: Int)

    private fun locateV5List(d: ByteArray, attrOffset: Long, index: Long?, cu: CompUnit): V5Loc? {
        if (attrOffset < 0 || attrOffset >= d.size) return null
        // attrOffset for DW_AT_ranges points directly at the list; the header sits earlier,
        // but DW_AT_rnglists_base gives the offset of the header. We accept either:
        // 1) If byte at attrOffset is an RLE opcode, use directly (common: offset = list start).
        // 2) Otherwise treat attrOffset as header base and index selects a list via offsets array.
        val probe = d[attrOffset.toIntExact()].toInt() and 0xff
        if (index == null && probe in 0..7) return V5Loc(attrOffset.toIntExact(), attrOffset.toIntExact(), cu.addressSize)

        // Parse a header starting at attrOffset (rnglists_base).
        val c = Cursor(d, attrOffset.toIntExact(), d.size, attrOffset.toIntExact(), littleEndian)
        return try {
            val (len, is64) = initialLen(c)
            val headerEnd = c.pos + len.toIntExact()
            c.u16() // version
            val addressSize = c.u8()
            c.u8() // segment selector size
            val offsetEntryCount = c.u32().toInt()
            val offEntrySize = if (is64) 8 else 4
            if (index != null) {
                if (index < 0 || index >= offsetEntryCount) return null
                c.at(c.pos + (index * offEntrySize).toInt())
                val rel = if (is64) c.u64() else c.u32()
                V5Loc((attrOffset + rel).toIntExact(), headerEnd, addressSize)
            } else {
                V5Loc(headerEnd, headerEnd, addressSize)
            }
        } catch (_: Exception) { null }
    }

    private fun initialLen(c: Cursor): Pair<Long, Boolean> {
        val first = c.u32()
        if (first == 0xffffffffL) return c.u64() to true
        return first to false
    }

    private fun maxValue(a: Int): Long = when (a) { 1 -> 0xffL; 2 -> 0xffffL; 4 -> 0xffffffffL; 8 -> -1L; else -> -1L }
}

private fun Long.toIntExact(): Int {
    if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseException("offset out of range: $this")
    return toInt()
}
