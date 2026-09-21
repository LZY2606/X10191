package com.compass.dwarf

/**
 * Resolves code ranges for a DIE.
 *
 * DW_AT_high_pc has two meanings:
 *  - address form : absolute end address
 *  - constant form: byte length added to DW_AT_low_pc
 * Zero-length ranges are retained (shown on the map) but never match a query.
 */
class RangeResolver(private val ctx: CuContext, private val issues: MutableList<ParseIssue>) {

    fun resolve(die: DieRecord, rootLowPc: Long): List<AddrRange> {
        val lowAttr = die.attr(DW_AT_low_pc)
        val highAttr = die.attr(DW_AT_high_pc)
        val rangesAttr = die.attr(DW_AT_ranges)

        if (rangesAttr != null) return readRanges(rangesAttr, rootLowPc, die.offset)
        if (lowAttr == null) return emptyList()
        val low = (lowAttr as? AttrValue.Addr)?.v ?: return emptyList()
        if (highAttr == null) return listOf(AddrRange(low, low, zeroLength = true))
        val high = when (highAttr) {
            is AttrValue.Addr -> highAttr.v
            is AttrValue.Num -> low + highAttr.v
            is AttrValue.UNum -> low + highAttr.v.toLong()
            else -> low
        }
        return if (high <= low) listOf(AddrRange(low, high.coerceAtLeast(low), zeroLength = true))
        else listOf(AddrRange(low, high))
    }

    private fun readRanges(attr: AttrValue, rootBase: Long, dieOffset: Int): List<AddrRange> =
        if (ctx.version >= 5) readRngListsV5(attr, dieOffset)
        else readRangesV4(attr, rootBase, dieOffset)

    private fun readRangesV4(attr: AttrValue, baseIn: Long, dieOffset: Int): List<AddrRange> {
        val off = when (attr) {
            is AttrValue.SecOffset -> attr.offset
            is AttrValue.Num -> attr.v
            else -> throw ParseException("bad DW_AT_ranges form at 0x${dieOffset.toString(16)}")
        }
        val sec = ctx.sections.bytes(if (ctx.isDwo) ".debug_ranges.dwo" else ".debug_ranges")
        if (sec.isEmpty()) {
            issues += ParseIssue("ranges", "DW_AT_ranges present but .debug_ranges missing", "error")
            return emptyList()
        }
        val b = Buf(sec); b.seek(off.toInt())
        val out = mutableListOf<AddrRange>()
        var base = baseIn
        val marker = if (ctx.addressSize == 8) -1L else 0xffff_ffffL
        var guard = 0
        while (true) {
            if (++guard > Limits.MAX_RANGES) { issues += ParseIssue("ranges", "range cap reached", "warn"); break }
            val start = readAddr(b); val end = readAddr(b)
            if (start == 0L && end == 0L) break
            if (start == marker) { base = end; continue }
            if (end < start) { issues += ParseIssue("ranges", "inverted range", "warn"); continue }
            addRange(out, base + start, base + end)
        }
        return out
    }

    private class RngHeader(val dwarf64: Boolean, val segSize: Int, val count: Int,
                            val offsetTableStart: Int)

    /** rnglists_base points at the header's unit_length offset. */
    private fun readRngHeader(sec: ByteArray, headerOff: Long): RngHeader {
        val h = Buf(sec); h.seek(headerOff.toInt())
        val first = h.u32()
        val dwarf64 = first == 0xffff_ffffL
        if (dwarf64) h.u64()
        h.u16(); h.u8()
        val seg = h.u8()
        val count = h.u32().toInt()
        return RngHeader(dwarf64, seg, count, h.pos)
    }

    private fun readRngListsV5(attr: AttrValue, dieOffset: Int): List<AddrRange> {
        val secName = if (ctx.isDwo && ctx.sections.has(".debug_rnglists.dwo"))
            ".debug_rnglists.dwo" else ".debug_rnglists"
        val sec = ctx.sections.bytes(secName)
        if (sec.isEmpty()) {
            issues += ParseIssue("rnglists", "DW_AT_ranges present but $secName missing", "error")
            return emptyList()
        }
        var segSize = 0
        var listOff = 0L
        if (attr is AttrValue.SecOffset && attr.formClass == FormClass.RNGLIST) {
            val base = ctx.rnglistsBase ?: throw ParseException("rnglistx without DW_AT_rnglists_base")
            val hdr = readRngHeader(sec, base)
            segSize = hdr.segSize
            if (attr.offset.toInt() !in 0 until hdr.count)
                throw ParseException("rnglistx index ${attr.offset} out of bounds at 0x${dieOffset.toString(16)}")
            val tb = Buf(sec)
            tb.seek(hdr.offsetTableStart + attr.offset.toInt() * (if (hdr.dwarf64) 8 else 4))
            val rel = if (hdr.dwarf64) tb.u64() else tb.u32()
            // offsets are relative to the first byte after unit_length
            listOff = base + (if (hdr.dwarf64) 12 else 4) + rel
        } else when (attr) {
            is AttrValue.SecOffset -> listOff = attr.offset
            is AttrValue.Num -> listOff = attr.v
            else -> throw ParseException("bad DW_AT_ranges form at 0x${dieOffset.toString(16)}")
        }
        val b = Buf(sec); b.seek(listOff.toInt())
        val out = mutableListOf<AddrRange>()
        var base = 0L
        var guard = 0
        while (true) {
            if (++guard > Limits.MAX_RANGES) { issues += ParseIssue("rnglists", "range cap reached", "warn"); break }
            when (b.u8()) {
                DW_RLE_end_of_list -> break
                DW_RLE_base_addressx -> { if (segSize > 0) b.unsigned(segSize); base = addrx(b.uleb().toInt()) }
                DW_RLE_startx_endx -> {
                    val s = addrx(b.uleb().toInt()); val e = addrx(b.uleb().toInt()); addRange(out, s, e)
                }
                DW_RLE_startx_length -> {
                    val s = addrx(b.uleb().toInt()); val l = b.uleb().toLong(); addRange(out, s, s + l)
                }
                DW_RLE_offset_pair -> {
                    val s = base + b.uleb().toLong(); val e = base + b.uleb().toLong(); addRange(out, s, e)
                }
                DW_RLE_base_address -> { if (segSize > 0) b.unsigned(segSize); base = readAddr(b) }
                DW_RLE_start_end -> {
                    val s = readAddr(b); val e = readAddr(b); addRange(out, s, e)
                }
                DW_RLE_start_length -> {
                    val s = readAddr(b); val l = b.uleb().toLong(); addRange(out, s, s + l)
                }
                else -> throw ParseException("unknown DW_RLE in rnglists at 0x${dieOffset.toString(16)}")
            }
        }
        return out
    }

    private fun addRange(out: MutableList<AddrRange>, lo: Long, hi: Long) {
        if (hi < lo) { issues += ParseIssue("rnglists", "inverted range", "warn"); return }
        out += if (hi == lo) AddrRange(lo, hi, true) else AddrRange(lo, hi)
    }

    private fun readAddr(b: Buf): Long = b.unsigned(ctx.addressSize).toLong()

    private fun addrx(index: Int): Long {
        val data = ctx.sections.bytes(if (ctx.isDwo) ".debug_addr.dwo" else ".debug_addr")
        if (data.isEmpty()) throw ParseException("address index used but .debug_addr missing")
        val base = ctx.addrBase ?: 0L
        val ab = Buf(data); ab.seek(base.toInt() + index * ctx.addressSize)
        return ab.unsigned(ctx.addressSize).toLong()
    }
}
