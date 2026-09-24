package compass.dwarf

import compass.binary.ByteReader
import compass.binary.ParseException
import compass.binary.uleb

/** Reads range lists for a DIE: low_pc/high_pc (two high_pc meanings) or a ranges table. */
object Ranges {
    private const val MAX_ENTRIES = 1_000_000

    /** Addresses are returned relative to the file's link-time base (no load bias). */
    fun rangesFor(
        die: DIE,
        cu: CompUnit,
        sections: DwarfSections,
    ): List<AddrRange> {
        val lowPc = (die.attrValue(DW.AT.low_pc) as? AttrValue.Addr)?.value
        val highPc = die.attrValue(DW.AT.high_pc)
        val direct = mutableListOf<AddrRange>()
        if (lowPc != null) {
            when (highPc) {
                is AttrValue.Addr -> direct.add(AddrRange(lowPc, highPc.value))
                is AttrValue.Const -> direct.add(AddrRange(lowPc, lowPc + highPc.value))
                else -> if (highPc == null) direct.add(AddrRange(lowPc, lowPc)) // zero-length anchor
            }
        }
        val rangesAttr = die.attrValue(DW.AT.ranges) ?: return direct
        val table = when (rangesAttr) {
            is AttrValue.SectionOffset -> readTable(rangesAttr.section, rangesAttr.offset, cu, sections, die)
            else -> return direct
        }
        return table + direct
    }

    private fun readTable(
        sectionHint: String,
        offset: Long,
        cu: CompUnit,
        sections: DwarfSections,
        die: DIE,
    ): List<AddrRange> {
        // DWARF 5: .debug_rnglists (possibly .rnglists.dwo). The offset may be an
        // rnglistx index (resolved against rnglists_base) or a raw sec_offset.
        val rngSectionName = when {
            sections.has(".debug_rnglists") -> ".debug_rnglists"
            sections.has(".debug_rnglists.dwo") -> ".debug_rnglists.dwo"
            else -> null
        }
        return if (cu.version >= 5 && rngSectionName != null) {
            val actualOff = if (sectionHint == "__indexed__") {
                resolveRnglistx(rngSectionName, sections, cu, offset.toInt())
            } else offset
            readRnglists(rngSectionName, sections, actualOff, cu)
        } else {
            readDebugRanges(sections, offset, cu, die)
        }
    }

    private fun resolveRnglistx(sectionName: String, sections: DwarfSections, cu: CompUnit, index: Int): Long {
        val sec = sections.bytes(sectionName)!!
        val r = ByteReader(sec)
        val length0 = r.u4().toLong() and 0xffffffffL
        val is64 = length0 == 0xffffffffL
        val length = if (is64) r.u8() else length0
        val end = r.pos + length
        r.u2() // version
        r.u1() // address_size
        r.u1() // segment_selector_size
        val offsetArrayOff = r.u4().toLong() and 0xffffffffL
        val arrayStart = r.pos + offsetArrayOff
        val entrySize = if (cu.is64BitDwarf) 8 else 4
        val pos = (cu.rnglistsBase + arrayStart + index.toLong() * entrySize).toInt()
        if (pos + entrySize > end) throw ParseException("rnglistx index $index out of bounds")
        r.seek(pos)
        return cu.rnglistsBase + (if (entrySize == 8) r.u8() else (r.u4().toLong() and 0xffffffffL))
    }

    private fun readRnglists(sectionName: String, sections: DwarfSections, offset: Long, cu: CompUnit): List<AddrRange> {
        val sec = sections.bytes(sectionName)!!
        if (offset < 0 || offset >= sec.size) throw ParseException("rnglist offset 0x${offset.toString(16)} out of bounds")
        val r = ByteReader(sec, offset.toInt(), sec.size, offset.toInt())
        val out = mutableListOf<AddrRange>()
        var base = 0L
        var count = 0
        while (r.remaining() > 0) {
            if (++count > MAX_ENTRIES) throw ParseException("rnglist too many entries")
            val kind = r.u1()
            when (kind) {
                DW.RLE.end_of_list -> return out
                DW.RLE.base_addressx -> {
                    val idx = r.uleb().toInt()
                    base = readAddrIndex(cu, sections, idx) ?: throw ParseException("bad base_addressx $idx")
                }
                DW.RLE.startx_endx -> {
                    val s = readAddrIndex(cu, sections, r.uleb().toInt())
                    val e = readAddrIndex(cu, sections, r.uleb().toInt())
                    if (s != null && e != null) out.add(AddrRange(s, e))
                }
                DW.RLE.startx_length -> {
                    val s = readAddrIndex(cu, sections, r.uleb().toInt())
                    val len = r.uleb()
                    if (s != null) out.add(AddrRange(s, s + len))
                }
                DW.RLE.offset_pair -> {
                    val s = r.uleb(); val len = r.uleb()
                    out.add(AddrRange(base + s, base + s + len))
                }
                DW.RLE.base_address -> base = readRawAddr(r, cu.addressSize)
                DW.RLE.start_end -> {
                    val s = readRawAddr(r, cu.addressSize)
                    val e = readRawAddr(r, cu.addressSize)
                    out.add(AddrRange(s, e))
                }
                DW.RLE.start_length -> {
                    val s = readRawAddr(r, cu.addressSize)
                    val len = readRawAddr(r, cu.addressSize)
                    out.add(AddrRange(s, s + len))
                }
                else -> throw ParseException("unsupported/unknown rnglist entry kind 0x${kind.toString(16)} (isolating CU)")
            }
        }
        throw ParseException("unterminated rnglist at 0x${offset.toString(16)}")
    }

    private fun readDebugRanges(sections: DwarfSections, offset: Long, cu: CompUnit, die: DIE): List<AddrRange> {
        val sec = sections.bytes(".debug_ranges")
            ?: throw ParseException("DW_AT_ranges present but .debug_ranges missing")
        if (offset < 0 || offset >= sec.size) throw ParseException("ranges offset 0x${offset.toString(16)} out of bounds")
        val r = ByteReader(sec, offset.toInt(), sec.size, offset.toInt())
        val width = cu.addressSize
        val max = if (width == 8) -1L else 0xffffffffL
        var base = (die.unit?.root?.attrValue(DW.AT.low_pc) as? AttrValue.Addr)?.value ?: 0L
        val out = mutableListOf<AddrRange>()
        var count = 0
        while (true) {
            if (++count > MAX_ENTRIES) throw ParseException("debug_ranges too many entries")
            val start = readRawAddr(r, width)
            val end = readRawAddr(r, width)
            if (start == 0L && end == 0L) return out
            if (start == max) {
                base = end
                continue
            }
            out.add(AddrRange(base + start, base + end))
        }
    }

    private fun readRawAddr(r: ByteReader, width: Int): Long = when (width) {
        4 -> r.u4().toLong() and 0xffffffffL
        8 -> r.u8()
        2 -> r.u2().toLong() and 0xffffL
        1 -> r.u1().toLong()
        else -> throw ParseException("bad address width $width")
    }

    private fun readAddrIndex(cu: CompUnit, sections: DwarfSections, index: Int): Long? {
        val addr = sections.bytes(".debug_addr") ?: return null
        val width = cu.addressSize
        val at = cu.addrBase + index.toLong() * width
        if (at + width > addr.size) return null
        val r = ByteReader(addr, at.toInt(), (at + width).toInt(), at.toInt())
        return readRawAddr(r, width)
    }
}
