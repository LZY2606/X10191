package compass.dwarf

import compass.elf.Reader
import compass.model.AddressRange

object Ranges {
    /** DWARF4 .debug_ranges list at [offset]; [cuBase] is the unit's default base address. */
    fun parseDebugRanges(data: ByteArray, offset: Long, cuBase: Long, addrSize: Int, bigEndian: Boolean): List<AddressRange> {
        if (offset < 0 || offset >= data.size) throw BadReference("ranges offset $offset out of bounds (size ${data.size})")
        val r = Reader(data, offset.toInt(), data.size, bigEndian)
        val out = ArrayList<AddressRange>()
        var base = cuBase
        val mask = if (addrSize == 8) -1L else 0xFFFFFFFFL
        while (true) {
            if (out.size > Limits.MAX_RANGE_ENTRIES) throw BadReference("range list too long")
            var begin = 0L; var end = 0L
            for (i in 0 until addrSize) begin = begin or (r.u8().toLong() shl (8 * i))
            for (i in 0 until addrSize) end = end or (r.u8().toLong() shl (8 * i))
            if (begin == 0L && end == 0L) break
            if (begin == mask) { base = end; continue }
            out.add(AddressRange(base + begin, base + end))
        }
        return out
    }

    /** DWARF5 .debug_rnglists list. [offsetOrIndex] is a section offset (sec_offset form)
     *  or a rnglistx index when [isIndex] is true. [base] is the unit's rnglists_base. */
    fun parseRngLists(
        data: ByteArray, offsetOrIndex: Long, isIndex: Boolean, cuBase: Long,
        addrSize: Int, bigEndian: Boolean, base: Long, sections: DwarfSections,
    ): List<AddressRange> {
        val offset: Long = if (isIndex) {
            // offsets array lives in the header at [base]; entry i is a u32 relative to base
            val hdr = Reader(data, base.toInt(), data.size, bigEndian)
            var len = hdr.u32()
            if (len == 0xFFFFFFFFL) len = hdr.u64()
            hdr.u16() // version
            hdr.u8(); hdr.u8() // addr_size, segment size
            val count = hdr.u32()
            if (offsetOrIndex >= count) throw BadReference("rnglistx index $offsetOrIndex >= offset_entry_count $count")
            val entryPos = (hdr.pos + offsetOrIndex * 4).toInt()
            val er = Reader(data, entryPos, data.size, bigEndian)
            base + er.u32()
        } else base + offsetOrIndex

        if (offset < 0 || offset >= data.size) throw BadReference("rnglists offset $offset out of bounds (size ${data.size})")
        val r = Reader(data, offset.toInt(), data.size, bigEndian)
        val out = ArrayList<AddressRange>()
        var curBase = cuBase
        fun readAddr(): Long {
            var v = 0L
            for (i in 0 until addrSize) v = v or (r.u8().toLong() shl (8 * i))
            return v
        }
        while (true) {
            if (out.size > Limits.MAX_RANGE_ENTRIES) throw BadReference("rnglist too long")
            val kind = r.u8()
            when (kind) {
                Rle.END_OF_LIST -> return out
                Rle.BASE_ADDRESSX -> {
                    val idx = r.uleb128()
                    curBase = addrAt(sections, 0, idx, addrSize)
                }
                Rle.STARTX_ENDX -> {
                    val s = addrAt(sections, 0, r.uleb128(), addrSize)
                    val e = addrAt(sections, 0, r.uleb128(), addrSize)
                    out.add(AddressRange(s, e))
                }
                Rle.STARTX_LENGTH -> {
                    val s = addrAt(sections, 0, r.uleb128(), addrSize)
                    val len = r.uleb128()
                    out.add(AddressRange(s, s + len))
                }
                Rle.OFFSET_PAIR -> {
                    val b = r.uleb128(); val e = r.uleb128()
                    out.add(AddressRange(curBase + b, curBase + e))
                }
                Rle.BASE_ADDRESS -> curBase = readAddr()
                Rle.START_END -> out.add(AddressRange(readAddr(), readAddr()))
                Rle.START_LENGTH -> {
                    val s = readAddr(); val len = r.uleb128()
                    out.add(AddressRange(s, s + len))
                }
                else -> throw BadReference("unknown DW_RLE code $kind")
            }
        }
    }

    private fun addrAt(sections: DwarfSections, base: Long, index: Long, addrSize: Int): Long {
        val table = sections.addr ?: throw BadReference(".debug_addr missing for addrx index $index")
        val off = base + index * addrSize
        if (off < 0 || off + addrSize > table.size) throw BadReference("addrx index $index out of bounds")
        val r = Reader(table, off.toInt(), table.size, sections.bigEndian)
        var v = 0L
        for (i in 0 until addrSize) v = v or (r.u8().toLong() shl (8 * i))
        return v
    }
}
