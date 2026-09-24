package linecompass.dwarf

/**
 * Decodes address range lists for DWARF 2-4 (.debug_ranges) and DWARF 5
 * (.debug_rnglists). All reads are bounded; a corrupt list throws
 * DwarfFormatException, which the CU driver turns into a CU-local warning
 * instead of losing the whole file.
 */
object RangeLists {
    /** DWARF 2-4 .debug_ranges contribution beginning at [offset]. */
    fun readDebugRanges(
        sections: SectionBundle, offset: Long, cuBase: Long, addressSize: Int
    ): List<AddressRange> {
        val data = sections.get(".debug_ranges")
            ?: throw DwarfFormatException("DW_AT_ranges without .debug_ranges")
        val r = BoundedReader(
            data, offset.toInt(), data.size - offset.toInt(), "debug_ranges", addressSize
        )
        val out = ArrayList<AddressRange>()
        var base = cuBase
        var guard = 0
        while (true) {
            if (++guard > 1_000_000) throw DwarfFormatException("ranges list too long")
            val a = if (addressSize == 4) r.u32() else r.u64()
            val b = if (addressSize == 4) r.u32() else r.u64()
            val max = if (addressSize == 4) 0xffffffffL else -1L
            if (a == 0L && b == 0L) break
            if (a == max) { // base address entry
                base = b
                continue
            }
            val start = base + a
            val end = base + b
            if (end < start) throw DwarfFormatException("inverted range [$start,$end) in .debug_ranges")
            out.add(AddressRange(start, end, "ranges", start == end))
        }
        return out
    }

    /**
     * Scans every table in .debug_rnglists (DWARF 5). Tables tile the
     * section back-to-back. We retain the offset array so rnglistx indexes
     * resolve deterministically. addrx entries inside lists are resolved
     * lazily at lookup time via the CU-supplied [addrOf].
     */
    fun scanRngListTables(sections: SectionBundle): Map<Int, RawRngTable> {
        val data = sections.get(".debug_rnglists") ?: return emptyMap()
        val tables = LinkedHashMap<Int, RawRngTable>()
        val sectionR = BoundedReader(data, 0, data.size, "debug_rnglists")
        while (sectionR.remaining > 0) {
            val headerStart = sectionR.pos
            val len = readInitialLength(sectionR)
            val body = BoundedReader(
                data, len.start, len.end - len.start, "debug_rnglists",
                if (len.is64bit) 8 else 4
            )
            val version = body.u16()
            if (version != 5) throw DwarfFormatException("unsupported rnglists version $version")
            val addressSize = body.u8()
            val segmentSize = body.u8()
            val offsetCount = body.u32().toInt()
            val offsetsArrayStart = body.pos
            val offsets = LongArray(offsetCount) { body.u32().toLong() and 0xffffffffL }
            // Raw lists are byte slices: decode per CU so the right .debug_addr
            // base is used.
            val rawLists = LongArray(offsetCount) { headerStart + offsets[it].toInt() }
            tables[offsetsArrayStart] = RawRngTable(
                headerStart, len.end, addressSize, segmentSize, offsets, rawLists
            )
            sectionR.seek(len.end, counted = false)
        }
        return tables
    }

    /** Decodes one DWARF 5 list beginning at [listOffset] using [addrOf]. */
    fun readRngList(
        sections: SectionBundle, listOffset: Int, addressSize: Int,
        addrOf: (Long) -> Long,
    ): List<AddressRange> {
        val data = sections.get(".debug_rnglists")
            ?: throw DwarfFormatException("rnglist without .debug_rnglists")
        val r = BoundedReader(data, listOffset, data.size - listOffset, "rnglist", addressSize)
        val out = ArrayList<AddressRange>()
        var base = 0L
        var guard = 0
        while (true) {
            if (++guard > 1_000_000) throw DwarfFormatException("rnglist too long")
            when (val kind = r.u8()) {
                RangeEntry.END_OF_LIST -> return out
                RangeEntry.BASE_ADDRESSX -> base = addrOf(r.uleb())
                RangeEntry.BASE_ADDRESS -> base = if (addressSize == 4) r.u32() else r.u64()
                RangeEntry.STARTX_ENDX -> {
                    val s = addrOf(r.uleb()); val e = addrOf(r.uleb())
                    if (e < s) throw DwarfFormatException("inverted startx_endx range")
                    out.add(AddressRange(s, e, "rnglist", s == e))
                }
                RangeEntry.STARTX_LENGTH -> {
                    val s = addrOf(r.uleb()); val l = r.uleb()
                    out.add(AddressRange(s, s + l, "rnglist", l == 0L))
                }
                RangeEntry.START_END -> {
                    val s = if (addressSize == 4) r.u32() else r.u64()
                    val e = if (addressSize == 4) r.u32() else r.u64()
                    if (e < s) throw DwarfFormatException("inverted start_end range")
                    out.add(AddressRange(s, e, "rnglist", s == e))
                }
                RangeEntry.START_LENGTH -> {
                    val s = if (addressSize == 4) r.u32() else r.u64()
                    val l = if (addressSize == 4) r.u32() else r.u64()
                    out.add(AddressRange(s, s + l, "rnglist", l == 0L))
                }
                RangeEntry.OFFSET_PAIR -> {
                    val a = r.uleb(); val b = r.uleb()
                    out.add(AddressRange(base + a, base + b, "rnglist", a == b))
                }
                else -> throw DwarfFormatException("unknown rnglist content type $kind")
            }
        }
    }
}

/** Un-decoded DWARF 5 rnglist table: offsets are section-absolute byte positions. */
data class RawRngTable(
    val headerStart: Int,
    val headerEnd: Int,
    val addressSize: Int,
    val segmentSize: Int,
    val offsets: LongArray,
    val listPositions: LongArray,
)
