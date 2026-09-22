package compass

/**
 * Resolve DW_AT_ranges values.
 *  - DWARF <=4: .debug_ranges pairs of address_size words, with base/end markers.
 *  - DWARF 5 : .debug_rnglists, including address-index (startx/length) entries.
 * Zero-length ranges are preserved on purpose.
 */
class RangeReader(private val ctx: ParseContext) {

    private val v4cache = HashMap<String, List<Long>>()

    fun readV4(section: ByteArray, offset: Long, addressSize: Int, selectorSize: Int, base: TargetAddress): List<AddrRange> {
        val key = "$addressSize:$selectorSize:$offset"
        // results depend on base, so cannot cache result, but parsing is simple.
        val c = ByteCursor(section, offset.toInt(), section.size, ".debug_ranges")
        val out = mutableListOf<AddrRange>()
        var curBase = base
        var n = 0
        while (true) {
            if (++n > Limits.MAX_RANGES) throw CursorException(".debug_ranges: too many entries")
            c.ensure(2 * addressSize)
            val a = c.address(addressSize)
            val b = c.address(addressSize)
            if (a == -1L) {
                if (b == 0L) break
                curBase = TargetAddress(b, curBase.segment)
                continue
            }
            out.add(AddrRange(TargetAddress(curBase.offset + a, curBase.segment), TargetAddress(curBase.offset + b, curBase.segment)))
            if (out.size > Limits.MAX_RANGES) throw CursorException(".debug_ranges: range count exceeds limit")
        }
        return out
    }

    /** v5 header table for one rnglists unit starting at headerOffset. */
    fun readRnglistsHeader(section: ByteArray, headerOffset: Int): RngListsHeader {
        val c = ByteCursor(section, headerOffset, section.size, ".debug_rnglists")
        val (end64, end) = readInitialLength(c)
        val version = c.u16()
        val addressSize = c.u8()
        val selectorSize = c.u8()
        val offsetArrayOffset = c.u32().toInt()
        val offsetArraySize = c.u32().toInt()
        val tableStart = c.pos
        val offsets = ArrayList<Long>()
        if (offsetArrayOffset > 0) {
            c.seek(headerOffset + offsetArrayOffset)
            var o = 0
            while (o < offsetArraySize) {
                offsets.add(c.u32()); o += 4
                if (offsets.size > Limits.MAX_RANGES) throw CursorException(".debug_rnglists: offset array too large")
            }
        }
        return RngListsHeader(headerOffset, end64, end, version, addressSize, selectorSize, tableStart, offsets)
    }

    /**
     * Parse a v5 rnglist at a CU-relative offset.
     * @param rnglistsBase DW_AT_rnglists_base offset inside .debug_rnglists (absolute section offset of table).
     */
    fun readV5List(
        section: ByteArray,
        headerOffset: Int,
        rnglistsBase: Long,
        formOffset: Long,
        addressLookup: (Long) -> TargetAddress,
        defaultBase: TargetAddress,
    ): List<AddrRange> {
        val header = readRnglistsHeader(section, headerOffset)
        // For DW_FORM_rnglistx the index selects in the offset table, and the value is relative to
        // the table start (DW_AT_rnglists_base).
        val targetOff = when {
            else -> formOffset // DW_FORM_sec_offset: offset from header start
        }
        val startPos = (headerOffset + targetOff).toInt()
        val c = ByteCursor(section, startPos, header.end, ".debug_rnglists")
        val out = mutableListOf<AddrRange>()
        var base = defaultBase
        var n = 0
        while (true) {
            if (++n > Limits.MAX_RANGES) throw CursorException(".debug_rnglists: too many entries")
            if (c.remaining == 0) throw CursorException(".debug_rnglists: list without end-of-list")
            val kind = c.u8()
            when (kind) {
                Dw.RLE_END_OF_LIST -> break
                Dw.RLE_BASE_ADDRESSX -> {
                    val idx = c.uleb()
                    base = addressLookup(idx)
                }
                Dw.RLE_STARTX_ENDX -> {
                    val s = addressLookup(c.uleb())
                    val e = addressLookup(c.uleb())
                    out.add(AddrRange(s, e))
                }
                Dw.RLE_STARTX_LENGTH -> {
                    val s = addressLookup(c.uleb())
                    val len = c.uleb()
                    out.add(AddrRange(s, TargetAddress(s.offset + len, s.segment)))
                }
                Dw.RLE_OFFSET_PAIR -> {
                    val s = c.sleb()
                    val e = c.sleb()
                    out.add(AddrRange(TargetAddress(base.offset + s, base.segment), TargetAddress(base.offset + e, base.segment)))
                }
                Dw.RLE_BASE_ADDRESS -> {
                    base = TargetAddress(c.address(header.addressSize), base.segment)
                }
                Dw.RLE_START_END -> {
                    val s = c.address(header.addressSize)
                    val e = c.address(header.addressSize)
                    out.add(AddrRange(TargetAddress(s, base.segment), TargetAddress(e, base.segment)))
                }
                Dw.RLE_START_LENGTH -> {
                    val s = c.address(header.addressSize)
                    val len = c.address(header.addressSize)
                    out.add(AddrRange(TargetAddress(s, base.segment), TargetAddress(s.offset + len, base.segment)))
                }
                else -> throw CursorException(".debug_rnglists: unknown RLE 0x${kind.toString(16)} at ${c.pos - 1}")
            }
            if (out.size > Limits.MAX_RANGES) throw CursorException(".debug_rnglists: range count exceeds limit")
        }
        return out
    }

    /**
     * Resolve a DW_FORM_rnglistx index into an offset usable by readV5List using the header's offset array.
     */
    fun resolveRnglistxOffset(section: ByteArray, headerOffset: Int, index: Long): Long {
        val header = readRnglistsHeader(section, headerOffset)
        if (index < 0 || index >= header.offsets.size)
            throw CursorException(".debug_rnglists: rnglistx index $index out of bounds (table=${header.offsets.size})")
        return header.offsets[index.toInt()]
    }

    companion object {
        fun readInitialLength(c: ByteCursor): Pair<Boolean, Int> {
            val start = c.pos
            val len = c.u32()
            val (is64, length) = when (len) {
                0xffffffffL -> true to c.u64()
                in 0L..0xfffffff0L -> false to len
                else -> throw CursorException("${c.name}: reserved initial length at $start")
            }
            if (length < 0 || length > Limits.MAX_UNIT_LENGTH) throw CursorException("${c.name}: bad unit_length $length")
            val end = c.pos + length.toInt()
            if (end > c.sectionEnd) throw CursorException("${c.name}: unit_length overruns section at $start")
            return is64 to end
        }
    }
}

data class RngListsHeader(
    val start: Int,
    val end: Int,
    val is64: Boolean,
    val version: Int,
    val addressSize: Int,
    val selectorSize: Int,
    val tableStart: Int,
    val offsets: List<Long>,
)
