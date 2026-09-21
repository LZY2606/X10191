package compass.dwarf

import java.nio.ByteOrder

data class AddrRange(val start: Long, val end: Long) {
    val length: Long get() = end - start
    fun contains(addr: Long): Boolean = addr >= start && addr < end
    override fun toString(): String = "[0x${start.toString(16)}, 0x${end.toString(16)})"
}

class RangeListResult(
    val ranges: List<AddrRange>,
    val notes: List<String>,
)

object Ranges {

    /** DWARF <= 4 .debug_ranges: pairs of addresses, base-selection entries, 0/0 terminator. */
    fun parseDebugRanges(
        buf: ByteArray, offset: Long, addrSize: Int, order: ByteOrder,
    ): RangeListResult {
        val notes = mutableListOf<String>()
        if (offset < 0 || offset >= buf.size) {
            return RangeListResult(emptyList(), listOf("ranges offset 0x${offset.toString(16)} out of bounds"))
        }
        val c = Cursor(buf, offset.toInt(), buf.size, order)
        val ranges = mutableListOf<AddrRange>()
        var base = 0L
        val baseMarker = if (addrSize == 8) -1L else 0xFFFFFFFFL
        try {
            var count = 0
            while (true) {
                if (++count > Dw.MAX_RANGE_ENTRIES) { notes += "range entry limit hit"; break }
                if (c.remaining < addrSize * 2) { notes += "range list truncated"; break }
                val begin = c.uintN(addrSize)
                val end = c.uintN(addrSize)
                if (begin == 0L && end == 0L) break
                if (begin == baseMarker) { base = end; continue }
                ranges += AddrRange(base + begin, base + end)
            }
        } catch (e: DwarfParseException) {
            notes += "ranges parse error: ${e.message}"
        }
        return RangeListResult(ranges, notes)
    }

    /** DWARF 5 .debug_rnglists. [resolveAddr] maps addrx indexes via .debug_addr. */
    fun parseRngLists(
        buf: ByteArray, offset: Long, addrSize: Int, order: ByteOrder,
        resolveAddr: (Long) -> Long?,
    ): RangeListResult {
        val notes = mutableListOf<String>()
        if (offset < 0 || offset + 4 > buf.size) {
            return RangeListResult(emptyList(), listOf("rnglists offset 0x${offset.toString(16)} out of bounds"))
        }
        val ranges = mutableListOf<AddrRange>()
        try {
            val c = Cursor(buf, offset.toInt(), buf.size, order)
            var unitLength = c.u32()
            val is64 = unitLength == 0xFFFFFFFFL
            if (is64) unitLength = c.u64()
            if (unitLength <= 0 || unitLength > Int.MAX_VALUE) throw DwarfParseException("bad rnglists length")
            val end = (c.pos + unitLength).coerceAtMost(buf.size.toLong()).toInt()
            val version = c.u16()
            if (version < 5) notes += "rnglists version $version unexpected"
            val entryAddrSize = c.u8()
            c.u8() // segment selector size
            val offsetEntryCount = c.u32()
            // Skip the offsets array; entries are walked linearly from here.
            val skip = offsetEntryCount * (if (is64) 8 else 4)
            if (skip > Int.MAX_VALUE || c.remaining < skip.toInt()) throw DwarfParseException("rnglists offsets overrun")
            c.skip(skip.toInt())
            var base = 0L
            var count = 0
            loop@ while (c.pos < end) {
                if (++count > Dw.MAX_RANGE_ENTRIES) { notes += "rnglists entry limit hit"; break }
                when (c.u8()) {
                    Dw.RLE_end_of_list -> break@loop
                    Dw.RLE_base_addressx -> {
                        val idx = c.uleb()
                        base = resolveAddr(idx) ?: run { notes += "unresolved base_addressx $idx"; 0L }
                    }
                    Dw.RLE_startx_endx -> {
                        val s = resolveAddr(c.uleb()); val e = resolveAddr(c.uleb())
                        if (s != null && e != null) ranges += AddrRange(s, e)
                        else notes += "unresolved startx_endx"
                    }
                    Dw.RLE_startx_length -> {
                        val s = resolveAddr(c.uleb()); val len = c.uleb()
                        if (s != null) ranges += AddrRange(s, s + len) else notes += "unresolved startx_length"
                    }
                    Dw.RLE_offset_pair -> {
                        val b = c.uleb(); val e = c.uleb()
                        ranges += AddrRange(base + b, base + e)
                    }
                    Dw.RLE_base_address -> base = c.uintN(entryAddrSize)
                    Dw.RLE_start_end -> {
                        val s = c.uintN(entryAddrSize); val e = c.uintN(entryAddrSize)
                        ranges += AddrRange(s, e)
                    }
                    Dw.RLE_start_length -> {
                        val s = c.uintN(entryAddrSize); val len = c.uleb()
                        ranges += AddrRange(s, s + len)
                    }
                    else -> { notes += "unknown RLE code; list aborted"; break@loop }
                }
            }
        } catch (e: DwarfParseException) {
            notes += "rnglists parse error: ${e.message}"
        }
        return RangeListResult(ranges, notes)
    }
}
