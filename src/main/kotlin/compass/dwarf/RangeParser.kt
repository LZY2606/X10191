package compass.dwarf

import compass.dwarf.DW.DW_RLE_base_address
import compass.dwarf.DW.DW_RLE_base_addressx
import compass.dwarf.DW.DW_RLE_end_of_list
import compass.dwarf.DW.DW_RLE_offset_pair
import compass.dwarf.DW.DW_RLE_start_end
import compass.dwarf.DW.DW_RLE_start_length
import compass.dwarf.DW.DW_RLE_startx_endx
import compass.dwarf.DW.DW_RLE_startx_length
import compass.model.AddrRange
import compass.model.BoundedReader
import compass.model.ParseIssue
import java.nio.ByteOrder

/**
 * Resolves range lists for both .debug_ranges (DWARF <= 4) and
 * .debug_rnglists (DWARF 5).  Selectors default to 0 unless a future
 * extension supplies one.
 */
class RangeResolver(private val sections: DebugSections) {
    private val order: ByteOrder = if (sections.elf.littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
    val issues = ArrayList<ParseIssue>()

    /**
     * DWARF <= 4 list.
     * @param addressSize CU address size
     * @param defaultBase base address to use before any base-selection entry
     *        (the enclosing DIE's DW_AT_low_pc per spec).
     */
    fun legacyList(offset: Long, addressSize: Int, defaultBase: Long, selector: Long = 0L): List<AddrRange> {
        val data = sections.ranges ?: return emptyList()
        if (offset < 0 || offset >= data.size) {
            issues += ParseIssue("WARNING", "RNGOOB", ".debug_ranges offset $offset out of bounds", ".debug_ranges", offset)
            return emptyList()
        }
        val r = BoundedReader(data, offset.toInt(), data.size, order)
        val max = if (addressSize == 8) -1L else 0xffffffffL
        val out = ArrayList<AddrRange>()
        var base = defaultBase
        while (r.remaining >= addressSize * 2) {
            val a = r.uint(addressSize)
            val b = r.uint(addressSize)
            if (a == 0L && b == 0L) break
            if (a == max) { base = b; continue }
            val start = (base + a)
            val end = (base + b)
            if (end < start) {
                issues += ParseIssue("WARNING", "RNGREV", "reversed range [$start,$end)", ".debug_ranges", r.pos.toLong())
                continue
            }
            out += AddrRange(selector, start, end)
        }
        return out
    }

    /**
     * DWARF 5 .debug_rnglists. [offset] is either the list header offset for
     * DW_FORM_rnglistx (indexed via CU rnglists_base), or the absolute list
     * offset for DW_FORM_sec_offset.
     */
    fun dwarf5List(offset: Long, indexed: Boolean, rnglistsBase: Long, addressSize: Int, selector: Long = 0L): List<AddrRange> {
        val data = sections.rnglists ?: return emptyList()
        var listStart = offset
        if (indexed) {
            val headerStart = rnglistsBase.toInt()
            if (headerStart < 0 || headerStart + 8 > data.size) {
                issues += ParseIssue("WARNING", "RNGOOB", "rnglists_base $rnglistsBase invalid", ".debug_rnglists", rnglistsBase)
                return emptyList()
            }
            val hr = BoundedReader(data, headerStart, data.size, order)
            hr.u32()           // unit_length
            hr.u16()           // version
            hr.u8(); hr.u8()   // address_size, segment_selector_size
            val offsetEntryCount = hr.u32().toInt()
            val idx = offset.toInt()
            if (idx >= offsetEntryCount) {
                issues += ParseIssue("WARNING", "RNGIDX", "rnglist index $idx >= entries $offsetEntryCount", ".debug_rnglists", rnglistsBase)
                return emptyList()
            }
            val tableOff = hr.pos + idx * 4
            val rel = BoundedReader(data, tableOff, data.size, order).u32()
            listStart = rnglistsBase + rel
        }
        if (listStart < 0 || listStart >= data.size) {
            issues += ParseIssue("WARNING", "RNGOOB", "rnglist start $listStart oob", ".debug_rnglists", listStart)
            return emptyList()
        }
        val r = BoundedReader(data, listStart.toInt(), data.size, order)
        val out = ArrayList<AddrRange>()
        var base = 0L
        while (r.remaining > 0) {
            val enc = r.u8()
            when (enc) {
                DW_RLE_end_of_list -> break
                DW_RLE_base_addressx -> base = readAddrIndex(r.uleb())
                DW_RLE_startx_endx -> {
                    val s = readAddrIndex(r.uleb()); val e = readAddrIndex(r.uleb())
                    out += AddrRange(selector, s, e)
                }
                DW_RLE_startx_length -> {
                    val s = readAddrIndex(r.uleb()); val len = r.uleb()
                    out += AddrRange(selector, s, s + len)
                }
                DW_RLE_offset_pair -> {
                    val s = base + r.uleb(); val e = base + r.uleb()
                    out += AddrRange(selector, s, e)
                }
                DW_RLE_base_address -> base = r.uint(addressSize)
                DW_RLE_start_end -> {
                    val s = r.uint(addressSize); val e = r.uint(addressSize)
                    out += AddrRange(selector, s, e)
                }
                DW_RLE_start_length -> {
                    val s = r.uint(addressSize); val len = r.uleb()
                    out += AddrRange(selector, s, s + len)
                }
                else -> {
                    issues += ParseIssue("WARNING", "RNGENC", "unknown rnglist encoding 0x${enc.toString(16)}; list aborted to avoid desync", ".debug_rnglists", r.pos.toLong() - 1)
                    break
                }
            }
        }
        return out
    }

    /** Reads .debug_addr[index] honoring the DWARF5 header at [addrBase]. */
    fun readAddrIndex(operand: Long, addrBase: Long = 0L, addressSize: Int = 8): Long {
        val data = sections.addr ?: return -1L
        if (addrBase <= 0L) {
            // GNU .debug_addr has no header
            val off = operand * addressSize
            if (off < 0 || off + addressSize > data.size) return -1L
            return BoundedReader(data, off.toInt(), data.size, order).uint(addressSize)
        }
        val hr = BoundedReader(data, addrBase.toInt(), data.size, order)
        if (hr.remaining < 8) return -1L
        hr.u32() // unit_length
        hr.u16() // version
        hr.u8()  // address_size
        hr.u8()  // segment_selector_size
        val off = hr.pos + operand * addressSize
        if (off + addressSize > data.size) return -1L
        return BoundedReader(data, off.toInt(), data.size, order).uint(addressSize)
    }
}
