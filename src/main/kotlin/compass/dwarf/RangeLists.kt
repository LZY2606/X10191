package compass.dwarf

import compass.elf.BinaryTruncatedException
import compass.elf.Reader
import compass.model.Endian

data class RawRange(val selector: Long, val start: Long, val end: Long)

/**
 * .debug_ranges (DWARF 4 and earlier).
 *
 * Address-size selectors (0xffffffff..) introduce an address_selector value
 * (the "segment") before base entries. We honour it: following entries carry
 * that selector until the next selector entry. Zero-length ranges are legal
 * and preserved.
 */
object RangesV4 {
    fun parse(
        data: ByteArray,
        offset: Long,
        endian: Endian,
        addrSize: Int,
        dwarf64: Boolean,
        cuLowPc: Long,
    ): List<RawRange> {
        if (data.isEmpty()) throw BinaryTruncatedException("DW_AT_ranges but no .debug_ranges")
        if (offset < 0 || offset >= data.size) throw BinaryTruncatedException("ranges offset out of section")
        val r = Reader(data, endian)
        r.seek(offset.toInt())
        val resolved = ArrayList<RawRange>()
        var base = cuLowPc
        var selector = 0L
        var guard = 0
        while (r.remaining() >= 2 * addrSize) {
            if (guard++ > 1_000_000) throw BinaryTruncatedException("rnglist loop guard")
            val a = Forms.readAddr(r, addrSize)
            val b = Forms.readAddr(r, addrSize)
            val max = if (addrSize == 8) -1L else 0xffffffffL
            when {
                a == 0L && b == 0L -> return resolved
                a == max && b == 0L -> {
                    // Base address entry
                    selector = 0L
                    base = Forms.readAddr(r, addrSize)
                }
                a == max && b == max -> {
                    // Address selector entry with zero selector bytes
                    selector = 0L
                }
                a == max -> {
                    // Address selector entry specifying selector byte length
                    val selBytes = (b and 0xffL).toInt()
                    selector = if (selBytes > 0) Forms.readAddr(r, selBytes.coerceAtMost(8)) else 0L
                }
                else -> resolved.add(RawRange(selector, base + a, base + b))
            }
        }
        throw BinaryTruncatedException(".debug_ranges list not terminated")
    }
}

/**
 * .debug_rnglists (DWARF 5).
 */
object RngListsV5 {
    const val DW_RLE_end_of_list = 0x00
    const val DW_RLE_base_addressx = 0x01
    const val DW_RLE_startx_endx = 0x02
    const val DW_RLE_startx_length = 0x03
    const val DW_RLE_offset_pair = 0x04
    const val DW_RLE_base_address = 0x05
    const val DW_RLE_start_end = 0x06
    const val DW_RLE_start_length = 0x07

    data class Header(
        val offsetSize: Int,
        val addrSize: Int,
        val segmentSize: Int,
        val offsetEntryCount: Int,
        val offsetTableStart: Int,
        val firstEntry: Int,
    )

    /** Parse the rnglists header beginning at `offset` in .debug_rnglists. */
    fun header(data: ByteArray, offset: Long, endian: Endian): Header {
        val r = Reader(data, endian)
        r.seek(offset.toInt())
        val unitLen = r.initialLength()
        r.u16() // version
        val addrSize = r.u8()
        val segmentSize = r.u8()
        val offsetSize = r.u8()
        val offsetEntryCount = r.u8()
        val tableStart = r.pos
        val firstEntry = tableStart + offsetEntryCount * offsetSize
        return Header(offsetSize, addrSize, segmentSize, offsetEntryCount, tableStart, firstEntry)
    }

    /**
     * Parse a list. `listOffset` is the absolute offset of the list (either
     * header base + offsets[index] or a direct DW_FORM_sec_offset value).
     */
    fun parse(
        data: ByteArray,
        listOffset: Long,
        endian: Endian,
        addrSize: Int,
        segmentSize: Int,
        readAddrIndex: (Long) -> Long,
    ): List<RawRange> {
        if (data.isEmpty()) throw BinaryTruncatedException("DW_AT_ranges but no .debug_rnglists")
        if (listOffset < 0 || listOffset >= data.size) throw BinaryTruncatedException("rnglist offset out of section")
        val r = Reader(data, endian)
        r.seek(listOffset.toInt())
        val out = ArrayList<RawRange>()
        var base = 0L
        var selector = 0L
        var guard = 0
        while (true) {
            if (guard++ > 1_000_000) throw BinaryTruncatedException("rnglist5 loop guard")
            val op = r.u8()
            fun seg(): Long = if (segmentSize > 0) Forms.readAddr(r, segmentSize.coerceAtMost(8)) else 0L
            when (op) {
                DW_RLE_end_of_list -> break
                DW_RLE_base_addressx -> { val idx = r.uleb128(); selector = seg(); base = readAddrIndex(idx) }
                DW_RLE_startx_endx -> {
                    val s = readAddrIndex(r.uleb128()); val e = readAddrIndex(r.uleb128())
                    out.add(RawRange(seg(), s, e))
                }
                DW_RLE_startx_length -> {
                    val s = readAddrIndex(r.uleb128()); val len = r.uleb128()
                    out.add(RawRange(seg(), s, s + len))
                }
                DW_RLE_offset_pair -> {
                    val sOff = r.uleb128(); val eOff = r.uleb128()
                    out.add(RawRange(selector, base + sOff, base + eOff))
                }
                DW_RLE_base_address -> { selector = seg(); base = Forms.readAddr(r, addrSize) }
                DW_RLE_start_end -> {
                    selector = seg()
                    val s = Forms.readAddr(r, addrSize); val e = Forms.readAddr(r, addrSize)
                    out.add(RawRange(selector, s, e))
                }
                DW_RLE_start_length -> {
                    selector = seg()
                    val s = Forms.readAddr(r, addrSize); val len = r.uleb128()
                    out.add(RawRange(selector, s, s + len))
                }
                else -> throw UnknownRngListOp(op)
            }
        }
        return out
    }
}

class UnknownRngListOp(op: Int) : RuntimeException("unknown DW_RLE 0x${"%x".format(op)}")
