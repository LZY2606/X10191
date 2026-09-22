package compass.dwarf

import compass.elf.ByteReader

/** Header of one DWARF5 .debug_rnglists contribution. */
data class RngListHeader(
    val offsetSize: Int,
    val segmentSize: Int,
    val offsetEntryCount: Long,
    val offsetArrayBase: Long,
    val listBase: Long
)

object RngLists {
    fun readHeaderAt(sec: ByteReader, base: Long): RngListHeader {
        val r = sec.subReader(base.toInt(), sec.size - base.toInt())
        val (_, _, dwarf64) = readInitialLength(r)
        val version = r.u2()
        if (version != 5) throw DwarfParseException("rnglists version $version != 5")
        val addressSize = r.u1()
        val segmentSize = r.u1()
        r.u4()
        val offsetEntryCount = r.u4().toLong() and 0xffffffffL
        val offsetSize = if (dwarf64) 8 else 4
        val offsetArrayBase = base + r.save().toLong()
        r.skip((offsetEntryCount * offsetSize).toInt())
        val listBase = base + r.save().toLong()
        return RngListHeader(addressSize, segmentSize, offsetEntryCount, offsetArrayBase, listBase)
    }

    /** Read one v5 range list; addrx entries resolve via [addrAt]. */
    fun readList(
        sec: ByteReader,
        listOffset: Long,
        addressSize: Int,
        segmentSize: Int,
        addrAt: (Long) -> Long
    ): List<AddressRange> {
        val r = sec.subReader(listOffset.toInt(), sec.size - listOffset.toInt())
        val out = ArrayList<AddressRange>()
        var baseAddr = 0L
        var guard = 0
        while (true) {
            if (++guard > Limits.MAX_RANGES_PER_DIE)
                throw DwarfParseException("range list at $listOffset too long")
            when (val op = r.u1()) {
                DW.RLE_end_of_list -> return out
                DW.RLE_base_addressx -> baseAddr = addrAt(r.uleb())
                DW.RLE_startx_endx -> out.add(AddressRange(addrAt(r.uleb()), addrAt(r.uleb())))
                DW.RLE_startx_length -> {
                    val s = addrAt(r.uleb()); out.add(AddressRange(s, s + r.uleb()))
                }
                DW.RLE_offset_pair -> {
                    val sOff = r.uleb(); val eOff = r.uleb()
                    val seg = if (segmentSize == 0) 0 else r.uword(segmentSize).toInt()
                    out.add(AddressRange(baseAddr + sOff, baseAddr + eOff, seg))
                }
                DW.RLE_constant -> {
                    val seg = if (segmentSize == 0) 0 else r.uword(segmentSize).toInt()
                    val a = r.uword(addressSize)
                    out.add(AddressRange(a, a, seg))
                }
                DW.RLE_base_address -> baseAddr = r.uword(addressSize)
                DW.RLE_start_end -> out.add(AddressRange(r.uword(addressSize), r.uword(addressSize)))
                DW.RLE_start_length -> {
                    val s = r.uword(addressSize); out.add(AddressRange(s, s + r.uleb()))
                }
                else -> throw DwarfParseException(String.format("unknown rnglists opcode 0x%02x", op))
            }
        }
    }
}

/** v4 .debug_ranges reader. */
object RangesV4 {
    fun readList(sec: ByteReader, offset: Long, addressSize: Int, cuLowPc: Long): List<AddressRange> {
        if (offset < 0 || offset + addressSize > sec.size)
            throw DwarfParseException("debug_ranges offset $offset out of bounds")
        val r = sec.subReader(offset.toInt(), sec.size - offset.toInt())
        val out = ArrayList<AddressRange>()
        var base = cuLowPc
        val max = if (addressSize == 8) DW.RANGES_MAX64 else DW.RANGES_MAX32
        var guard = 0
        while (true) {
            if (++guard > Limits.MAX_RANGES_PER_DIE)
                throw DwarfParseException("range list at $offset too long")
            val a = r.uword(addressSize)
            val b = r.uword(addressSize)
            if (a == max) {
                if (b == 0L) return out
                base = b
                continue
            }
            if (a == 0L && b == 0L) return out
            out.add(AddressRange(base + a, base + b))
        }
    }
}
