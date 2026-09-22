package compass.dwarf

import compass.elf.ByteReader
import compass.elf.DwarfParseException

object RangeLists {
    /** DWARF <=4 .debug_ranges contribution at [offset] with base = [cuLowPc]. */
    fun parseDwarf4(
        bundle: DebugBundle,
        offset: Long,
        addressSize: Int,
        cuLowPc: Long
    ): List<RangeEntry> {
        val data = bundle.ranges ?: return emptyList()
        val r = ByteReader(data, bundle.elf.bigEndian, ".debug_ranges")
        r.seek(offset.toIntSafe())
        val out = ArrayList<RangeEntry>()
        var base = cuLowPc
        val maxAddr = if (addressSize == 4) 0xffffffffL else -1L
        var guard = 0
        while (r.remaining() >= addressSize * 2 && guard++ < 1_000_000) {
            val a = r.readUInt(addressSize)
            val b = r.readUInt(addressSize)
            if (a == 0L && b == 0L) break
            if (a == maxAddr) { base = b; continue }
            val start = a + base
            val end = b + base
            if (end < start) throw DwarfParseException(".debug_ranges: inverted entry at 0x${r.pos.toString(16)}")
            out.add(RangeEntry(start, end))
        }
        return out
    }

    /**
     * DWARF5 .debug_rnglists list body at [listOffset] (AT_ranges points past the table
     * header to the first list-entry byte). [addrBase] is the CU's AT_addr_base.
     */
    fun parseDwarf5(
        bundle: DebugBundle,
        listOffset: Long,
        useDwo: Boolean,
        addressSize: Int,
        addrBase: Long
    ): ParseResult {
        val data = (if (useDwo) bundle.rnglistsDwo else bundle.rnglists)
            ?: return ParseResult(emptyList(), "no .debug_rnglists section")
        val notes = ArrayList<String>()
        val r = ByteReader(data, bundle.elf.bigEndian, ".debug_rnglists")
        r.seek(listOffset.toIntSafe())

        val out = ArrayList<RangeEntry>()
        var base = 0L
        var guard = 0
        scan@ while (r.remaining() > 0 && guard++ < 1_000_000) {
            when (val kind = r.u8()) {
                RLE.END_OF_LIST -> break@scan
                RLE.BASE_ADDRESSX -> {
                    val idx = r.uleb128()
                    base = readAddr(bundle, idx, addrBase, addressSize)
                }
                RLE.STARTX_ENDX -> {
                    val si = r.uleb128(); val ei = r.uleb128()
                    out.add(RangeEntry(
                        readAddr(bundle, si, addrBase, addressSize),
                        readAddr(bundle, ei, addrBase, addressSize)
                    ))
                }
                RLE.STARTX_LENGTH -> {
                    val si = r.uleb128(); val len = r.uleb128().toLong()
                    val s = readAddr(bundle, si, addrBase, addressSize)
                    out.add(RangeEntry(s, s + len))
                }
                RLE.OFFSET_PAIR -> {
                    val so = r.uleb128().toLong(); val len = r.uleb128().toLong()
                    out.add(RangeEntry(base + so, base + so + len))
                }
                RLE.BASE_ADDRESS -> base = r.readUInt(addressSize)
                RLE.START_END -> {
                    val s = r.readUInt(addressSize); val e = r.readUInt(addressSize)
                    out.add(RangeEntry(s, e))
                }
                RLE.START_LENGTH -> {
                    val s = r.readUInt(addressSize); val len = r.readUInt(addressSize)
                    out.add(RangeEntry(s, s + len))
                }
                else -> {
                    notes.add("unknown rnglist entry kind 0x${kind.toString(16)}; scan stopped")
                    break@scan
                }
            }
        }
        out.forEach { if (it.end < it.start) throw DwarfParseException(".debug_rnglists: inverted range") }
        return ParseResult(out, notes.joinToString("; ").ifEmpty { null })
    }

    private fun readAddr(bundle: DebugBundle, idx: ULong, addrBase: Long, addressSize: Int): Long {
        val data = bundle.addr ?: throw DwarfParseException("addr index used but .debug_addr missing")
        val ar = ByteReader(data, bundle.elf.bigEndian, ".debug_addr")
        ar.seek((addrBase + idx.toLong() * addressSize).toIntSafe())
        return ar.readUInt(addressSize)
    }

    private fun Long.toIntSafe(): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseException("rangelist offset out of range")
        return toInt()
    }

    data class ParseResult(val ranges: List<RangeEntry>, val note: String?)
}
