package compass

/**
 * Access .debug_addr by "base": CU attr_base points to the byte right after the unit_length/version/address_size
 * header for DWARF5; GNU v4 points similarly at an 8-byte (addr_size=8) or (4,4,addr_size) header.
 */
class AddrTableReader(private val section: ByteArray?) {
    fun get(base: Long, index: Long, addressSize: Int, gnuStyle: Boolean): TargetAddress {
        if (section == null) throw CursorException(".debug_addr: section missing (base=$base idx=$index)")
        if (index < 0 || index > Limits.MAX_ADDR_TABLE) throw CursorException(".debug_addr: bad index $index")
        val start = (base + index * addressSize).toInt()
        if (start < 0 || start + addressSize > section.size)
            throw CursorException(".debug_addr: index $index (base=$base) out of bounds, section=${section.size}")
        val c = ByteCursor(section, start, section.size, ".debug_addr")
        return TargetAddress(c.address(addressSize))
    }

    /** Read a v5 header starting at [unitStart] and return (tableBase, addressSize). */
    fun v5Header(unitStart: Long): Pair<Long, Int> {
        if (section == null) throw CursorException(".debug_addr: missing")
        val c = ByteCursor(section, unitStart.toInt(), section.size, ".debug_addr")
        RangeReader.readInitialLength(c)
        c.u16() // version
        val asz = c.u8()
        c.u8() // seg selector
        return c.pos.toLong() to asz
    }
}

class StrOffsetsReader(private val section: ByteArray?) {
    /** v5 str_offsets entry: unit header then offsets of offsetSize (4 or 8). */
    fun get(base: Long, index: Long, offsetSize: Int): Long {
        if (section == null) throw CursorException(".debug_str_offsets: section missing")
        // base typically points to first entry per DW_AT_str_offsets_base
        val start = (base + index * offsetSize).toInt()
        if (start < 0 || start + offsetSize > section.size)
            throw CursorException(".debug_str_offsets: index $index out of bounds")
        val c = ByteCursor(section, start, section.size, ".debug_str_offsets")
        return if (offsetSize == 8) c.u64() else c.u32()
    }
}
