package compass.dwarf

/**
 * .debug_addr resolution. DWARF 5 tables carry a header; GNU split DWARF tables are
 * raw arrays whose base is given by DW_AT_GNU_addr_base on the skeleton CU.
 */
class AddrTable(private val debugAddr: ByteReader?) {
    /**
     * @param base v5: offset of the table header; GNU: offset of the first raw entry
     */
    fun resolve(base: Long?, idx: Long, addressSize: Int, version: Int): Long? {
        if (debugAddr == null || base == null) return null
        try {
            val r = debugAddr.subReader(debugAddr.base, debugAddr.limit)
            r.seek(base)
            r.addressSize = addressSize
            val firstEntry: Long
            if (version >= 5) {
                val (len, _) = r.initialLength()
                val endOff = r.sectionOffset() + len
                if (endOff > r.limit - r.base) return null
                r.u16(); r.u8(); r.u8()
                firstEntry = r.sectionOffset()
            } else {
                firstEntry = base
            }
            r.seek(firstEntry + idx * addressSize)
            return r.address()
        } catch (_: Exception) {
            return null
        }
    }
}
