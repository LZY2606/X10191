package compass.dwarf

/**
 * Bounded view into `.debug_addr`. DWARF 5 sets carry a header (version,
 * address_size, segment_selector_size); GNU split `.debug_addr` is a bare
 * array addressed by DW_AT_GNU_addr_base. Both shapes are supported.
 */
class AddrTableView(private val r: Reader, private val addressSize: Int) {

    private val v5Sets = HashMap<Long, Pair<Long, Int>>() // base -> (dataStart, count)
    private val bareBase = 0L

    init {
        // Probe for DWARF 5 sets across the whole section, while retaining
        // bare-array access for GNU bases.
        var guard = 0
        while (r.remaining() >= 4 && guard++ < 100_000) {
            val setStart = r.pos.toLong()
            try {
                val len = r.u32()
                if (len in 1..0xfffffff0L && r.remaining() >= len - 4) {
                    val version = r.u16()
                    if (version == 5) {
                        val asize = r.u8()
                        val ssize = r.u8()
                        if ((asize == 4 || asize == 8) && ssize == 0) {
                            val dataStart = r.pos.toLong()
                            val count = ((len - 8) / asize).toInt()
                            v5Sets[setStart] = dataStart to count
                            r.seek((setStart + 4 + len).toIntExact())
                            continue
                        }
                    }
                }
                r.seek((setStart + 1).toIntExact())
            } catch (e: Exception) {
                break
            }
        }
        r.seek(0)
    }

    fun get(base: Long, index: Long): Long {
        val set = v5Sets[base]
        if (set != null) {
            val (dataStart, count) = set
            if (index < 0 || index >= count) throw ParseError(".debug_addr index $index out of set (count=$count)")
            r.seek((dataStart + index * addressSize).toIntExact())
            return readAddress(r, addressSize)
        }
        // GNU bare array: base is a byte offset in .debug_addr.
        val stride = addressSize
        val off = (base + index * stride).toIntExact()
        r.seek(off)
        return readAddress(r, addressSize)
    }

    private fun readAddress(r: Reader, size: Int): Long = when (size) {
        4 -> r.u32(); 8 -> r.u64(); else -> throw ParseError("bad addr size $size")
    }
}

/** View into `.debug_str_offsets`, similarly header + sets or bare GNU array. */
class StrOffsetsView(private val r: Reader, private val cuIs64: Boolean) {
    private val v5Sets = HashMap<Long, Pair<Long, Int>>()

    init {
        val entrySize = if (cuIs64) 8 else 4
        var guard = 0
        while (r.remaining() >= 4 && guard++ < 100_000) {
            val setStart = r.pos.toLong()
            try {
                val len = r.u32()
                if (len in 1..0xfffffff0L && r.remaining() >= len - 4) {
                    val version = r.u16()
                    if (version == 5 && r.u16() == 0) {
                        val dataStart = r.pos.toLong()
                        val count = ((len - 6) / entrySize).toInt()
                        v5Sets[setStart] = dataStart to count
                        r.seek((setStart + 4 + len).toIntExact())
                        continue
                    }
                }
                r.seek((setStart + 1).toIntExact())
            } catch (e: Exception) {
                break
            }
        }
        r.seek(0)
    }

    fun get(base: Long, index: Long): Long {
        val entrySize = if (cuIs64) 8 else 4
        val set = v5Sets[base]
        if (set != null) {
            val (dataStart, count) = set
            if (index < 0 || index >= count) throw ParseError(".debug_str_offsets index $index out of set")
            r.seek((dataStart + index * entrySize).toIntExact())
            return if (cuIs64) r.u64() else r.u32()
        }
        r.seek((base + index * entrySize).toIntExact())
        return if (cuIs64) r.u64() else r.u32()
    }
}
