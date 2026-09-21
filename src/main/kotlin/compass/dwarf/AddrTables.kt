package compass.dwarf

import compass.binary.ByteReader
import compass.binary.DwarfParseException

/**
 * Pre-scans the DWARF 5 .debug_addr and .debug_str_offsets headers so index
 * resolution knows where each CU's contribution data begins.
 */
data class AddrTable(val dataStart: Long, val addressSize: Int) {
    /**
     * [base] is the section offset of the first entry (DW_AT_addr_base);
     * [index] is relative to that base.
     */
    fun readAt(data: ByteArray, base: Long, index: Long): Long? {
        val pos = base + index * addressSize
        if (pos < 0 || pos + addressSize > data.size) return null
        val r = ByteReader(data, pos.toInt(), (pos + addressSize).toInt())
        return if (addressSize == 8) r.u64() else r.u32()
    }
}

object AddrTables {
    /** Scan .debug_addr, mapping header-start offset -> table. Multiple contributions supported. */
    fun scanAddr(data: ByteArray?, defaultAddressSize: Int): Map<Long, AddrTable> {
        if (data == null || data.isEmpty()) return emptyMap()
        val out = HashMap<Long, AddrTable>()
        var p = 0
        var guard = 0
        while (p + 8 <= data.size) {
            if (++guard > 4096) break
            try {
                val r = ByteReader(data, p, data.size)
                val len = r.u32()
                if (len <= 4 || p + 4 + len > data.size) break
                val version = r.u16()
                if (version != 5) break
                val addrSize = r.u8()
                r.u8() // segment selector size
                val dataStart = p + 8L
                val table = AddrTable(dataStart, addrSize)
                out[p.toLong()] = table
                out[dataStart] = table           // DW_AT_addr_base points here
                p = (p + 4 + len).toInt()
            } catch (_: DwarfParseException) { break }
        }
        if (out.isEmpty()) {
            // Headerless GNU extension: treat base 0 as raw entry array.
            out[0L] = AddrTable(0L, defaultAddressSize)
        }
        return out
    }

    fun scanStrOffsets(data: ByteArray?): Map<Long, StrOffsetsTable> {
        if (data == null || data.isEmpty()) return emptyMap()
        val out = HashMap<Long, StrOffsetsTable>()
        var p = 0
        var guard = 0
        while (p + 8 <= data.size) {
            if (++guard > 4096) break
            try {
                val r = ByteReader(data, p, data.size)
                val len = r.u32()
                if (len <= 4 || p + 4 + len > data.size) break
                val version = r.u16()
                if (version != 5) break
                r.u16() // padding
                // Header is exactly 8 bytes (DWARF32); entries follow immediately.
                out[p.toLong()] = StrOffsetsTable(p + 8, 4)
                p = (p + 4 + len).toInt()
            } catch (_: DwarfParseException) { break }
        }
        if (out.isEmpty()) out[0L] = StrOffsetsTable(0, 4)
        return out
    }
}
