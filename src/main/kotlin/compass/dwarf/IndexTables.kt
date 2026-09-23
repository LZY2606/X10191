package compass.dwarf

import compass.elf.BinaryTruncatedException
import compass.elf.Reader
import compass.model.Endian

/**
 * .debug_addr support for both DWARF 5 and the GNU split-DWARF 4 layout.
 * The base given by DW_AT_addr_base points *at* the first address entry in
 * both conventions (the header size was already skipped by the producer).
 */
object AddrTable {
    fun readAddress(
        sections: DebugSections,
        endian: Endian,
        base: Long,
        index: Long,
        addrSize: Int,
    ): Long {
        val data = sections.require(".debug_addr")
        if (data.isEmpty()) throw BinaryTruncatedException("DW_FORM_addrx but no .debug_addr")
        val off = base + index * addrSize
        if (off < 0 || off + addrSize > data.size)
            throw BinaryTruncatedException("addr index out of .debug_addr")
        val r = Reader(data, endian)
        r.seek(off.toInt())
        return Forms.readAddr(r, addrSize)
    }
}

/**
 * .debug_str_offsets: an array of offsets (of the CU's offset size) into
 * .debug_str. Bases from DW_AT_str_offsets_base point at the first entry.
 */
object StrOffsets {
    fun resolve(
        sections: DebugSections,
        endian: Endian,
        base: Long,
        index: Long,
        dwarf64: Boolean,
    ): String {
        val so = sections.require(".debug_str_offsets")
        if (so.isEmpty()) throw BinaryTruncatedException("DW_FORM_strx but no .debug_str_offsets")
        val ptrSize = if (dwarf64) 8 else 4
        val off = base + index * ptrSize
        if (off < 0 || off + ptrSize > so.size)
            throw BinaryTruncatedException("strx index out of .debug_str_offsets")
        val r = Reader(so, endian, off.toInt()); r.seek(off.toInt())
        val strOff = (if (dwarf64) r.u64() else r.u32())
        val str = sections.require(".debug_str")
        if (str.isEmpty() || strOff < 0 || strOff >= str.size)
            throw BinaryTruncatedException("str offset out of .debug_str")
        return Reader(str, endian).cStringAt(strOff.toInt())
    }
}
