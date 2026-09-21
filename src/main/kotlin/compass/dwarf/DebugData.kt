package compass.dwarf

import compass.util.ByteReader
import compass.util.ParseException
import compass.util.U64

/**
 * Read access to .debug_addr / .debug_str_offsets with DWARF 5 headers understood.
 * All accesses are bounds-checked; a corrupt table produces a ParseException that the
 * CU parser converts into an isolated issue.
 */
class DebugData(private val sections: Sections) {

    /** Read an address from .debug_addr at (base + index*addrSize). Bases point at the header in v5. */
    fun readAddr(base: U64, index: Long, addrSize: Int, version: Int, dwo: Boolean): U64 {
        val bytes = sections[if (dwo) ".debug_addr.dwo" else ".debug_addr"]
            ?: sections[".debug_addr"]
            ?: throw ParseException("DW_FORM_addrx but no .debug_addr section")
        val dataBase = dataStart(base, addrSize, version, bytes)
        val off = (dataBase + index * addrSize).toInt()
        if (off < 0 || off > bytes.size - addrSize) {
            throw ParseException("addrx index $index out of .debug_addr (base=$base)")
        }
        val r = ByteReader(bytes, off)
        return if (addrSize == 4) U64(r.u32()) else r.u64()
    }

    /** In v5 the 8-byte header (unit_length 4 + version 2 + addr_size 1 + seg_size 1) precedes entries. */
    private fun dataStart(base: U64, addrSize: Int, version: Int, bytes: ByteArray): Long {
        val p = base.v.toLong()
        if (version >= 5 && p + 8 <= bytes.size) {
            val h = ByteReader(bytes, p.toInt())
            val length = h.u32()
            val ver = h.u16()
            val asize = h.u8()
            if (ver == 5 && (asize == 4 || asize == 8) && length in 8..Int.MAX_VALUE.toLong()) {
                return p + 8
            }
        }
        return p
    }

    /**
     * Resolve a strx form: index into the CU's .debug_str_offsets contribution.
     * The CU's strOffsetsBase points at the start of the v5 contribution header.
     */
    fun resolveStrx(strOffsetsBase: U64?, index: Long, offsetSize: Int, version: Int, dwo: Boolean): String {
        val bytes = sections[if (dwo) ".debug_str_offsets.dwo" else ".debug_str_offsets"]
            ?: sections[".debug_str_offsets"]
            ?: throw ParseException("DW_FORM_strx but no .debug_str_offsets section")
        if (strOffsetsBase == null) throw ParseException("DW_FORM_strx without DW_AT_str_offsets_base")
        val dataStart = if (version >= 5) strOffsetsBase.v.toLong() + 8L else strOffsetsBase.v.toLong()
        val entOff = (dataStart + index * offsetSize).toInt()
        if (entOff < 0 || entOff > bytes.size - offsetSize) {
            throw ParseException("strx index $index out of .debug_str_offsets")
        }
        val er = ByteReader(bytes, entOff)
        val strOff = if (offsetSize == 4) er.u32() else er.u64().v
        return readDebugString(strOff, dwo)
    }

    fun readDebugString(offset: Long, dwo: Boolean): String {
        val bytes = sections[if (dwo) ".debug_str.dwo" else ".debug_str"] ?: sections[".debug_str"]
        ?: throw ParseException("string reference but no .debug_str section")
        if (offset < 0 || offset >= bytes.size) throw ParseException("strp offset $offset out of .debug_str")
        return ByteReader(bytes, offset.toInt()).cstring()
    }

    fun readLineString(offset: Long, dwo: Boolean): String {
        val bytes = sections[if (dwo) ".debug_line_str.dwo" else ".debug_line_str"]
            ?: throw ParseException("line_strp reference but no .debug_line_str section")
        if (offset < 0 || offset >= bytes.size) throw ParseException("line_strp offset out of section")
        return ByteReader(bytes, offset.toInt()).cstring()
    }
}
