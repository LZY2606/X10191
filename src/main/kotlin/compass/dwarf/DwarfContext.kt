package compass.dwarf

import compass.ByteReader

/** Shared section access for resolvers; each method tolerates a missing section. */
class DwarfContext(val sections: DwarfSections) {

    private var addrArray: ByteArray? = sections.addr

    fun debugString(offset: Long): String? {
        val s = sections.str ?: return null
        if (offset < 0 || offset >= s.size) return null
        return runCatching { ByteReader(s, offset.toInt()).cString() }.getOrNull()
    }

    fun lineString(offset: Long): String? {
        val s = sections.lineStr ?: sections.str ?: return null
        if (offset < 0 || offset >= s.size) return null
        return runCatching { ByteReader(s, offset.toInt()).cString() }.getOrNull()
    }

    /** Resolve a string stored as a section offset form. */
    fun stringAt(form: Int, offset: Long): String? = when (form) {
        DW.FORM_line_strp -> lineString(offset)
        else -> debugString(offset)
    }

    fun addrEntry(base: Long, index: Long, addressSize: Int): Long {
        val s = addrArray ?: throw IllegalStateException(".debug_addr required but missing")
        val off = (base + index * addressSize).toIntExact()
        return ByteReader(s, off).addr(addressSize)
    }

    fun hasAddr(): Boolean = addrArray != null

    private fun Long.toIntExact(): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw IllegalStateException("offset too large")
        return toInt()
    }
}
