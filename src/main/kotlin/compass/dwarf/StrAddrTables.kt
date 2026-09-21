package compass.dwarf

/**
 * .debug_str / .debug_line_str / .debug_str_offsets / .debug_addr access.
 * All reads are bounds-checked and failures degrade to placeholders rather than
 * crashing the whole import.
 */
object StrTables {
    fun readString(bundle: SectionBundle, section: String, offset: Long, useSplitFallback: Boolean): String? {
        val (data, _) = bundle.bytesFromAny(section) ?: return null
        if (offset < 0 || offset >= data.size) return null
        val r = SectionReader(data, section, bundle.le, offset.toInt())
        return try { r.cString() } catch (e: DwarfBoundsException) { null }
    }

    /**
     * Read strx entry. base is the CU-level str_offsets_base (offset of the offsets array
     * for this CU, i.e. just after the str_offsets header).
     */
    fun readStrx(bundle: SectionBundle, section: String, base: Long, index: Long): String? {
        val (data, _) = bundle.bytesFromAny(section) ?: return null
        // .debug_str_offsets
        val so = bundle.bytesFromAny(".debug_str_offsets") ?: return null
        val (soData, _) = so
        // Determine offset width from header at the position preceding `base`.
        val arrayPos = base.toInt()
        if (arrayPos < 0 || arrayPos >= soData.size) return null
        val headerPos = findStrOffsetsHeader(soData, bundle.le, arrayPos)
        val offsetSize = if (headerPos >= 0) probeOffsetSize(soData, bundle.le, headerPos) else 4
        val r = SectionReader(soData, ".debug_str_offsets", bundle.le, arrayPos)
        val entryPos = arrayPos + (index * offsetSize).toInt()
        if (entryPos < 0 || entryPos + offsetSize > soData.size) return null
        r.seek(entryPos)
        val strOff = r.u(offsetSize)
        return readString(bundle, section, strOff, true)
    }

    /** Walk backwards from arrayPos looking for a plausible str_offsets header length. */
    private fun findStrOffsetsHeader(data: ByteArray, le: Boolean, arrayPos: Int): Int {
        // Header: length(4/12) + version(2) + padding(2), array starts right after.
        if (arrayPos >= 8) {
            val p = arrayPos - 8
            val len = readU32(data, le, p)
            if (len in 8L..0xfffffff0L && p + 4 + len.toInt() <= data.size) return p
        }
        if (arrayPos >= 16) {
            val p = arrayPos - 16
            if (readU32(data, le, p) == 0xffffffffL) {
                val len = readU64(data, le, p + 4)
                if (p + 12 + len in 0..data.size.toLong()) return p
            }
        }
        return -1
    }

    private fun probeOffsetSize(data: ByteArray, le: Boolean, headerPos: Int): Int =
        if (readU32(data, le, headerPos) == 0xffffffffL) 8 else 4

    private fun readU32(d: ByteArray, le: Boolean, o: Int): Long {
        var v = 0L
        for (i in 0 until 4) { val b = d[o + i].toLong() and 0xff; v = if (le) v or (b shl 8 * i) else (v shl 8) or b }
        return v
    }
    private fun readU64(d: ByteArray, le: Boolean, o: Int): Long {
        var v = 0L
        for (i in 0 until 8) { val b = d[o + i].toLong() and 0xff; v = if (le) v or (b shl 8 * i) else (v shl 8) or b }
        return v
    }
}

object AddrTables {
    fun resolve(bundle: SectionBundle, base: Long, index: Long, addressSize: Int): Long {
        val (data, _) = bundle.bytesFromAny(".debug_addr") ?: return 0L
        val arrayPos = base.toInt()
        val pos = arrayPos + (index * addressSize).toInt()
        if (pos < 0 || pos + addressSize > data.size) return 0L
        val r = SectionReader(data, ".debug_addr", bundle.le, pos)
        return r.u(addressSize)
    }
}
