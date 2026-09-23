package compass.dwarf

/** Parses DW_AT_ranges values from .debug_ranges (v4) and .debug_rnglists (v5). */
class RangeListParser(
    private val sections: DebugSections,
    private val cu: CompilationUnit,
) {
    private val notes = ArrayList<String>()

    fun parse(attr: AttrValue?): List<AddressRange> {
        if (attr == null) return emptyList()
        return if (cu.version >= 5) parseV5(attr) else parseV4(attr)
    }

    private fun parseV4(attr: AttrValue): List<AddressRange> {
        val bytes = sections.get(".debug_ranges")
        if (bytes == null) {
            notes.add("DW_AT_ranges present but .debug_ranges is missing")
            return emptyList()
        }
        val offset = when (attr) {
            is AttrValue.SecOffset -> attr.v
            is AttrValue.UInt -> attr.v
            else -> return emptyList()
        }
        if (offset < 0 || offset >= bytes.size) {
            notes.add("ranges offset 0x${offset.toString(16)} outside .debug_ranges")
            return emptyList()
        }
        val r = ByteReader(bytes, offset.toInt(), bytes.size, sections.littleEndian)
        val out = ArrayList<AddressRange>()
        var base = cu.lowPc ?: 0L
        val maxVal = if (cu.addressSize == 8) -1L else 0xFFFFFFFFL
        var count = 0
        while (r.remaining >= cu.addressSize * 2) {
            if (++count > Limits.MAX_RANGE_ENTRIES) {
                notes.add("range list entry limit exceeded; truncated")
                break
            }
            val start = r.uN(cu.addressSize)
            val end = r.uN(cu.addressSize)
            if (start == 0L && end == 0L) break
            if (start == maxVal) {
                base = end
                continue
            }
            out.add(AddressRange(base + start, base + end))
        }
        return out
    }

    private fun parseV5(attr: AttrValue): List<AddressRange> {
        val bytes = sections.get(".debug_rnglists")
        if (bytes == null) {
            notes.add("DW_AT_ranges present but .debug_rnglists is missing")
            return emptyList()
        }
        return when (attr) {
            is AttrValue.SecOffset -> parseV5Entries(bytes, attr.v)
            is AttrValue.UInt -> parseV5Entries(bytes, attr.v)
            is AttrValue.RngListIndex -> {
                val offset = resolveRngListOffset(bytes, attr.index)
                if (offset == null) emptyList() else parseV5Entries(bytes, offset)
            }
            else -> emptyList()
        }
    }

    /** Resolves a rnglistx index through the offsets table at the section header. */
    private fun resolveRngListOffset(bytes: ByteArray, index: Long): Long? {
        val r = ByteReader(bytes, 0, bytes.size, sections.littleEndian)
        return try {
            var length = r.u32()
            val is64 = length == 0xFFFFFFFFL
            if (is64) length = r.u64()
            r.u16() // version
            r.u8()  // address size
            r.u8()  // segment selector size
            val count = r.u32()
            if (index < 0 || index >= count) {
                notes.add("rnglistx index $index out of bounds (offset_entry_count=$count)")
                return null
            }
            val offsetsStart = r.pos.toLong()
            r.pos = (offsetsStart + index * 4).toInt()
            val rel = r.u32()
            // Offsets are relative to the start of the offsets array unless the CU
            // supplies an explicit DW_AT_rnglists_base.
            val base = if (cu.rnglistsBase != 0L) cu.rnglistsBase else offsetsStart
            base + rel
        } catch (e: Exception) {
            notes.add("failed to resolve rnglistx $index: ${e.message}")
            null
        }
    }

    private fun parseV5Entries(bytes: ByteArray, offset: Long): List<AddressRange> {
        if (offset < 0 || offset >= bytes.size) {
            notes.add("rnglists offset 0x${offset.toString(16)} outside .debug_rnglists")
            return emptyList()
        }
        val r = ByteReader(bytes, offset.toInt(), bytes.size, sections.littleEndian)
        val out = ArrayList<AddressRange>()
        var base = cu.lowPc ?: 0L
        var count = 0
        fun addrAt(index: Long): Long? {
            val table = sections.get(".debug_addr")
            if (table == null) {
                notes.add("rnglists entry needs .debug_addr but the section is missing")
                return null
            }
            val pos = cu.addrBase + index * cu.addressSize
            if (pos < 0 || pos + cu.addressSize > table.size) {
                notes.add("rnglists addrx $index out of bounds of .debug_addr")
                return null
            }
            return ByteReader(table, pos.toInt(), table.size, sections.littleEndian).uN(cu.addressSize)
        }
        while (r.hasRemaining()) {
            if (++count > Limits.MAX_RANGE_ENTRIES) {
                notes.add("rnglists entry limit exceeded; truncated")
                break
            }
            when (r.u8()) {
                RngList.END_OF_LIST -> break
                RngList.BASE_ADDRESSX -> {
                    val idx = r.uleb()
                    base = addrAt(idx) ?: base
                }
                RngList.STARTX_ENDX -> {
                    val s = addrAt(r.uleb())
                    val e = addrAt(r.uleb())
                    if (s != null && e != null) out.add(AddressRange(s, e))
                }
                RngList.STARTX_LENGTH -> {
                    val s = addrAt(r.uleb())
                    val len = r.uleb()
                    if (s != null) out.add(AddressRange(s, s + len))
                }
                RngList.OFFSET_PAIR -> {
                    val s = r.uleb()
                    val e = r.uleb()
                    out.add(AddressRange(base + s, base + e))
                }
                RngList.BASE_ADDRESS -> base = r.uN(cu.addressSize)
                RngList.START_END -> {
                    val s = r.uN(cu.addressSize)
                    val e = r.uN(cu.addressSize)
                    out.add(AddressRange(s, e))
                }
                RngList.START_LENGTH -> {
                    val s = r.uN(cu.addressSize)
                    val len = r.uleb()
                    out.add(AddressRange(s, s + len))
                }
                else -> {
                    notes.add("unknown rangelist entry kind; list truncated")
                    break
                }
            }
        }
        return out
    }

    fun collectedNotes(): List<String> = notes
}
