package compass.dwarf

import compass.ByteReader
import compass.DwarfFormatException
import compass.unitLength

/**
 * Resolves DW_AT_ranges / DW_AT_rnglists_base into concrete [AddressRange]s.
 *
 *  - DWARF <=4: .debug_ranges, series of (begin,end) pairs where both == maxint means
 *    "set base address" and (0,0) terminates; begin may be 0xffffffff on 32-bit targets.
 *  - DWARF 5: .debug_rnglists with a unit header and the RLE_* entry kinds.
 *
 * Zero-length entries are retained (they matter for "address exactly on boundary" semantics).
 */
class RangeResolver(private val obj: DebugObject) {

    fun resolveV4(offset: Long, cu: CompilationUnit, initialBase: Long): List<AddressRange>? {
        val sec = obj.section(".debug_ranges") ?: return null
        if (offset < 0 || offset >= sec.size) {
            cu.issues += DebugIssue(DebugIssue.Severity.ERROR, "ranges_oob",
                ".debug_ranges offset $offset outside section", cu.sectionOffset, ".debug_ranges")
            return null
        }
        val r = ByteReader(sec, offset.toInt(), sec.size, obj.littleEndian)
        val addrsize = cu.addressSize
        val max = if (addrsize == 8) -1L else 0xffffffffL
        var base = initialBase
        val out = mutableListOf<AddressRange>()
        var guard = 0
        while (true) {
            if (++guard > 10_000_000) throw DwarfFormatException("ranges entry limit")
            val begin = readAddr(r, addrsize)
            val end = readAddr(r, addrsize)
            if (begin == 0L && end == 0L) break
            if (begin == max && end != max) {
                base = end // base address selection entry
                continue
            }
            if (begin == max && end == max) break // malformed but tolerated
            out += AddressRange(base + begin, base + end, RangeKind.RANGES_V4, ".debug_ranges+$offset")
        }
        return out
    }

    fun resolveV5(offset: Long, cu: CompilationUnit, rnglistxIndex: ULong? = null): List<AddressRange>? {
        val sec = obj.section(".debug_rnglists") ?: return null
        val (tableStart, sectionIs64) = locateV5Table(sec, offset, rnglistxIndex, cu) ?: return null
        if (tableStart < 0 || tableStart >= sec.size) {
            cu.issues += DebugIssue(DebugIssue.Severity.ERROR, "rnglists_oob",
                "offset $offset outside .debug_rnglists", cu.sectionOffset, ".debug_rnglists")
            return null
        }
        return parseV5Entries(sec, tableStart, cu)
    }

    /**
     * A v5 ranges attribute is either a header-relative byte offset or (with DW_FORM_rnglistx)
     * an index into the table's offset array.
     */
    private fun locateV5Table(
        sec: ByteArray, attrOffset: Long, index: ULong?, cu: CompilationUnit,
    ): Pair<Int, Boolean>? {
        // One rnglists unit per section in practice. Scan unit headers so a section with
        // multiple units still works.
        var tableStart = 0
        while (tableStart < sec.size) {
            val r = ByteReader(sec, tableStart, sec.size, obj.littleEndian)
            val ul = r.unitLength()
            val unitEnd = ul.end
            r.u16() // version
            r.u8()  // address_size
            r.u8()  // segment_selector_size
            val offsetArrayOffset = readOff(r, ul.is64Bit)
            val offsetArraySize = readOff(r, ul.is64Bit)
            // r.pos is the byte immediately after the fixed header fields; spec-relative
            // offsets (both DW_AT_ranges byte offsets and offset-array entries) are relative
            // to the first byte after the unit_length field + ... specifically relative to the
            // byte following the header_length field, i.e. the version field.
            val relativeBase = tableStart + (if (ul.is64Bit) 12 else 4)
            val offsetsStart = r.pos
            if (index != null) {
                val entryPos = offsetsStart + offsetArrayOffset.toInt() +
                    index.toInt() * (if (ul.is64Bit) 8 else 4)
                if (entryPos + (if (ul.is64Bit) 8 else 4) > sec.size) return null
                val er = ByteReader(sec, entryPos, sec.size, obj.littleEndian)
                val rel = readOff(er, ul.is64Bit)
                val target = relativeBase + rel.toInt()
                if (target in tableStart until unitEnd) return target to ul.is64Bit
            } else {
                val target = relativeBase + attrOffset.toInt()
                if (target in tableStart until unitEnd) return target to ul.is64Bit
            }
            tableStart = unitEnd
        }
        return null
    }

    private fun parseV5Entries(sec: ByteArray, start: Int, cu: CompilationUnit): List<AddressRange> {
        val r = ByteReader(sec, start, sec.size, obj.littleEndian)
        val addrsize = cu.addressSize
        var base = 0L
        var baseIndex: ULong? = null
        val out = mutableListOf<AddressRange>()
        var guard = 0
        while (true) {
            if (++guard > 10_000_000) throw DwarfFormatException("rnglists entry limit")
            val kind = r.u8()
            when (kind) {
                DW.RLE_END_OF_LIST -> break
                DW.RLE_BASE_ADDRESSX -> {
                    baseIndex = r.uleb128()
                    base = resolveAddrx(obj, cu, baseIndex) ?: run {
                        cu.issues += DebugIssue(DebugIssue.Severity.WARNING, "addrx_missing",
                            "base_addressx $baseIndex unresolved; table truncated",
                            cu.sectionOffset, ".debug_rnglists")
                        return out
                    }
                }
                DW.RLE_BASE_ADDRESS -> base = readAddr(r, addrsize)
                DW.RLE_STARTX_ENDX -> {
                    val s = resolveAddrx(obj, cu, r.uleb128()) ?: return markAddrx(cu, out)
                    val e = resolveAddrx(obj, cu, r.uleb128()) ?: return markAddrx(cu, out)
                    out += AddressRange(s, e, RangeKind.RANGES_V5, ".debug_rnglists")
                }
                DW.RLE_STARTX_LENGTH -> {
                    val s = resolveAddrx(obj, cu, r.uleb128()) ?: return markAddrx(cu, out)
                    val len = r.uleb128().toLong()
                    out += AddressRange(s, s + len, RangeKind.RANGES_V5, ".debug_rnglists")
                }
                DW.RLE_OFFSET_PAIR -> {
                    val sOff = r.uleb128().toLong()
                    val eOff = r.uleb128().toLong()
                    out += AddressRange(base + sOff, base + eOff, RangeKind.RANGES_V5, ".debug_rnglists")
                }
                DW.RLE_START_END -> {
                    val s = readAddr(r, addrsize)
                    val e = readAddr(r, addrsize)
                    out += AddressRange(s, e, RangeKind.RANGES_V5, ".debug_rnglists")
                }
                DW.RLE_START_LENGTH -> {
                    val s = readAddr(r, addrsize)
                    val len = r.uleb128().toLong()
                    out += AddressRange(s, s + len, RangeKind.RANGES_V5, ".debug_rnglists")
                }
                else -> throw DwarfFormatException("unknown RLE 0x${kind.toString(16)}")
            }
        }
        return out
    }

    private fun markAddrx(cu: CompilationUnit, out: List<AddressRange>): List<AddressRange> {
        cu.issues += DebugIssue(DebugIssue.Severity.WARNING, "addrx_missing",
            "rnglists addrx could not be resolved; remaining ranges skipped",
            cu.sectionOffset, ".debug_rnglists")
        return out
    }

    private fun readAddr(r: ByteReader, size: Int): Long = when (size) {
        1 -> r.u8().toLong(); 2 -> r.u16().toLong(); 4 -> r.u32(); 8 -> r.u64()
        else -> throw DwarfFormatException("bad address size $size")
    }

    private fun readOff(r: ByteReader, is64: Boolean): Long = if (is64) r.u64() else r.u32()
}
