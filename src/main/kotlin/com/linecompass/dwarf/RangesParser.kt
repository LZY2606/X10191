package com.linecompass.dwarf

import com.linecompass.io.ByteReader
import com.linecompass.io.ParseException

/**
 * Decodes .debug_ranges (DWARF <=4 / GNU) and .debug_rnglists (DWARF 5).
 * Zero-length entries are kept (and flagged by the model) because they are
 * legal but must never win a containment query.
 */
class RangeListParser(
    private val debugRanges: ByteArray?,
    private val debugRngLists: ByteArray?,
    private val addrReader: AddrTableReader,
    private val issues: MutableList<ParseIssue>
) {
    fun parseRangesV4(offset: Long?, cu: CompilationUnit): List<AddressRange> {
        if (offset == null) return emptyList()
        val bytes = debugRanges ?: return emptyList()
        if (offset < 0 || offset >= bytes.size) {
            issues += ParseIssue(".debug_ranges", "ERROR", "RANGES_OFFSET_OOB",
                "CU 0x${cu.offset.toString(16)} ranges offset 0x${offset.toString(16)} out of bounds",
                cuOffset = cu.offset)
            return emptyList()
        }
        val r = ByteReader(bytes, cu.littleEndian, ".debug_ranges", offset.toInt())
        val out = mutableListOf<AddressRange>()
        val maxAddr = when (cu.addressSize) {
            4 -> 0xffffffffL
            else -> -1L
        }
        var base = cu.lowPc ?: 0L
        var guard = 0
        try {
            while (r.remaining >= cu.addressSize * 2) {
                if (guard++ > Limits.MAX_LINE_ROWS_PER_PROGRAM) throw ParseException("rangelist too long")
                val a = r.u(cu.addressSize)
                val b = r.u(cu.addressSize)
                if (a == 0L && b == 0L) break
                if (a == maxAddr) { base = b; continue }
                out += AddressRange(base + a, base + b, 0, RangeKind.RANGE_LIST, null, cu,
                    explicitPriority = 1)
            }
        } catch (e: Exception) {
            issues += ParseIssue(".debug_ranges", "WARNING", "RANGES_PARSE_FAILED",
                "CU 0x${cu.offset.toString(16)} rangelist at 0x${offset.toString(16)} truncated: ${e.message}",
                offset = offset, cuOffset = cu.offset)
        }
        return out
    }

    fun parseRangesV5(offset: Long?, cu: CompilationUnit): List<AddressRange> {
        if (offset == null) return emptyList()
        val bytes = debugRngLists ?: return emptyList()
        if (offset < 0 || offset >= bytes.size) {
            issues += ParseIssue(".debug_rnglists", "ERROR", "RNGLISTS_OFFSET_OOB",
                "CU 0x${cu.offset.toString(16)} rnglists offset 0x${offset.toString(16)} out of bounds",
                cuOffset = cu.offset)
            return emptyList()
        }
        // DWARF 5 lists begin at the offset of the rangelist (inside a unit_length
        // block). Our fixtures emit bare lists; locate the enclosing header by
        // scanning is non-trivial, so callers pass the rangelist offset directly
        // and the base-address header start is found via rnglists_base attr if
        // present. For simplicity fixtures/tests place lists at section start.
        val r = ByteReader(bytes, cu.littleEndian, ".debug_rnglists", offset.toInt())
        val out = mutableListOf<AddressRange>()
        var base = 0L
        var guard = 0
        try {
            while (r.remaining > 0) {
                if (guard++ > Limits.MAX_LINE_ROWS_PER_PROGRAM) throw ParseException("rnglist too long")
                when (val kind = r.u1()) {
                    DW.RLE_end_of_list -> break
                    DW.RLE_base_addressx -> {
                        val idx = r.uleb128()
                        base = addrReader.addrx(idx, cu.addrBase, cu.offset, cu.addressSize,
                            cu.littleEndian, v5 = true)
                    }
                    DW.RLE_startx_endx -> {
                        val sx = r.uleb128(); val ex = r.uleb128()
                        val s = addrReader.addrx(sx, cu.addrBase, cu.offset, cu.addressSize, cu.littleEndian, true)
                        val e = addrReader.addrx(ex, cu.addrBase, cu.offset, cu.addressSize, cu.littleEndian, true)
                        out += AddressRange(s, e, 0, RangeKind.RANGE_LIST, null, cu, 1)
                    }
                    DW.RLE_startx_length -> {
                        val sx = r.uleb128(); val len = r.uleb128()
                        val s = addrReader.addrx(sx, cu.addrBase, cu.offset, cu.addressSize, cu.littleEndian, true)
                        out += AddressRange(s, s + len, 0, RangeKind.RANGE_LIST, null, cu, 1)
                    }
                    DW.RLE_offset_pair -> {
                        val a = r.uleb128(); val b = r.uleb128()
                        out += AddressRange(base + a, base + b, 0, RangeKind.RANGE_LIST, null, cu, 1)
                    }
                    DW.RLE_base_address -> { base = r.u(cu.addressSize) }
                    DW.RLE_start_end -> {
                        val s = r.u(cu.addressSize); val e = r.u(cu.addressSize)
                        out += AddressRange(s, e, 0, RangeKind.RANGE_LIST, null, cu, 1)
                    }
                    DW.RLE_start_length -> {
                        val s = r.u(cu.addressSize); val len = r.uleb128()
                        out += AddressRange(s, s + len, 0, RangeKind.RANGE_LIST, null, cu, 1)
                    }
                    else -> {
                        issues += ParseIssue(".debug_rnglists", "WARNING", "UNKNOWN_RLE",
                            "CU 0x${cu.offset.toString(16)} unknown rnglist entry kind $kind; list abandoned",
                            offset = r.offset - 1L, cuOffset = cu.offset)
                        break
                    }
                }
            }
        } catch (e: Exception) {
            issues += ParseIssue(".debug_rnglists", "WARNING", "RNGLISTS_PARSE_FAILED",
                "CU 0x${cu.offset.toString(16)} rnglist truncated: ${e.message}",
                offset = offset, cuOffset = cu.offset)
        }
        return out
    }
}
