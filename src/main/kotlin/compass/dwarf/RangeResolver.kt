package compass.dwarf

import compass.util.ByteReader
import compass.util.ParseException
import compass.util.U64

/**
 * Resolves DW_AT_ranges for one CU, supporting:
 *   - DWARF <=4 .debug_ranges (absolute offsets, base-address pairs, terminators)
 *   - DWARF 5  .debug_rnglists (header + entry kinds 0..7, rnglistx indices)
 *   - addrx forms resolved through .debug_addr
 * Zero-length ranges are preserved (start == end).
 */
class RangeResolver(private val sections: Sections, private val debugData: DebugData) {

    private val v4Cache = HashMap<U64, List<AddrRange>>()

    fun rangesFor(cu: CompilationUnit, die: Die): List<AddrRange> {
        val lowPc = (die.attrs[DwAt.LOW_PC] as? AttrValue.Addr)?.a
        val high = die.attrs[DwAt.HIGH_PC]
        if (lowPc != null && high != null) {
            return when (high) {
                is AttrValue.Addr -> listOf(AddrRange(lowPc, high.a, source = "low_pc/high_pc"))
                is AttrValue.UConst -> listOf(AddrRange(lowPc, U64(lowPc.v + high.v.v), source = "low_pc/high_pc(offset)"))
                else -> emptyList()
            }
        }
        if (lowPc != null) {
            // low_pc alone: single-address (zero length) marker
            return listOf(AddrRange(lowPc, lowPc, source = "low_pc-only"))
        }
        val rangesAttr = die.attrs[DwAt.RANGES] ?: return emptyList()
        val offset = when (rangesAttr) {
            is AttrValue.SecOff -> rangesAttr.v
            is AttrValue.UConst -> rangesAttr.v
            is AttrValue.RngListIndex -> rngListOffset(cu, rangesAttr.index)
            else -> throw ParseException("DW_AT_ranges unsupported form")
        }
        return if (cu.dwarfVersion >= 5) parseRnglistsV5(cu, offset) else parseRangesV4(cu, offset)
    }

    /** rnglistx: Nth offset entry relative to the CU's rnglists_base contribution. */
    private fun rngListOffset(cu: CompilationUnit, index: U64): U64 {
        val bytes: ByteArray = (if (cu.kind == "split") sections[".debug_rnglists.dwo"] else null)
            ?: sections[".debug_rnglists"]
            ?: throw ParseException("DW_FORM_rnglistx but no .debug_rnglists")
        val base = cu.rnglistsBase?.v?.toLong() ?: 0L
        val offSize = if (cu.dwarf64) 8 else 4
        val entOff = (base + index.v.toLong() * offSize).toInt()
        val r = ByteReader(bytes, entOff)
        val rel = if (offSize == 4) r.u32() else r.u64().v
        val hdrStart = findContributionStart(bytes, base)
        return U64(hdrStart + rel)
    }

    /** The offset table sits right after the 12-byte v5 rnglists header; lists begin after it. */
    private fun findContributionStart(bytes: ByteArray, base: Long): Long {
        // rnglists_base usually points directly at the header for the CU's contribution.
        if (base + 12 <= bytes.size) {
            val h = ByteReader(bytes, base.toInt())
            val length = h.u32()
            val version = h.u16()
            if (version == 5 && length in 12..Int.MAX_VALUE.toLong()) return base
        }
        return base
    }

    private fun parseRnglistsV5(cu: CompilationUnit, offset: U64): List<AddrRange> {
        val sec = if (cu.kind == "split") ".debug_rnglists.dwo" else ".debug_rnglists"
        val bytes = sections[sec] ?: throw ParseException("missing $sec")
        val r = ByteReader(bytes, offset.v.toInt())
        val out = ArrayList<AddrRange>()
        var baseAddr: U64? = null
        while (true) {
            val kind = r.u8()
            when (kind) {
                DwRle.END_OF_LIST -> break
                DwRle.BASE_ADDRESSX -> {
                    val idx = r.uleb128()
                    baseAddr = debugData.readAddr(cu.addrBase ?: U64.ZERO, idx, cu.addressSize, cu.dwarfVersion, cu.kind == "split")
                }
                DwRle.STARTX_ENDX -> {
                    val sIdx = r.uleb128()
                    val eIdx = r.uleb128()
                    val s = debugData.readAddr(cu.addrBase ?: U64.ZERO, sIdx, cu.addressSize, cu.dwarfVersion, cu.kind == "split")
                    val e = debugData.readAddr(cu.addrBase ?: U64.ZERO, eIdx, cu.addressSize, cu.dwarfVersion, cu.kind == "split")
                    out += AddrRange(s, e, source = "rnglists/startx_endx")
                }
                DwRle.STARTX_LENGTH -> {
                    val sIdx = r.uleb128()
                    val len = r.uleb128()
                    val s = debugData.readAddr(cu.addrBase ?: U64.ZERO, sIdx, cu.addressSize, cu.dwarfVersion, cu.kind == "split")
                    out += AddrRange(s, U64(s.v + len), source = "rnglists/startx_length")
                }
                DwRle.OFFSET_PAIR -> {
                    val sOff = r.sleb128()
                    val eOff = r.sleb128()
                    val b = baseAddr ?: throw ParseException("rnglists offset_pair without base")
                    out += AddrRange(U64(b.v + sOff), U64(b.v + eOff), source = "rnglists/offset_pair")
                }
                DwRle.BASE_ADDRESS -> baseAddr = readAddr(r, cu.addressSize)
                DwRle.START_END -> {
                    val s = readAddr(r, cu.addressSize)
                    val e = readAddr(r, cu.addressSize)
                    out += AddrRange(s, e, source = "rnglists/start_end")
                }
                DwRle.START_LENGTH -> {
                    val s = readAddr(r, cu.addressSize)
                    val len = r.uleb128()
                    out += AddrRange(s, U64(s.v + len), source = "rnglists/start_length")
                }
                else -> throw ParseException("unknown rnglist entry kind 0x${kind.toString(16)}")
            }
        }
        return out
    }

    private fun readAddr(r: ByteReader, size: Int): U64 = if (size == 4) U64(r.u32()) else r.u64()

    private fun parseRangesV4(cu: CompilationUnit, offset: U64): List<AddrRange> {
        return v4Cache.getOrPut(U64(offset.v)) {
            val bytes = sections[".debug_ranges"] ?: throw ParseException("missing .debug_ranges")
            val size = cu.addressSize
            val r = ByteReader(bytes, offset.v.toInt())
            val max = if (size == 4) 0xffffffffL else -1L
            val out = ArrayList<AddrRange>()
            var base = U64.ZERO
            while (true) {
                val a = readRaw(r, size)
                val b = readRaw(r, size)
                if (a.v == max && b.v == 0L) break
                if (a.v == max) {
                    base = b
                    continue
                }
                out += AddrRange(U64(base.v + a.v), U64(base.v + b.v), source = "debug_ranges")
            }
            out
        }
    }

    private fun readRaw(r: ByteReader, size: Int): U64 = if (size == 4) U64(r.u32()) else r.u64()
}
