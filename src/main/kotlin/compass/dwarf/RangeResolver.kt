package compass.dwarf

import compass.elf.Cursor
import compass.elf.sleb128
import compass.elf.uleb128

/**
 * Resolves the address ranges of a DIE:
 *  - [low_pc, high_pc) with high_pc as an absolute address, or
 *    [low_pc, low_pc + high_pc) with high_pc as a constant length;
 *  - DW_AT_ranges into .debug_ranges (DWARF <= 4) or .debug_rnglists (DWARF 5).
 *
 * Zero-length results are preserved: they are legal DWARF and still deserve an
 * explanation ("a range exists but it is empty").
 */
class RangeResolver(private val data: DwarfData) {

    fun dieRanges(die: Die, cu: CompilationUnit): List<AddrRange> {
        val low = die.attr(Attr.LOW_PC)?.value as? FormValue.Addr
        val high = die.attr(Attr.HIGH_PC)?.value
        val rangesAttr = die.attr(Attr.RANGES)?.value

        val out = ArrayList<AddrRange>()
        if (low != null) {
            when (high) {
                is FormValue.Addr -> out.add(AddrRange(low.v, high.v))
                is FormValue.Number -> out.add(AddrRange(low.v, low.v + high.v.toULong()))
                else -> out.add(AddrRange(low.v, low.v))
            }
        } else if (high != null) {
            data.warnings += "DIE at ${die.offset} has high_pc without low_pc; ignored"
        }

        when (rangesAttr) {
            is FormValue.SecOffset -> {
                if (cu.version >= 5) out.addAll(readRnglists(rangesAttr.v, cu))
                else out.addAll(readDebugRanges(rangesAttr.v, cu))
            }
            is FormValue.Number -> {
                // GNU split DWARF DW_AT_ranges index form: index * address_size.
                if (cu.version >= 5) data.warnings += "unexpected rnglist index form"
                else out.addAll(readDebugRanges(rangesAttr.v * cu.addressSize, cu))
            }
            else -> {}
        }
        return normalize(out)
    }

    private fun baseAddress(cu: CompilationUnit): ULong =
        (cu.root.attr(Attr.LOW_PC)?.value as? FormValue.Addr)?.v ?: 0UL

    private fun readDebugRanges(secOffset: Long, cu: CompilationUnit): List<AddrRange> {
        val bytes = data.debugRanges ?: run {
            data.warnings += "DW_AT_ranges used but .debug_ranges is absent"
            return emptyList()
        }
        val addrSize = cu.addressSize
        if (secOffset < 0 || secOffset >= bytes.size) {
            data.warnings += ".debug_ranges offset $secOffset out of bounds"
            return emptyList()
        }
        val terminator = when (addrSize) {
            1 -> 0xFFUL; 2 -> 0xFFFFUL; 4 -> 0xFFFFFFFFUL; else -> ULong.MAX_VALUE
        }
        val c = Cursor(bytes, secOffset.toInt(), bytes.size - secOffset.toInt(), data.littleEndian)
        var base = baseAddress(cu)
        val out = ArrayList<AddrRange>()
        var guard = 0
        while (true) {
            if (++guard > MAX_ENTRIES) throw DwarfParseException("ranges entry limit exceeded")
            if (c.remaining < addrSize * 2) {
                data.warnings += ".debug_ranges list at $secOffset truncated"
                break
            }
            val start = readAddr(c, addrSize)
            val end = readAddr(c, addrSize)
            if (start == terminator && end == 0UL) break
            if (start == terminator) { base = end; continue }
            if (start == 0UL && end == 0UL) break
            out.add(AddrRange(start + base, end + base))
        }
        return normalize(out)
    }

    private fun readRnglists(secOffset: Long, cu: CompilationUnit): List<AddrRange> {
        val bytes = data.debugRnglists ?: run {
            data.warnings += "DW_AT_ranges used but .debug_rnglists is absent"
            return emptyList()
        }
        if (secOffset < 0 || secOffset >= bytes.size) {
            data.warnings += ".debug_rnglists offset $secOffset out of bounds"
            return emptyList()
        }
        val c = Cursor(bytes, secOffset.toInt(), bytes.size - secOffset.toInt(), data.littleEndian)
        var base = baseAddress(cu)
        val out = ArrayList<AddrRange>()
        var guard = 0
        while (true) {
            if (++guard > MAX_ENTRIES) throw DwarfParseException("rnglist entry limit exceeded")
            if (c.remaining <= 0) break
            when (val kind = c.u8()) {
                0x00 -> break
                0x01 -> {
                    val start = readAddr(c, cu.addressSize)
                    val end = readAddr(c, cu.addressSize)
                    out.add(AddrRange(start, end))
                }
                0x02 -> {
                    val length = c.uleb128()
                    val start = readAddr(c, cu.addressSize)
                    out.add(AddrRange(start, start + length))
                }
                0x03 -> {
                    val index = c.u8().toULong()
                    val length = c.uleb128()
                    val start = readAddr(c, cu.addressSize) + index
                    out.add(AddrRange(start, start + length))
                }
                0x04 -> base = readAddr(c, cu.addressSize)
                0x05 -> base = baseAddress(cu)
                else -> {
                    data.warnings += "unknown .debug_rnglists entry kind 0x${kind.toString(16)}; list stopped"
                    break
                }
            }
        }
        return normalize(out)
    }

    private fun readAddr(c: Cursor, size: Int): ULong = when (size) {
        1 -> c.u8().toULong()
        2 -> c.u16().toULong()
        4 -> c.u32().toULong()
        8 -> c.u64()
        else -> throw DwarfParseException("bad address size $size in ranges")
    }

    companion object {
        const val MAX_ENTRIES = 100_000

        /** Sort by start and coalesce overlapping/adjacent non-empty ranges. */
        fun normalize(ranges: List<AddrRange>): List<AddrRange> {
            if (ranges.size <= 1) return ranges.toList()
            val sorted = ranges.sortedWith(compareBy({ it.start }, { it.end }))
            val out = ArrayList<AddrRange>()
            for (r in sorted) {
                val last = out.lastOrNull()
                if (last != null && r.start <= last.end && last.length > 0UL && r.length > 0UL) {
                    if (r.end > last.end) out[out.size - 1] = AddrRange(last.start, r.end)
                } else {
                    out.add(r)
                }
            }
            return out
        }
    }
}
