package com.luopan.dwarf

import com.luopan.dwarf.DwarfAttr as A

object RangeResolver {
    private const val DW_RLE_END = 0x00
    private const val DW_RLE_BASE_ADDRESSX = 0x01
    private const val DW_RLE_STARTX_ENDX = 0x02
    private const val DW_RLE_START_END = 0x03
    private const val DW_RLE_OFFSET = 0x04

    fun collect(
        dies: List<Die>,
        sections: DwarfSections,
        version: Int,
        addressSize: Int,
        offsetSize: Int,
        dwarf64: Boolean,
        cuBase: Long,
        addrBase: Long,
        useDwo: Boolean,
        jumps: JumpBudget,
        diag: MutableList<Diagnostic>,
        cuName: String,
    ): List<DieRange> {
        val out = ArrayList<DieRange>()
        for (die in dies) {
            val low = die.attr(A.LOW_PC)
            val high = die.attr(A.HIGH_PC)
            if (low is AttrVal.Addr && high != null) {
                when (high) {
                    is AttrVal.Addr -> out.add(
                        DieRange(die.index, AddrRange(low.v, high.v), "low_high"))
                    is AttrVal.Const -> out.add(
                        // high_pc 为常量 => 长度（允许 0 长度范围）
                        DieRange(die.index, AddrRange(low.v, low.v + high.v), "low_const"))
                    else -> diag.add(Diagnostic("WARNING", "ranges",
                        "DIE 0x${"%x".format(die.offset)}: unsupported high_pc form", cuName))
                }
            }
            val rangesAttr = die.attr(A.RANGES)
            if (rangesAttr is AttrVal.SecOffset) {
                try {
                    if (version >= 5) {
                        out.addAll(parseRnglists(sections, rangesAttr.offset.toInt(), addressSize,
                            die.index, cuBase, addrBase, jumps))
                    } else {
                        out.addAll(parseDebugRanges(sections, rangesAttr.offset.toInt(), addressSize,
                            die.index, cuBase))
                    }
                } catch (ex: DwarfReadException) {
                    diag.add(Diagnostic("WARNING", "ranges",
                        "DIE 0x${"%x".format(die.offset)} range list unreadable: ${ex.message}", cuName))
                }
            }
        }
        return out
    }

    private fun parseDebugRanges(
        sections: DwarfSections, offset: Int, addressSize: Int,
        dieIndex: Int, cuBase: Long,
    ): List<DieRange> {
        val data = sections.ranges
            ?: throw DwarfReadException("DW_AT_ranges without .debug_ranges")
        val b = Binary(data, 0, data.size)
        b.seek(offset)
        var base = cuBase
        val out = ArrayList<DieRange>()
        val maxEntries = 1 shl 20
        var n = 0
        while (true) {
            if (++n > maxEntries) throw DwarfReadException("range list too long")
            val start = b.uint(addressSize)
            val end = b.uint(addressSize)
            val max = if (addressSize == 4) 0xffffffffL else -1L
            if (start == 0L && end == 0L) break
            if (start == max) { base = end; continue }
            out.add(DieRange(dieIndex, AddrRange(start + base, end + base), "ranges"))
        }
        return out
    }

    private fun parseRnglists(
        sections: DwarfSections, headerOffset: Int, addressSize: Int,
        dieIndex: Int, cuBase: Long, addrBase: Long, jumps: JumpBudget,
    ): List<DieRange> {
        val data = sections.rnglists
            ?: throw DwarfReadException("DW_AT_ranges without .debug_rnglists")
        jumps.jump()
        val b = Binary(data, 0, data.size)
        b.seek(headerOffset)
        var base = cuBase
        val out = ArrayList<DieRange>()
        val maxEntries = 1 shl 20
        var n = 0
        loop@ while (b.available() > 0) {
            if (++n > maxEntries) throw DwarfReadException("rnglist too long")
            when (val kind = b.u1()) {
                DW_RLE_END -> break@loop
                DW_RLE_BASE_ADDRESSX -> {
                    val idx = b.uleb().toInt()
                    base = readAddr(sections, (addrBase + idx.toLong() * addressSize).toInt(), addressSize)
                }
                DW_RLE_STARTX_ENDX -> {
                    val sIdx = b.uleb().toInt(); val eIdx = b.uleb().toInt()
                    val s = readAddr(sections, (addrBase + sIdx.toLong() * addressSize).toInt(), addressSize)
                    val e = readAddr(sections, (addrBase + eIdx.toLong() * addressSize).toInt(), addressSize)
                    out.add(DieRange(dieIndex, AddrRange(s, e), "rnglists"))
                }
                DW_RLE_START_END -> {
                    val s = b.uint(addressSize); val e = b.uint(addressSize)
                    out.add(DieRange(dieIndex, AddrRange(s, e), "rnglists"))
                }
                DW_RLE_OFFSET -> {
                    val off = b.uint(addressSize)
                    out.add(DieRange(dieIndex, AddrRange(cuBase + off, cuBase + b.uint(addressSize)), "rnglists"))
                }
                else -> throw DwarfReadException("unsupported DW_RLE kind 0x%x at rnglists offset %d".format(kind, b.pos))
            }
        }
        return out
    }

    private fun readAddr(sections: DwarfSections, off: Int, addressSize: Int): Long {
        val data = sections.addr ?: throw DwarfReadException("address index without .debug_addr")
        val b = Binary(data, 0, data.size); b.seek(off)
        return b.uint(addressSize)
    }
}
