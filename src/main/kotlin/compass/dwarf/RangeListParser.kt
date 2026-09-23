package compass.dwarf

import compass.core.ByteCursor
import compass.core.CursorException

class RangeListParser(private val sections: DebugSections) {

    fun parseAll(): RangeLists {
        val issues = ArrayList<ParseIssue>()
        return RangeLists(parseV4(issues), parseV5(issues), issues)
    }

    /** .debug_ranges：以 list 在 section 内的起始偏移为键。 */
    private fun parseV4(issues: MutableList<ParseIssue>): Map<Long, List<RngV4Entry>> {
        val c = sections.cursor(".debug_ranges") ?: return emptyMap()
        // section 内可能混用地址宽度；CU 解析时再按 CU 宽度切片读取，这里按 8/4 各建一份代价大。
        // 采用：按“起始 offset”在 CU 需要时惰性解析（见 [parseV4At]），此处不做全量。
        return emptyMap()
    }

    fun parseV4At(sectionOffset: Long, addressSize: Int): List<RngV4Entry>? {
        val c = sections.cursor(".debug_ranges") ?: return null
        return try {
            c.jump(sectionOffset, 0)
            val entries = ArrayList<RngV4Entry>()
            val maxAddr = if (addressSize < 8) (-1L ushr (64 - addressSize * 8)) else -1L
            while (true) {
                val begin = readAddr(c, addressSize)
                val end = readAddr(c, addressSize)
                when {
                    begin == 0L && end == 0L -> { entries += RngV4Entry.End; break }
                    begin == maxAddr -> entries += RngV4Entry.Base(end)
                    (addressSize == 4 && begin == 0xfffffffeL) || (addressSize == 8 && begin == maxAddr - 1) -> {
                        // GNU indexed address pair: selector, 0, index, begin, end（已消费 selector+0）
                        val idx = readAddr(c, addressSize)
                        val rb = readAddr(c, addressSize)
                        val re = readAddr(c, addressSize)
                        entries += RngV4Entry.Indexed(idx, rb, re)
                    }
                    else -> entries += RngV4Entry.Pair(begin, end)
                }
                if (entries.size > MAX_ENTRIES) throw CursorException("ranges 条目超限")
            }
            entries
        } catch (e: CursorException) { null }
    }

    /** .debug_rnglists：可含多个单元，键为每个 list 数据的绝对 section offset。 */
    private fun parseV5(issues: MutableList<ParseIssue>): Map<Long, RngV5List> {
        val c = sections.cursor(".debug_rnglists") ?: return emptyMap()
        val out = LinkedHashMap<Long, RngV5List>()
        c.pos = 0
        while (c.remaining() > 4) {
            val unitStart = c.pos
            val len0 = c.u32()
            val dwarf64 = len0 == 0xffffffffL
            val unitLength = if (dwarf64) c.i64() else len0
            val unitEnd = c.pos - (if (dwarf64) 12 else 4) + unitLength.toInt()
            if (unitEnd > c.limit || unitEnd <= c.pos) {
                issues += ParseIssue(ParseIssue.Severity.ERROR, "rnglists.length", "rnglists 单元长度非法", ".debug_rnglists", unitStart.toLong())
                break
            }
            c.u16() // version
            val addressSize = c.u8()
            val segmentSize = c.u8()
            val offsetTableSize = (if (dwarf64) c.i64() else c.u32()).toInt()
            c.pos += offsetTableSize // offset array 用不到（CU 用 rnglists_base + index）
            while (c.pos < unitEnd) {
                val listStart = c.pos.toLong()
                val items = ArrayList<RngV5Item>()
                var bad = false
                while (true) {
                    val kind = c.u8()
                    when (kind) {
                        Rng.END -> { items += RngV5Item.EndList; break }
                        Rng.BASE_ADDRESSX -> items += RngV5Item.BaseAddressX(c.uleb128())
                        Rng.STARTX_ENDX -> items += RngV5Item.StartxEndx(c.uleb128(), c.uleb128())
                        Rng.STARTX_LENGTH -> items += RngV5Item.StartxLength(c.uleb128(), c.uleb128())
                        Rng.OFFSET_PAIR -> {
                            var seg = 0L
                            if (segmentSize > 0) seg = readAddr(c, segmentSize)
                            items += RngV5Item.OffsetPair(seg, c.sleb128(), c.sleb128())
                        }
                        Rng.BASE_ADDRESS -> items += RngV5Item.BaseAddress(readAddr(c, addressSize))
                        Rng.START_END -> {
                            var seg = 0L
                            if (segmentSize > 0) seg = readAddr(c, segmentSize)
                            items += RngV5Item.StartEnd(seg, readAddr(c, addressSize), readAddr(c, addressSize))
                        }
                        Rng.START_LENGTH -> {
                            var seg = 0L
                            if (segmentSize > 0) seg = readAddr(c, segmentSize)
                            items += RngV5Item.StartLength(seg, readAddr(c, addressSize), readAddr(c, addressSize))
                        }
                        else -> {
                            issues += ParseIssue(ParseIssue.Severity.ERROR, "rnglists.unknown",
                                "未知 rnglist 条目 kind=$kind，该单元后续 list 不解析", ".debug_rnglists", c.pos.toLong() - 1L)
                            bad = true
                            break
                        }
                    }
                    if (items.size > MAX_ENTRIES) throw CursorException("rnglist 条目超限")
                }
                out[listStart] = RngV5List(addressSize, segmentSize, items)
                if (bad) break
            }
            c.pos = unitEnd
        }
        return out
    }

    private fun readAddr(c: ByteCursor, n: Int): Long = when (n) {
        1 -> c.u8().toLong(); 2 -> c.u16().toLong(); 4 -> c.u32(); 8 -> c.i64()
        else -> throw CursorException("不支持地址宽度 $n")
    }

    companion object { const val MAX_ENTRIES = 1_000_000 }
}
