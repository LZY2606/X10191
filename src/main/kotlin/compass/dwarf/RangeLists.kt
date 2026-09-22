package compass.dwarf

import compass.elf.BinaryParseException
import compass.elf.Reader
import java.nio.ByteOrder

/**
 * 零长度范围（low==high 或 length==0）会保留为空范围：
 * 查询时它不覆盖任何地址，但 UI/结论中仍可展示“空范围”这一事实。
 */
class RangeListParser(
    private val debugRanges: ByteArray?,
    private val debugRngLists: ByteArray?,
    private val endian: ByteOrder
) {
    /** DWARF4 .debug_ranges：offset 为 section 内偏移，cuLowPc 为基址。 */
    fun parseDwarf4(offset: Long, dwarf64: Boolean, addressSize: Int, cuLowPc: Long): List<DieRange> {
        if (debugRanges == null) throw BinaryParseException("缺少 .debug_ranges section")
        if (offset < 0 || offset >= debugRanges.size) throw BinaryParseException(".debug_ranges 偏移越界 0x${offset.toString(16)}")
        val r = Reader(debugRanges, endian)
        r.dwarf64 = dwarf64
        r.seek(offset.toInt())
        val out = ArrayList<DieRange>()
        var base = cuLowPc
        var guard = 0
        while (true) {
            if (++guard > 100_000) throw BinaryParseException(".debug_ranges 条目数量超限")
            val a = readAddr(r, addressSize)
            val b = readAddr(r, addressSize)
            val max = if (addressSize == 8) -1L else 0xffffffffL
            if (a == 0L && b == 0L) break
            if (a == max) { base = b; continue }
            out.add(DieRange(base + a, base + b))
        }
        return out
    }

    private fun readAddr(r: Reader, size: Int): Long = when (size) {
        1 -> r.u1().toLong(); 2 -> r.u2().toLong(); 4 -> r.u4long(); 8 -> r.u8()
        else -> throw BinaryParseException("地址大小 $size")
    }

    /** DWARF5 .debug_rnglists：offset 为 list 在 section 内的偏移（rnglists_base + index*entsize 亦可由调用方处理）。 */
    fun parseDwarf5(offset: Long): List<DieRange> {
        if (debugRngLists == null) throw BinaryParseException("缺少 .debug_rnglists section")
        if (offset < 0 || offset >= debugRngLists.size) throw BinaryParseException(".debug_rnglists 偏移越界 0x${offset.toString(16)}")
        val r = Reader(debugRngLists, endian)
        r.seek(offset.toInt())
        // 若落在 list header 起点则跳过 header；调用方也可能直接传入 list 起点（以 end_of_list 结尾）。
        // 检测：首字节在 1..6 且像 header 版本时，按 header 解析。
        return if (looksLikeHeader(r, offset)) {
            val hr = Reader(debugRngLists, endian)
            hr.seek(offset.toInt())
            val startAfter = parseHeader(hr)
            val br = Reader(debugRngLists, endian)
            br.seek(startAfter)
            br.addressSize = hr.addressSize
            parseEntries(br, 0L)
        } else {
            r.addressSize = 8
            parseEntries(r, 0L)
        }
    }

    private fun looksLikeHeader(r: Reader, off: Long): Boolean {
        return try {
            val save = r.pos
            r.initialLength()
            val version = r.u2()
            r.seek(save)
            version == 5
        } catch (_: Exception) { false }
    }

    private fun parseHeader(r: Reader): Int {
        r.initialLength()
        r.u2() // version
        r.addressSize = r.u1()
        r.u1() // segment selector size
        r.u4long() // offset entry count
        r.u4() // offset table
        return r.pos
    }

    private fun parseEntries(r: Reader, initialBase: Long): List<DieRange> {
        var base = initialBase
        val out = ArrayList<DieRange>()
        var guard = 0
        while (!r.eof()) {
            if (++guard > 100_000) throw BinaryParseException(".debug_rnglists 条目数量超限")
            when (val kind = r.u1()) {
                RLE.end_of_list -> break
                RLE.base_addressx -> { r.uleb(); } // 需要 .debug_addr，fixture 不使用索引形式
                RLE.startx_endx -> { r.uleb(); r.uleb() }
                RLE.startx_length -> { r.uleb(); r.uleb() }
                RLE.offset_pair -> {
                    val a = r.uleb(); val b = r.uleb()
                    out.add(DieRange(base + a, base + b))
                }
                RLE.default_location -> { r.uleb() }
                RLE.base_address -> { base = when (r.addressSize) { 4 -> r.u4long(); else -> r.u8() } }
                RLE.start_end -> {
                    val a = when (r.addressSize) { 4 -> r.u4long(); else -> r.u8() }
                    val b = when (r.addressSize) { 4 -> r.u4long(); else -> r.u8() }
                    out.add(DieRange(a, b))
                }
                RLE.start_length -> {
                    val a = when (r.addressSize) { 4 -> r.u4long(); else -> r.u8() }
                    val b = r.uleb()
                    out.add(DieRange(a, a + b))
                }
                else -> throw BinaryParseException("未知 rnglist entry kind=$kind")
            }
        }
        return out
    }
}
