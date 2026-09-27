package compass.dwarf

import compass.model.AddrRange
import compass.model.BoundsException
import compass.model.Endian

/**
 * .debug_rnglists (DWARF5) 一个贡献块的头部信息。
 * CU 的 rnglists_base 指向贡献块（含头部），DW_AT_ranges 是节内绝对偏移（落在某贡献块内）。
 */
data class RngListContribution(
    val offset: Long,
    val length: Long,
    val version: Int,
    val addressSize: Int,
    val segmentSelectorSize: Int,
    val offsetEntryCount: Long,
    val offsetEntryOff: Long, // 偏移表起点（相对节）
    val dataStart: Long       // 条目数据起点（相对节）
)

fun parseRngListContributions(data: ByteArray?, endian: Endian): List<RngListContribution> {
    val out = ArrayList<RngListContribution>()
    if (data == null || data.isEmpty()) return out
    val r = ByteReader(data)
    var guard = 0
    while (r.remaining > 8 && guard++ < 100_000) {
        val off = r.pos.toLong()
        val (len, fmt, contentStart) = r.readInitialLength(endian)
        if (len <= 0 || contentStart.toLong() + len > data.size) break
        val version = r.readU16(endian)
        val addressSize = r.readByte()
        val segSize = r.readByte()
        val offsetEntryCount = r.readU32(endian)
        val offsetTableStart = r.pos.toLong()
        r.seek((offsetTableStart + offsetEntryCount * 4L).toInt())
        val dataStart = r.pos.toLong()
        out += RngListContribution(off, len, version, addressSize, segSize, offsetEntryCount, offsetTableStart, dataStart)
        r.seek((contentStart + len).toInt())
    }
    return out
}

class RangeListContext(
    val endian: Endian,
    val addressSize: Int,
    val segSelectorSize: Int,
    val debugRanges: ByteArray?,      // DWARF <=4
    val rnglists: ByteArray?,         // DWARF5
    val rngContributions: List<RngListContribution>,
    val debugAddr: ByteArray?,        // .debug_addr
    val addrBase: Long,               // 该 CU 的 addr_base（节内偏移，指向贡献块头部后）
    val version: Int
) {
    fun readAddrIndex(index: Long): Long {
        if (debugAddr == null) throw BoundsException("DW_FORM_addrx but no .debug_addr")
        // addr_base 直接指向第一个地址（贡献块头部之后）
        val off = (addrBase + index * addressSize).toInt()
        if (off < 0 || off + addressSize > debugAddr.size)
            throw BoundsException("addr index $index out of .debug_addr (base=$addrBase)")
        return ByteReader(debugAddr, off, addressSize).readAddress(addressSize, endian)
    }

    /** DWARF<=4：ranges 节内偏移。 */
    fun readV4RangeList(sectionOff: Long): List<AddrRange> {
        if (debugRanges == null) throw BoundsException("DW_AT_ranges but no .debug_ranges")
        if (sectionOff < 0 || sectionOff >= debugRanges.size)
            throw BoundsException("rnglist offset $sectionOff outside .debug_ranges")
        val r = ByteReader(debugRanges, sectionOff.toInt(), debugRanges.size - sectionOff.toInt())
        val out = ArrayList<AddrRange>()
        var base = 0L
        val allOnes = if (addressSize >= 8) -1L else (1L shl (8 * addressSize)) - 1
        var guard = 0
        while (guard++ < 1_000_000) {
            if (segSelectorSize > 0) repeat(segSelectorSize) { r.readByte() }
            val a = r.readAddress(addressSize, endian)
            val b = r.readAddress(addressSize, endian)
            if (a == 0L && b == 0L) break
            if (a == allOnes) { base = b; continue }
            out += AddrRange(a + base, b + base)
        }
        return out
    }

    /** DWARF5：节内绝对偏移。 */
    fun readV5RangeList(sectionOff: Long): List<AddrRange> {
        if (rnglists == null) throw BoundsException("DW_AT_ranges but no .debug_rnglists")
        val contrib = rngContributions.firstOrNull { sectionOff >= it.dataStart && sectionOff < it.offset + it.length + 11 }
            ?: throw BoundsException("rnglist offset 0x${sectionOff.toString(16)} not within any contribution")
        val out = ArrayList<AddrRange>()
        var base = 0L
        val r = ByteReader(rnglists, sectionOff.toInt(), rnglists.size - sectionOff.toInt())
        var guard = 0
        while (guard++ < 1_000_000) {
            val kind = r.readByte()
            when (kind) {
                DW_RLE.END_OF_LIST -> break
                DW_RLE.BASE_ADDRESSX -> base = readAddrIndex(r.readULEB128())
                DW_RLE.STARTX_ENDX -> {
                    val s = readAddrIndex(r.readULEB128()); val e = readAddrIndex(r.readULEB128())
                    out += AddrRange(s, e)
                }
                DW_RLE.STARTX_LENGTH -> {
                    val s = readAddrIndex(r.readULEB128()); val l = r.readULEB128()
                    out += mkRange(s, s + l)
                }
                DW_RLE.OFFSET_PAIR -> {
                    val a = r.readAddress(addressSize, endian); val b = r.readAddress(addressSize, endian)
                    out += AddrRange(base + a, base + b)
                }
                DW_RLE.BASE_ADDRESS -> base = r.readAddress(addressSize, endian)
                DW_RLE.START_END -> {
                    val a = r.readAddress(addressSize, endian); val b = r.readAddress(addressSize, endian)
                    out += AddrRange(a, b)
                }
                DW_RLE.START_LENGTH -> {
                    val a = r.readAddress(addressSize, endian); val b = r.readULEB128()
                    out += mkRange(a, a + b)
                }
                else -> throw BoundsException("unknown DW_RLE 0x${kind.toString(16)} in rnglist")
            }
        }
        @Suppress("UNUSED_VARIABLE") val unused = contrib
        return out
    }

    private fun mkRange(low: Long, high: Long): AddrRange =
        if (high == low) AddrRange(low, high, zeroLength = true, source = "ranges")
        else AddrRange(low, high)
}
