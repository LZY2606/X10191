package compass.dwarf

/**
 * range list 解析：
 * - DWARF 2/3/4: .debug_ranges，定长 address_size 条目对 + base address selection
 * - DWARF 5:     .debug_rnglists，带头与多种 entry kind（含 indexed / offset pair）
 *
 * 含 indexed（startx/base_addressx）的条目无法在本段内独立解析，
 * 以 [RnglistsSection.resolveWithAddrTable] 延迟到 .debug_addr 可用时解析，
 * 保证缺表时只影响这些条目，不污染普通条目。
 */

data class PendingRngList(
    val entries: List<RawRngEntry>,
    val startOffset: Long,
    val endOffset: Long,
)

sealed class RawRngEntry {
    data class StartEnd(val start: Long, val end: Long) : RawRngEntry()
    data class StartLength(val start: Long, val length: Long) : RawRngEntry()
    data class OffsetPair(val startOffset: Long, val endOffset: Long) : RawRngEntry()
    data class BaseAddress(val addr: Long) : RawRngEntry()
    data class StartxEndx(val startIdx: Long, val endIdx: Long) : RawRngEntry()
    data class StartxLength(val startIdx: Long, val length: Long) : RawRngEntry()
    data class BaseAddressx(val idx: Long) : RawRngEntry()
}

class RnglistsSection(
    /** list 相对段头的起始偏移 -> 原始列表。 */
    val rawLists: Map<Long, PendingRngList>,
    val addressSize: Int,
    val segmentSize: Int,
    val headerEndRelative: Long,
    val warnings: List<String>,
) {
    /** 已解析缓存（.debug_addr 注入后生成）。 */
    @Volatile private var resolved: Map<Long, List<AddrRange>>? = null

    fun listAt(offset: Long, addrTable: LongArray?): List<AddrRange> {
        val raw = rawLists[offset] ?: return emptyList()
        return resolve(raw, addrTable)
    }

    fun resolveWithAddrTable(addrTable: LongArray?): Map<Long, List<AddrRange>> {
        resolved?.let { return it }
        val m = linkedMapOf<Long, List<AddrRange>>()
        rawLists.forEach { (off, raw) -> m[off] = resolve(raw, addrTable) }
        resolved = m
        return m
    }

    private fun resolve(raw: PendingRngList, addrTable: LongArray?): List<AddrRange> {
        val out = mutableListOf<AddrRange>()
        var base = 0L
        for (e in raw.entries) when (e) {
            is RawRngEntry.BaseAddress -> base = e.addr
            is RawRngEntry.BaseAddressx -> base = addrTable?.getOrNull(e.idx.toInt()) ?: return markUnresolved(out)
            is RawRngEntry.StartEnd -> out.add(AddrRange(e.start, e.end))
            is RawRngEntry.StartLength -> out.add(AddrRange(e.start, e.start + e.length))
            is RawRngEntry.OffsetPair -> out.add(AddrRange(base + e.startOffset, base + e.endOffset))
            is RawRngEntry.StartxEndx -> {
                val s = addrTable?.getOrNull(e.startIdx.toInt()) ?: return markUnresolved(out)
                val en = addrTable?.getOrNull(e.endIdx.toInt()) ?: return markUnresolved(out)
                out.add(AddrRange(s, en))
            }
            is RawRngEntry.StartxLength -> {
                val s = addrTable?.getOrNull(e.startIdx.toInt()) ?: return markUnresolved(out)
                out.add(AddrRange(s, s + e.length))
            }
        }
        return out
    }

    private fun markUnresolved(prefix: List<AddrRange>): List<AddrRange> {
        // indexed 条目缺 .debug_addr：已可解析的非 indexed 前缀不丢弃，但调用方应记录 warning
        return prefix
    }
}

object RangeListParser {

    /** 读取 .debug_ranges 中某个绝对段偏移起始的列表（直到 end-of-list）。 */
    fun parseDebugRanges(blob: SectionBlob?, offset: Long, addressSize: Int, segmentSize: Int = 0): List<AddrRange> {
        if (blob == null || offset < 0 || offset >= blob.size) return emptyList()
        val view = blob.view()
        val r = view.reader(offset.toInt())
        val out = mutableListOf<AddrRange>()
        var base = 0L
        val maxV = if (addressSize == 8) -1L else 0xffffffffL
        var guard = 0
        try {
            while (!r.eof) {
                if (++guard > 1_000_000) break
                if (segmentSize > 0) r.bytes(segmentSize)
                val a = readAddr(r, addressSize)
                val b = readAddr(r, addressSize)
                if (a == maxV && b == 0L) break
                if (a == maxV) { base = b; continue }
                out.add(AddrRange(base + a, base + b))
            }
        } catch (e: DwarfBoundsException) {
            // 截断：返回完整前缀
        }
        return out
    }

    /** 解析整个 .debug_rnglists 段（DWARF5）。 */
    fun parseRnglists(blob: SectionBlob?): RnglistsSection {
        if (blob == null || blob.bytes.isEmpty()) {
            return RnglistsSection(emptyMap(), 8, 0, 0L, emptyList())
        }
        val view = blob.view()
        val r = view.reader(0)
        val warnings = mutableListOf<String>()
        val rawLists = linkedMapOf<Long, PendingRngList>()
        var addressSize = 8
        var segmentSize = 0
        try {
            val lengthField = r.u32()
            val is64 = lengthField == 0xffffffffL
            val unitLength = if (is64) r.u64() else lengthField
            r.u16() // version
            addressSize = r.u8()
            segmentSize = r.u8()
            r.u32() // padding / offset table count is next:
            val offsetEntryCount = r.u32()
            // 注意：DWARF5 header 布局：unit_length, version(2), address_size(1),
            // segment_selector_size(1), offset_entry_count(4)。上面 r.u32() 的第一次即 padding?
            // 重新严谨定位：
            r.seek(0)
            val headerStart = 0
            val lenBase = if (is64) 12 else 4
            r.seek(headerStart + lenBase + 2 + 1 + 1)
            val count = r.u32()
            val offsetTableStart = r.pos
            val offsets = (0 until count).map { if (is64) r.u64() else r.u32() }
            val headerEnd = offsetTableStart + count * (if (is64) 12 else 4)
            val listAreaBase = lenBase + 2 + 1 + 1 + 4
            val sectionEnd = if (is64) (lenBase + unitLength).toInt() else (4 + unitLength).toInt()
            val limit = sectionEnd.coerceAtMost(view.size)

            // 1) 按 offset table 登记
            for (relOff in offsets) {
                if (rawLists.containsKey(relOff)) continue
                val parsed = readOneList(view, listAreaBase + relOff.toInt(), addressSize, segmentSize, limit)
                if (parsed != null) rawLists[relOff] = parsed
            }
            // 2) 顺序扫描兜底（有些工具链不写 offset table，DW_AT_ranges 直接给相对偏移）
            var cursor = headerEnd
            while (cursor < limit) {
                val rel = (cursor - listAreaBase).toLong()
                val parsed = readOneList(view, cursor, addressSize, segmentSize, limit) ?: break
                rawLists.putIfAbsent(rel, parsed)
                cursor = parsed.endOffset.toInt().coerceAtLeast(cursor + 1)
            }
            return RnglistsSection(rawLists, addressSize, segmentSize, listAreaBase.toLong(), warnings)
        } catch (e: DwarfBoundsException) {
            warnings.add(".debug_rnglists truncated: ${e.message}")
        } catch (e: DwarfFormatException) {
            warnings.add(".debug_rnglists malformed: ${e.message}")
        }
        return RnglistsSection(rawLists, addressSize, segmentSize, 0L, warnings)
    }

    private fun readOneList(view: ByteView, start: Int, addressSize: Int, segmentSize: Int, limit: Int): PendingRngList? {
        if (start < 0 || start >= view.size) return null
        val r = view.reader(start)
        val entries = mutableListOf<RawRngEntry>()
        var guard = 0
        try {
            while (r.pos < limit) {
                if (++guard > 1_000_000) return null
                val kind = r.u8()
                when (kind) {
                    DW.RLKE_end -> return PendingRngList(entries, start.toLong(), r.pos.toLong())
                    DW.RLKE_base_addressx -> entries.add(RawRngEntry.BaseAddressx(r.uleb128()))
                    DW.RLKE_startx_endx -> entries.add(RawRngEntry.StartxEndx(r.uleb128(), r.uleb128()))
                    DW.RLKE_startx_length -> entries.add(RawRngEntry.StartxLength(r.uleb128(), r.uleb128()))
                    DW.RLKE_offset_pair -> entries.add(RawRngEntry.OffsetPair(r.uleb128(), r.uleb128()))
                    DW.RLKE_base_address -> {
                        if (segmentSize > 0) r.bytes(segmentSize)
                        entries.add(RawRngEntry.BaseAddress(readAddr(r, addressSize)))
                    }
                    DW.RLKE_start_end -> {
                        if (segmentSize > 0) r.bytes(segmentSize)
                        entries.add(RawRngEntry.StartLength(0, 0)).let { }
                        val s = readAddr(r, addressSize); val e = readAddr(r, addressSize)
                        entries.removeAt(entries.lastIndex)
                        entries.add(RawRngEntry.StartEnd(s, e))
                    }
                    DW.RLKE_start_length -> {
                        if (segmentSize > 0) r.bytes(segmentSize)
                        val s = readAddr(r, addressSize); val l = r.uleb128()
                        entries.add(RawRngEntry.StartLength(s, l))
                    }
                    else -> throw DwarfFormatException("unknown rnglists entry kind=0x${kind.toString(16)}")
                }
            }
        } catch (e: DwarfBoundsException) {
            return PendingRngList(entries, start.toLong(), r.pos.toLong())
        }
        return null
    }

    private fun readAddr(r: ByteView.Reader, addressSize: Int): Long = when (addressSize) {
        1 -> r.u8().toLong()
        2 -> r.u16().toLong() and 0xffff
        4 -> r.u32()
        8 -> r.u64()
        else -> throw DwarfFormatException("bad address_size $addressSize")
    }
}
