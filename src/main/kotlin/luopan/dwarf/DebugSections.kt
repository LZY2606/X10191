package luopan.dwarf

import luopan.model.AddressRange

/** 对一个 ELF 内全部 DWARF section 的访问器；包含 DWARF5 .debug_addr / range list 解析。 */
class DebugSections(val raw: Map<String, ByteArray>, val littleEndian: Boolean) {
    fun bytes(name: String): ByteArray? = raw[name]?.takeIf { it.isNotEmpty() }

    fun stringAt(section: String, offset: Long): String? {
        val data = bytes(section) ?: return null
        if (offset < 0 || offset >= data.size) return null
        var end = offset.toInt()
        while (end < data.size && data[end].toInt() != 0) end++
        if (end >= data.size) return null
        return String(data, offset.toInt(), end - offset.toInt(), Charsets.UTF_8)
    }

    fun resolve(v: FormValue): String? = when (v) {
        is FormValue.InString -> v.v
        is FormValue.StrRef -> stringAt(v.section, v.offset)
        else -> null
    }

    /**
     * 解析 DWARF5 .debug_addr 表，base 为 CU 的 DW_AT_addr_base（即 header 起点）。
     * 返回该 header 里 index 起始的地址数组。
     */
    fun addrTable(base: Long, dwarf64: Boolean): AddrTable? {
        val data = bytes(".debug_addr") ?: return null
        val r = ByteReader.of(data, littleEndian)
        try {
            r.seek(base.toInt())
            val (unitLen, contentStart, d64) = r.initialLength()
            val version = r.u16()
            if (version != 5) return null
            val addrSize = r.u8()
            r.u8() // segment selector size
            val tableStart = r.pos.toLong()
            val end = contentStart + unitLen
            val n = ((end - tableStart) / addrSize).toInt()
            val addrs = LongArray(n) { r.readFixed(addrSize) }
            return AddrTable(addrs, addrSize, dwarf64 || d64)
        } catch (e: DwarfBoundsException) {
            return null
        }
    }

    /** DWARF4 .debug_ranges：[base] 为 CU base (0 或 low_pc)。 */
    fun rangesV4(offset: Long, baseAddr: Long, addressSize: Int): List<AddressRange> {
        val data = bytes(".debug_ranges") ?: return emptyList()
        val r = ByteReader.of(data, littleEndian)
        val out = ArrayList<AddressRange>()
        try {
            r.seek(offset.toInt())
            var base = baseAddr
            var guard = 0
            while (guard++ < MAX_RANGES) {
                val a = r.readFixed(addressSize)
                val b = r.readFixed(addressSize)
                if (a == 0L && b == 0L) break
                if (addressSize == 4) {
                    val max = 0xffffffffL
                    if (a == max) { base = b; continue }
                    out += AddressRange(base + a, base + b)
                } else {
                    if (a == -1L) { base = b; continue }
                    out += AddressRange(base + a, base + b)
                }
            }
        } catch (e: DwarfBoundsException) {
            // 截断：保留已解析
        }
        return out
    }

    /** DWARF5 .debug_rnglists：返回某个 offset 处列表的全部 entry（绝对地址）。 */
    fun rnglistsV5(offset: Long, addrTable: AddrTable?, addressSize: Int): List<AddressRange> {
        val data = bytes(".debug_rnglists") ?: return emptyList()
        val r = ByteReader.of(data, littleEndian)
        val out = ArrayList<AddressRange>()
        try {
            r.seek(offset.toInt())
            var base = 0L
            var guard = 0
            while (guard++ < MAX_RANGLES) {
                val kind = r.u8()
                when (kind) {
                    DwRle.END_OF_LIST -> break
                    DwRle.BASE_ADDRESSX -> {
                        val idx = r.uleb128().first
                        base = addrTable?.get(idx) ?: 0L
                    }
                    DwRle.STARTX_ENDX -> {
                        val s = r.uleb128().first; val e = r.uleb128().first
                        out += AddressRange(addrTable?.get(s) ?: 0L, addrTable?.get(e) ?: 0L)
                    }
                    DwRle.STARTX_LENGTH -> {
                        val s = r.uleb128().first; val len = r.uleb128().first
                        val sa = addrTable?.get(s) ?: 0L
                        out += AddressRange(sa, sa + len)
                    }
                    DwRle.OFFSET_PAIR -> {
                        val s = r.readFixed(addressSize); val e = r.readFixed(addressSize)
                        out += AddressRange(base + s, base + e)
                    }
                    DwRle.BASE_ADDRESS -> { base = r.readFixed(addressSize) }
                    DwRle.START_END -> {
                        out += AddressRange(r.readFixed(addressSize), r.readFixed(addressSize))
                    }
                    DwRle.START_LENGTH -> {
                        val s = r.readFixed(addressSize); val len = r.readFixed(addressSize)
                        out += AddressRange(s, s + len)
                    }
                    else -> throw DwarfFormatException("unknown rnglists entry kind 0x${kind.toString(16)}")
                }
            }
        } catch (e: DwarfBoundsException) {
            // 保留已解析
        }
        return out
    }

    companion object {
        const val MAX_RANGES = 1_000_000
        const val MAX_RANGLES = 1_000_000
    }
}

data class AddrTable(val addrs: LongArray, val addressSize: Int, val dwarf64: Boolean) {
    fun get(index: Long): Long? =
        if (index < 0 || index >= addrs.size) null else addrs[index.toInt()]
}
