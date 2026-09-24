package compass

object RangesParser {
    private const val DW_RLE_end_of_list = 0
    private const val DW_RLE_base_addressx = 1
    private const val DW_RLE_startx_endx = 2
    private const val DW_RLE_startx_length = 3
    private const val DW_RLE_offset_pair = 4
    private const val DW_RLE_base_address = 5
    private const val DW_RLE_start_end = 6
    private const val DW_RLE_start_length = 7

    fun parseV4(bytes: ByteArray, offset: Long, baseAddress: Long, addressSize: Int, endian: Int, segmentSize: Int): List<RangeEdge> {
        if (bytes.isEmpty() || offset < 0 || offset >= bytes.size) throw CursorException("range list offset out of bounds", offset)
        val reader = ByteReader(bytes)
        reader.pos = offset.toInt()
        var base = baseAddress
        val result = mutableListOf<RangeEdge>()
        var ordinal = 0
        val max = -1L

        while (true) {
            val start = readAddress(reader, addressSize, endian, segmentSize)
            val end = readAddress(reader, addressSize, endian, segmentSize)
            val isEnd = if (segmentSize > 0) start.address == max && end.address == max else start.address == 0L && end.address == 0L
            val isBase = if (segmentSize > 0) start.address == max && end.address != max else start.address == max && end.address != 0L
            when {
                isEnd -> break
                isBase -> base = end.address
                else -> {
                    val s = base + start.address
                    val e = base + end.address
                    result += RangeEdge(s, e, start.segment, "ranges", ordinal++)
                }
            }
        }
        return result
    }

    data class V5Table(val entriesOffset: Long, val offsets: List<Long>)

    fun parseV5Header(bytes: ByteArray, headerOffset: Long, endian: Int): V5Table {
        if (bytes.isEmpty() || headerOffset < 0 || headerOffset >= bytes.size) throw CursorException("range list header out of bounds", headerOffset)
        val reader = ByteReader(bytes)
        reader.pos = headerOffset.toInt()
        val first = reader.u32(endian)
        val is64 = first == 0xffffffffL
        val unitLength = if (is64) reader.u64(endian) else first
        val version = reader.u16(endian)
        if (version != 5) throw CursorException("expected DWARF 5 rnglists version")
        val addressSize = reader.u8()
        val segmentSize = reader.u8()
        val offsetEntryCount = reader.u32(endian)
        if (offsetEntryCount > 1_000_000) throw CursorException("too many rnglist offsets")
        val offsets = (0 until offsetEntryCount.toInt()).map { reader.u32(endian) }
        val entriesOffset = reader.pos.toLong()
        if (entriesOffset > bytes.size || headerOffset + unitLength > bytes.size) throw CursorException("rnglists table exceeds section")
        return V5Table(entriesOffset, offsets)
    }

    fun parseV5(bytes: ByteArray, headerOffset: Long, listOffset: Long, lowPc: Long, addressSize: Int, segmentSize: Int, endian: Int, addresses: Map<Long, Long> = emptyMap()): List<RangeEdge> {
        val table = parseV5Header(bytes, headerOffset, endian)
        val target = if (listOffset < table.offsets.size) headerOffset + table.entriesOffset + table.offsets[listOffset.toInt()] else headerOffset + table.entriesOffset + listOffset
        if (target < 0 || target >= bytes.size) throw CursorException("range list entry out of bounds", target)
        val reader = ByteReader(bytes)
        reader.pos = target.toInt()
        var base = lowPc
        var ordinal = 0
        val result = mutableListOf<RangeEdge>()
        while (true) {
            when (val op = reader.u8()) {
                DW_RLE_end_of_list -> break
                DW_RLE_base_addressx -> base = addresses[reader.uleb()] ?: throw CursorException("missing indexed base address")
                DW_RLE_startx_endx -> {
                    val s = addresses[reader.uleb()] ?: throw CursorException("missing indexed start address")
                    val e = addresses[reader.uleb()] ?: throw CursorException("missing indexed end address")
                    result += RangeEdge(s, e, 0, "rnglists", ordinal++)
                }
                DW_RLE_startx_length -> {
                    val s = addresses[reader.uleb()] ?: throw CursorException("missing indexed start address")
                    val len = reader.uleb()
                    result += RangeEdge(s, s + len, 0, "rnglists", ordinal++)
                }
                DW_RLE_offset_pair -> {
                    val s = readAddress(reader, addressSize, endian, segmentSize)
                    val e = readAddress(reader, addressSize, endian, segmentSize)
                    result += RangeEdge(base + s.address, base + e.address, s.segment, "rnglists", ordinal++)
                }
                DW_RLE_base_address -> base = readAddress(reader, addressSize, endian, segmentSize).address
                DW_RLE_start_end -> {
                    val s = readAddress(reader, addressSize, endian, segmentSize)
                    val e = readAddress(reader, addressSize, endian, segmentSize)
                    result += RangeEdge(s.address, e.address, s.segment, "rnglists", ordinal++)
                }
                DW_RLE_start_length -> {
                    val s = readAddress(reader, addressSize, endian, segmentSize)
                    val len = reader.uleb()
                    result += RangeEdge(s.address, s.address + len, s.segment, "rnglists", ordinal++)
                }
                else -> throw CursorException("unsupported rnglist entry $op", reader.pos - 1L)
            }
        }
        return result
    }

    private data class AddressPart(val address: Long, val segment: Int)

    private fun readAddress(reader: ByteReader, addressSize: Int, endian: Int, segmentSize: Int): AddressPart {
        val segment = if (segmentSize > 0) reader.uint(segmentSize, endian).toInt() else 0
        return AddressPart(reader.uint(addressSize, endian), segment)
    }
}
