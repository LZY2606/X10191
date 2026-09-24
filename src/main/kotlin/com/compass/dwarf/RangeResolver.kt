package com.compass.dwarf

class RangeResolver(
    private val sections: Map<String, ByteArray>,
    private val ctx: UnitContext,
    private val dies: List<DieNode>,
    private val littleEndian: Boolean
) {
    private val maxRelocationDepth = 8
    private val maxReferences = 200
    private val seenReferences = mutableSetOf<Long>()

    fun resolve(): List<DwarfRange> = dies.filter {
        it.tag == DwarfConst.DW_TAG_SUBPROGRAM || it.tag == DwarfConst.DW_TAG_INLINED_SUBROUTINE
    }.flatMap { die -> dieRanges(die, inlineDepth(die)) }

    private fun inlineDepth(die: DieNode): Int {
        var current = die
        var depth = 0
        repeat(maxRelocationDepth) {
            val parentOffset = current.parentOffset ?: return depth
            current = dies.firstOrNull { it.offset == parentOffset } ?: return depth
            if (current.tag == DwarfConst.DW_TAG_INLINED_SUBROUTINE) depth++
        }
        return depth
    }

    private fun dieRanges(die: DieNode, depth: Int): List<DwarfRange> {
        val low = die.address(DwarfConst.DW_AT_LOW_PC)
        val highAttr = die.attr(DwarfConst.DW_AT_HIGH_PC)
        if (low != null && highAttr != null) {
            val high = when (val value = highAttr.value) {
                is AttrValue.AddressValue -> value.value
                is AttrValue.NumberValue -> low + value.value
                else -> null
            }
            if (high != null) return listOf(range(die, low, high, depth, "low_pc/high_pc"))
        }
        if (low != null && highAttr == null) {
            return listOf(range(die, low, low, depth, "low_pc singleton"))
        }
        val ranges = die.number(DwarfConst.DW_AT_RANGES)
        if (ranges != null) return listRanges(ranges, die, depth)
        val relocated = relocate(die) ?: return emptyList()
        return dieRanges(relocated.die, depth)
    }

    private fun relocate(die: DieNode): RelocatedDie? {
        var current = die
        var hops = 0
        while (hops < maxRelocationDepth) {
            val target = current.reference(DwarfConst.DW_AT_ABSTRACT_ORIGIN)
                ?: current.reference(DwarfConst.DW_AT_SPECIFICATION)
                ?: return if (hops == 0) null else RelocatedDie(current)
            if (!seenReferences.add(target)) return if (hops == 0) null else RelocatedDie(current)
            if (seenReferences.size > maxReferences) throw DwarfParseException("Reference jump limit reached")
            current = dies.firstOrNull { it.offset == target } ?: return if (hops == 0) null else RelocatedDie(current)
            hops++
        }
        return RelocatedDie(current)
    }

    private data class RelocatedDie(val die: DieNode)

    private fun listRanges(offset: Long, die: DieNode, depth: Int): List<DwarfRange> =
        if (ctx.version >= 5) dwarf5Ranges(offset, die, depth) else dwarf4Ranges(offset, die, depth)

    private fun dwarf4Ranges(offset: Long, die: DieNode, depth: Int): List<DwarfRange> {
        val data = sections[".debug_ranges"] ?: return emptyList()
        val cursor = BinaryCursor(data, littleEndian = littleEndian)
        if (offset !in 0..cursor.size.toLong()) return emptyList()
        cursor.localSeek(offset.toInt())
        val out = mutableListOf<DwarfRange>()
        var base = rootLowPc() ?: 0L
        while (true) {
            val start = readAddr(cursor); val end = readAddr(cursor)
            if (start == 0L && end == 0L) break
            if (isMaxAddress(start)) base = end else if (end >= start) out += range(die, base + start, base + end, depth, "debug_ranges")
        }
        return out
    }

    private fun dwarf5Ranges(indexOrOffset: Long, die: DieNode, depth: Int): List<DwarfRange> {
        val data = sections[".debug_rnglists"] ?: return emptyList()
        val raw = BinaryCursor(data, littleEndian = littleEndian)
        if (indexOrOffset !in 0..raw.size.toLong()) return emptyList()
        raw.localSeek(indexOrOffset.toInt())
        val out = mutableListOf<DwarfRange>()
        var base = rootLowPc() ?: 0L ?: 0L
        repeat(100_000) {
            if (raw.remaining() == 0) return out
            when (val kind = raw.u8()) {
                0x00 -> return out
                0x01 -> base = resolveAddress(raw.uleb())
                0x02 -> { val s = resolveAddress(raw.uleb()); val e = resolveAddress(raw.uleb()); if (e >= s) out += range(die, s, e, depth, "rnglists") }
                0x03 -> { val s = resolveAddress(raw.uleb()); val n = raw.uleb(); if (n >= 0) out += range(die, s, s + n, depth, "rnglists") }
                0x04 -> { val s = raw.uleb(); val e = raw.uleb(); if (e >= s) out += range(die, base + s, base + e, depth, "rnglists offset") }
                0x05 -> { val s = raw.uleb(); val n = raw.uleb(); out += range(die, base + s, base + s + n, depth, "rnglists offset") }
                0x06 -> { val s = readAddr(raw); val e = readAddr(raw); if (e >= s) out += range(die, s, e, depth, "rnglists address") }
                0x07 -> { val s = readAddr(raw); val n = raw.uleb(); out += range(die, s, s + n, depth, "rnglists address") }
                else -> throw DwarfParseException("Unknown rnglists entry kind $kind")
            }
        }
        return out
    }

    private fun resolveAddress(index: Long): Long {
        val addrData = sections[".debug_addr"] ?: throw DwarfParseException("Missing .debug_addr")
        val cursor = BinaryCursor(addrData, littleEndian = littleEndian)
        val baseAttr = dies.firstOrNull()?.number(DwarfConst.DW_AT_ADDR_BASE) ?: 0L
        cursor.localSeek(baseAttr.toInt())
        val start = cursor.absolutePosition()
        val init = cursor.u32()
        val dwarf64 = init == 0xffffffffL
        if (!dwarf64) cursor.localSeek(start.toInt())
        val length = if (dwarf64) cursor.u64() else cursor.u32()
        val version = cursor.u16()
        if (version != 5) throw DwarfParseException("Unsupported .debug_addr version")
        val addressSize = cursor.u8()
        cursor.u8()
        cursor.localSeek((start + length + (if (dwarf64) 12 else 4)).toInt() + (index * addressSize).toInt())
        return readAddr(cursor, addressSize)
    }

    private fun readAddr(cursor: BinaryCursor, size: Int = ctx.addressSize): Long = when (size) {
        1 -> cursor.u8().toLong(); 2 -> cursor.u16().toLong(); 4 -> cursor.u32(); 8 -> cursor.u64()
        else -> throw DwarfParseException("Bad address size")
    }

    private fun isMaxAddress(value: Long): Boolean = when (ctx.addressSize) {
        1 -> value == 0xffL; 2 -> value == 0xffffL; 4 -> value == 0xffffffffL; 8 -> value == -1L
        else -> false
    }

    private fun rootLowPc(): Long? = dies.firstOrNull()?.address(DwarfConst.DW_AT_LOW_PC)
    private val resolvedNames = ResolvedNames(dies)
    private fun name(die: DieNode): String? = resolvedNames.name(die)
    private fun range(die: DieNode, start: Long, end: Long, depth: Int, source: String) =
        DwarfRange(start, end, segment = die.number(DwarfConst.DW_AT_SEGMENT) ?: 0, die.offset, die.tag, name(die), depth, start == end, source)
}

class ResolvedNames(private val dies: List<DieNode>) {
    private val cache = mutableMapOf<Long, String?>()
    fun name(die: DieNode?): String? {
        if (die == null) return null
        cache[die.offset]?.let { return it }
        var current: DieNode = die
        repeat(8) {
            val active = current
            active.text(DwarfConst.DW_AT_NAME)?.let { cache[die.offset] = it; return it }
            val target = active.reference(DwarfConst.DW_AT_ABSTRACT_ORIGIN) ?: active.reference(DwarfConst.DW_AT_SPECIFICATION) ?: return null
            current = dies.firstOrNull { it.offset == target } ?: return null
        }
        return null
    }
}
