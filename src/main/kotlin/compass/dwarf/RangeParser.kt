package compass.dwarf

import compass.dwarf.DW_AT as A

/**
 * Resolves address ranges for every DIE from low_pc/high_pc, .debug_ranges (v<=4)
 * and .debug_rnglists (v5). Zero-length ranges (high_pc == 0 or zero-length rnglist
 * entries) are preserved with a distinct flag rather than dropped.
 */
class RangeResolver(
    private val bundle: SectionBundle,
    private val diagnostics: MutableList<ParseDiagnostic>
) {
    fun resolve(cus: List<CompUnit>) {
        for (cu in cus) resolveCu(cu)
    }

    private fun resolveCu(cu: CompUnit) {
        val root = cu.root ?: return
        var cuBase = 0L
        (root.attr(A.LOW_PC)?.value as? AttrValue.Addr)?.let { cuBase = it.v }
        val rnglistHeaderBase = if (cu.version >= 5)
            (root.num(A.RNGLISTS) as Long?) else null

        val all = ArrayDeque<DieNode>().apply { add(root) }
        var guard = 0
        while (all.isNotEmpty()) {
            if (++guard > InfoParser.MAX_DIES_PER_CU) break
            val d = all.removeFirst()
            try {
                resolveDie(d, cu, cuBase, rnglistHeaderBase)
            } catch (e: DwarfBoundsException) {
                diagnostics.add(ParseDiagnostic("WARNING", "RANGE_OOB",
                    "DIE @${d.offset} 范围解析越界: ${e.message}", ".debug_ranges", null))
            }
            all.addAll(d.children)
        }
    }

    private fun resolveDie(d: DieNode, cu: CompUnit, cuBase: Long, rnglistsHeader: Long?) {
        val lowPc = (d.attr(A.LOW_PC)?.value as? AttrValue.Addr)?.v
        val highAttr = d.attr(A.HIGH_PC)?.value
        val rangesAttr = d.attr(A.RANGES)
        val gnuBase = d.num(A.GNU_RANGES_BASE)
        if (lowPc != null && highAttr != null) {
            when (highAttr) {
                is AttrValue.Addr -> {
                    val hl = highAttr.v
                    d.ranges.add(AddressRange(lowPc, hl, hl == lowPc, RangeSource.LOW_HIGH_PC, d.offset))
                }
                is AttrValue.Number -> {
                    val size = highAttr.v
                    d.ranges.add(AddressRange(lowPc, lowPc + size, size == 0L, RangeSource.LOW_HIGH_PC, d.offset))
                }
                else -> {}
            }
        } else if (lowPc != null && highAttr == null && d.tag == DW_TAG.SUBPROGRAM) {
            // low_pc only: zero-length symbol marker
            d.ranges.add(AddressRange(lowPc, lowPc, true, RangeSource.ZERO_PC, d.offset))
        }

        if (rangesAttr != null) {
            when (val v = rangesAttr.value) {
                is AttrValue.SecOffset -> {
                    val more = if (cu.version >= 5)
                        readRnglists(cu, v.v, gnuBase ?: cuBase)
                    else
                        readDebugRanges(cu, v.v, gnuBase ?: cuBase)
                    d.ranges.addAll(more)
                }
                else -> {}
            }
        }
    }

    // ---- DWARF <=4 .debug_ranges -------------------------------------------------
    private fun readDebugRanges(cu: CompUnit, offset: Long, baseIn: Long): List<AddressRange> {
        if (bundle.elf.section(".debug_ranges") == null && bundle.split?.section(".debug_ranges") == null)
            return emptyList()
        val bytes = bundle.bytesFromAny(".debug_ranges")!!.first
        val le = if (bundle.elf.section(".debug_ranges") != null) bundle.le
        else bundle.split!!.littleEndian
        val r = SectionReader(bytes, ".debug_ranges", le)
        if (offset < 0 || offset >= bytes.size) {
            diagnostics.add(ParseDiagnostic("WARNING", "RANGE_OFFSET_OOB",
                "DW_AT_ranges 偏移 0x${offset.toString(16)} 越界", ".debug_ranges", offset))
            return emptyList()
        }
        r.seek(offset.toInt())
        val out = mutableListOf<AddressRange>()
        var base = baseIn
        var hops = 0
        while (r.pos + 2 * cu.addressSize <= r.size) {
            if (++hops > MAX_RANGE_ENTRIES) {
                diagnostics.add(ParseDiagnostic("WARNING", "RANGE_TOO_LONG",
                    "range list @$offset 条目超过 $MAX_RANGE_ENTRIES", ".debug_ranges", offset))
                break
            }
            val start = r.u(cu.addressSize)
            val end = r.u(cu.addressSize)
            val sentinel = if (cu.addressSize == 4) 0xffffffffL else -1L
            if (start == 0L && end == 0L) break
            if (start == sentinel) { base = end; continue }
            val s = base + start
            val e = base + end
            out.add(AddressRange(s, e, s == e, RangeSource.DEBUG_RANGES, offset))
        }
        return out
    }

    // ---- DWARF 5 .debug_rnglists ------------------------------------------------
    private fun readRnglists(cu: CompUnit, entryOffset: Long, baseIn: Long): List<AddressRange> {
        val pair = bundle.bytesFromAny(".debug_rnglists") ?: return emptyList()
        val (bytes, fromSplit) = pair
        val le = if (fromSplit) bundle.split!!.littleEndian else bundle.le
        val r = SectionReader(bytes, ".debug_rnglists", le)
        // Find the list whose header contains the given offset: entryOffset is relative
        // to the start of the offsets array referenced by DW_AT_rnglists_base or the CU.
        val targetOffset = locateRnglist(r, cu, entryOffset) ?: return emptyList()
        if (targetOffset < 0 || targetOffset >= bytes.size) {
            diagnostics.add(ParseDiagnostic("WARNING", "RNGLIST_OFFSET_OOB",
                "rnglist 偏移 0x${targetOffset.toString(16)} 越界", ".debug_rnglists", targetOffset))
            return emptyList()
        }
        r.seek(targetOffset.toInt())
        val out = mutableListOf<AddressRange>()
        var base = baseIn
        var hops = 0
        while (r.pos < r.size) {
            if (++hops > MAX_RANGE_ENTRIES) break
            val op = r.u8()
            when (op) {
                DW_RLE.END_OF_LIST -> break
                DW_RLE.BASE_ADDRESSX -> {
                    val idx = r.uleb()
                    base = AddrTables.resolve(bundle, cu.root?.num(A.ADDR_BASE) ?: 0L, idx, cu.addressSize)
                }
                DW_RLE.STARTX_ENDX -> {
                    val s = AddrTables.resolve(bundle, cu.root?.num(A.ADDR_BASE) ?: 0L, r.uleb(), cu.addressSize)
                    val e = AddrTables.resolve(bundle, cu.root?.num(A.ADDR_BASE) ?: 0L, r.uleb(), cu.addressSize)
                    out.add(AddressRange(s, e, s == e, RangeSource.RANGLISTS, targetOffset))
                }
                DW_RLE.STARTX_LENGTH -> {
                    val s = AddrTables.resolve(bundle, cu.root?.num(A.ADDR_BASE) ?: 0L, r.uleb(), cu.addressSize)
                    val len = r.uleb()
                    out.add(AddressRange(s, s + len, len == 0L, RangeSource.RANGLISTS, targetOffset))
                }
                DW_RLE.OFFSET_PAIR -> {
                    val s = base + r.sleb(); val e = base + r.sleb()
                    out.add(AddressRange(s, e, s == e, RangeSource.RANGLISTS, targetOffset))
                }
                DW_RLE.BASE_ADDRESS -> { base = r.u(cu.addressSize) }
                DW_RLE.START_END -> {
                    val s = r.u(cu.addressSize); val e = r.u(cu.addressSize)
                    out.add(AddressRange(s, e, s == e, RangeSource.RANGLISTS, targetOffset))
                }
                DW_RLE.START_LENGTH -> {
                    val s = r.u(cu.addressSize); val len = r.uleb()
                    out.add(AddressRange(s, s + len, len == 0L, RangeSource.RANGLISTS, targetOffset))
                }
                else -> {
                    diagnostics.add(ParseDiagnostic("WARNING", "UNKNOWN_RLE",
                        "未知 rnglist opcode 0x${op.toString(16)} @${r.pos - 1}，停止该 list", ".debug_rnglists", (r.pos - 1).toLong()))
                    break
                }
            }
        }
        return out
    }

    /**
     * In DWARF 5, DW_AT_ranges for rnglists is an offset from the beginning of the
     * .debug_rnglists contribution for the CU (or from section start when DW_AT_rnglists_base absent).
     * We locate the header for this CU's contribution and translate to an absolute section offset.
     */
    private fun locateRnglist(r: SectionReader, cu: CompUnit, entryOffset: Long): Long? {
        val baseAttr = cu.root?.num(A.RNGLISTS) // offset of this CU's contribution header
        if (baseAttr == null || baseAttr == 0L) return entryOffset
        val saved = r.pos
        try {
            r.seek(baseAttr.toInt())
            val il = r.readInitialLength()
            r.u16() // version
            r.u8()  // address_size
            r.u8()  // segment_selector_size
            val offsetEntryCount = r.u32().toInt()
            val offsetTableEnd = r.pos + offsetEntryCount * il.offsetSize
            // entryOffset is relative to the first byte of the offsets table
            val target = r.pos + entryOffset
            if (target in (r.pos until offsetTableEnd)) {
                r.seek(target.toInt())
                val intoList = r.u(il.offsetSize)
                return baseAttr + intoList
            }
            // entryOffset is already relative to the byte after header
            return baseAttr + (il.headerEndPos - baseAttr.toInt()) + entryOffset
        } catch (e: Exception) {
            return null
        } finally {
            r.seek(saved)
        }
    }

    companion object {
        const val MAX_RANGE_ENTRIES = 1_000_000
    }
}
