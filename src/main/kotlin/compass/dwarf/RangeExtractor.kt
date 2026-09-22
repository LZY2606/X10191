package compass.dwarf

/**
 * Extracts the address ranges of a scope DIE:
 *  - DW_AT_low_pc + DW_AT_high_pc, where high_pc is either an absolute
 *    address (FORM_addr) or a constant length
 *  - DW_AT_ranges (v4 .debug_ranges) and DW_AT_rnglists / rnglistx (v5)
 *
 * Zero-length ranges are kept (they still describe exactly one address).
 */
object RangeExtractor {

    fun rangesFor(die: DieNode, unit: CompUnit, parsed: ParsedFile): List<AddressRange> {
        val lowAttr = die.attr(DW.AT_low_pc)?.value
        val highAttr = die.attr(DW.AT_high_pc)?.value
        val out = ArrayList<AddressRange>()

        if (lowAttr != null) {
            val low = (lowAttr as? FormValue.Address)?.value
                ?: (lowAttr as? FormValue.Number)?.value
                ?: (lowAttr as? FormValue.DeferredAddrIndex)?.let {
                    resolveAddrx(unit, parsed, it.index)
                }
            if (low != null) {
                if (highAttr != null) {
                    when (highAttr) {
                        is FormValue.Address -> out.add(AddressRange(low, highAttr.value))
                        is FormValue.Number -> out.add(AddressRange(low, low + highAttr.value))
                        else -> out.add(AddressRange(low, low))
                    }
                } else {
                    out.add(AddressRange(low, low)) // low_pc alone = zero-length symbol
                }
            }
        }

        die.attr(DW.AT_ranges)?.let { at ->
            val value = at.value
            val offset = when (value) {
                is FormValue.SectionOffset -> value.value
                is FormValue.Number -> value.value
                else -> null
            }
            if (offset != null) {
                val cuLow = (unit.root.attr(DW.AT_low_pc)?.value as? FormValue.Address)?.value ?: 0L
                val sec = parsed.sections.ranges
                    ?: throw DwarfParseException("DW_AT_ranges present but no .debug_ranges")
                out.addAll(RangesV4.readList(sec, offset, unit.addressSize, cuLow))
            }
        }

        die.attr(DW.AT_rnglists)?.let { at ->
            val value = at.value
            val listOffset = when (value) {
                is FormValue.SectionOffset -> value.value // rnglistx resolved already
                is FormValue.Number -> value.value
                else -> throw DwarfParseException("unsupported DW_AT_rnglists form")
            }
            val sec = parsed.sections.rnglists
                ?: throw DwarfParseException("DW_AT_rnglists present but no .debug_rnglists")
            val base = unit.rnglistsBase
            val hdr = RngLists.readHeaderAt(sec, base)
            out.addAll(RngLists.readList(sec, listOffset, hdr.offsetSize, hdr.segmentSize) { idx ->
                resolveAddrx(unit, parsed, idx)
                    ?: throw DwarfParseException("addrx $idx unresolved in skeleton")
            })
        }
        return out
    }

    @Suppress("UNUSED_PARAMETER")
    fun resolveAddrx(unit: CompUnit, parsed: ParsedFile, index: Long): Long? =
        parsed.sections.addr?.let { sec ->
            val at = (unit.addrBase + index * unit.addressSize).toInt()
            if (at + unit.addressSize > sec.size) return null
            sec.subReader(at, unit.addressSize).uword(unit.addressSize)
        }
}
