package compass.dwarf

import compass.elf.ElfFile

/**
 * Resolves DW_AT_ranges and DW_AT_low_pc/high_pc into concrete [AddressRange]s.
 * Zero-length ranges are retained (they represent legitimate empty functions and
 * can become selectable when the runtime address falls exactly on them).
 */
class RangeListParser(
    private val elf: ElfFile,
    private val addrTable: AddrTable,
) {
    private val ranges4 = elf.reader(".debug_ranges")
    private val rnglists5 = elf.reader(".debug_rnglists")
        ?: elf.reader(".debug_rnglists.dwo")

    /**
     * @param cuLowPc resolved CU-level low PC / addrx base (may be null)
     * @param rnglistOffset raw DW_AT_ranges value (section offset or rnglistx index)
     */
    fun resolveRanges(
        rnglistOffset: AttrValue,
        cuLowPc: Long?,
        cu: CompileUnit,
        dieOffset: Long,
        warnings: MutableList<String>,
    ): List<AddressRange> {
        return when (rnglistOffset) {
            is AttrValue.SecOffset -> {
                val off = rnglistOffset.v
                if (cu.version >= 5) resolveV5(off, null, cu, dieOffset, cuLowPc, warnings)
                else resolveV4(off, cu, dieOffset, cuLowPc, warnings)
            }
            is AttrValue.Indexed -> {
                if (rnglistOffset.kind != AttrValue.IndexKind.RNGLISTX) return emptyList()
                resolveV5(cu.rnglistsBase, rnglistOffset.idx, cu, dieOffset, cuLowPc, warnings)
            }
            else -> emptyList()
        }
    }

    fun resolveLowHigh(lowPc: Long, highAttr: DAttribute, cu: CompileUnit, dieOffset: Long)
            : AddressRange? {
        return when (val hv = highAttr.value) {
            is AttrValue.Addr -> AddressRange(lowPc, hv.v, 0, dieOffset, cu.id)
            is AttrValue.Num -> AddressRange(lowPc, lowPc + hv.v, 0, dieOffset, cu.id)
            is AttrValue.Indexed -> {
                val base = resolveAddrx(hv, cu) ?: return null
                AddressRange(base, base, 0, dieOffset, cu.id)
            }
            else -> null
        }
    }

    fun resolveAddrx(v: AttrValue.Indexed, cu: CompileUnit): Long? {
        if (v.kind != AttrValue.IndexKind.ADDRX) return null
        return addrTable.resolve(cu.addrBase, v.idx, cu.addressSize, cu.version)
    }

    private fun resolveV4(
        offset: Long, cu: CompileUnit, dieOffset: Long, cuLowPc: Long?,
        warnings: MutableList<String>
    ): List<AddressRange> {
        val sec = ranges4 ?: return emptyList()
        val r = sec.subReader(sec.base, sec.limit)
        try {
            r.seek(offset)
        } catch (e: BoundsException) {
            warnings.add(".debug_ranges offset 0x${offset.toString(16)} out of bounds")
            return emptyList()
        }
        r.addressSize = cu.addressSize
        val maxAddr = if (cu.addressSize == 4) 0xffffffffL else -1L
        var base = cuLowPc ?: 0L
        val out = ArrayList<AddressRange>()
        var guard = 0
        while (true) {
            if (++guard > 1_000_000) {
                warnings.add(".debug_ranges list at 0x${offset.toString(16)} too long")
                break
            }
            val a = r.address()
            val b = r.address()
            if (a == 0L && b == 0L) break
            if (a == maxAddr) {
                base = b
                continue
            }
            out.add(AddressRange(a + base, b + base, 0, dieOffset, cu.id))
        }
        return out
    }

    private fun resolveV5(
        tableHeaderOffset: Long, rnglistx: Long?, cu: CompileUnit, dieOffset: Long,
        cuLowPc: Long?, warnings: MutableList<String>
    ): List<AddressRange> {
        val sec = rnglists5 ?: return emptyList()
        val r = sec.subReader(sec.base, sec.limit)
        val firstEntry: Long
        val addressSize: Int
        try {
            r.seek(tableHeaderOffset)
            val (len, d64) = r.initialLength()
            val endOff = r.sectionOffset() + len
            if (endOff > r.limit - r.base) {
                warnings.add(".debug_rnglists table at 0x${tableHeaderOffset.toString(16)} overruns section")
                return emptyList()
            }
            val version = r.u16()
            addressSize = r.u8()
            r.u8() // segment_selector_size
            val offsetEntryCount = r.u32().toInt()
            val offsetsStart = r.sectionOffset()
            val entryStart = offsetsStart + (if (d64) 8L else 4L) * offsetEntryCount
            r.addressSize = addressSize
            firstEntry = if (rnglistx != null) {
                r.seek(offsetsStart + rnglistx * (if (d64) 8 else 4))
                val rel = if (d64) r.u64() else r.u32()
                tableHeaderOffset + rel
            } else entryStart
            r.seek(firstEntry)
        } catch (e: BoundsException) {
            warnings.add(".debug_rnglists table at 0x${tableHeaderOffset.toString(16)} truncated")
            return emptyList()
        }

        var base = cuLowPc ?: 0L
        val out = ArrayList<AddressRange>()
        var guard = 0
        while (true) {
            if (++guard > 1_000_000) {
                warnings.add(".debug_rnglists entry stream too long")
                break
            }
            val op = r.u8()
            when (op) {
                RangeOp.RLE_end_of_list -> break
                RangeOp.RLE_base_addressx -> {
                    val idx = r.uleb()
                    base = addrTable.resolve(cu.addrBase, idx, addressSize, 5)
                        ?: run { warnings.add("bad base_addressx $idx"); return out }
                }
                RangeOp.RLE_startx_endx -> {
                    val s = addrTable.resolve(cu.addrBase, r.uleb(), addressSize, 5)
                    val e = addrTable.resolve(cu.addrBase, r.uleb(), addressSize, 5)
                    if (s != null && e != null) out.add(AddressRange(s, e, 0, dieOffset, cu.id))
                }
                RangeOp.RLE_startx_length -> {
                    val s = addrTable.resolve(cu.addrBase, r.uleb(), addressSize, 5)
                    val len = r.uleb()
                    if (s != null) out.add(AddressRange(s, s + len, 0, dieOffset, cu.id))
                }
                RangeOp.RLE_offset_pair -> {
                    val s = r.uleb(); val e = r.uleb()
                    out.add(AddressRange(base + s, base + e, 0, dieOffset, cu.id))
                }
                RangeOp.RLE_base_address -> {
                    base = r.address()
                }
                RangeOp.RLE_start_end -> {
                    out.add(AddressRange(r.address(), r.address(), 0, dieOffset, cu.id))
                }
                RangeOp.RLE_start_length -> {
                    val s = r.address(); val len = r.uleb()
                    out.add(AddressRange(s, s + len, 0, dieOffset, cu.id))
                }
                else -> {
                    warnings.add("unknown rnglists opcode 0x${op.toString(16)}; stopping this list to avoid drift")
                    break
                }
            }
        }
        return out
    }
}
