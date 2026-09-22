package compass.dwarf

import compass.elf.ByteReader

/**
 * Section access + shared caches while parsing one ELF file.
 * Indices that may live in the skeleton file (split DWARF) produce deferred
 * values resolved by the linker pass once skeleton<->dwo pairs are known.
 */
class ParseContext(
    val sections: DwarfSections,
    val abbrevCache: HashMap<Long, AbbrevTable> = HashMap()
) {
    val info: ByteReader? = sections.info

    fun abbrevTable(offset: Long): AbbrevTable = abbrevCache.getOrPut(offset) {
        val sec = sections.abbrev ?: throw DwarfParseException("missing .debug_abbrev")
        AbbrevTable.parse(sec, offset)
    }

    fun readStr(offset: Int): String {
        val sec = sections.str ?: throw DwarfParseException("DW_FORM_strp but no .debug_str")
        return sec.stringAt(offset)
    }

    fun readLineStr(offset: Int): String {
        val sec = sections.lineStr
            ?: throw DwarfParseException("DW_FORM_line_strp but no .debug_line_str")
        return sec.stringAt(offset)
    }

    /** Resolve a strx against this file's .debug_str_offsets, or defer. */
    fun readStrx(state: ParseState, index: Long): FormValue {
        val sec = sections.strOffsets ?: return FormValue.DeferredStrIndex(index)
        val root = state.diesByOffset[state.unitStart + state.headerLength]
        val base = root?.num(DW.AT_str_offsets_base) ?: 0L
        val entrySize = state.addressSize.coerceAtLeast(4)
        val at = (base + index * entrySize).toInt()
        if (at + entrySize > sec.size)
            throw DwarfParseException("strx index $index out of .debug_str_offsets")
        val rr = sec.subReader(at, entrySize)
        val strOff = if (entrySize == 4) rr.u4().toLong() and 0xffffffffL else rr.u8()
        return FormValue.Text(readStr(strOff.toInt()))
    }

    /** Resolve an addrx against this file's .debug_addr, or defer to the skeleton. */
    fun readAddrx(state: ParseState, index: Long): FormValue {
        val sec = sections.addr ?: return FormValue.DeferredAddrIndex(index)
        val root = state.diesByOffset[state.unitStart + state.headerLength]
        val base = root?.num(DW.AT_addr_base) ?: root?.num(DW.AT_GNU_addr_base) ?: 0L
        val at = (base + index * state.addressSize).toInt()
        if (at + state.addressSize > sec.size)
            throw DwarfParseException("addrx index $index out of .debug_addr")
        val rr = sec.subReader(at, state.addressSize)
        return FormValue.Address(rr.uword(state.addressSize))
    }

    /** Resolve a rnglistx index to an offset inside this file's .debug_rnglists. */
    fun resolveRnglistx(state: ParseState, index: Long): Long {
        val sec = sections.rnglists
            ?: throw DwarfParseException("DW_FORM_rnglistx but no .debug_rnglists")
        val root = state.diesByOffset[state.unitStart + state.headerLength]
        val base = root?.num(DW.AT_rnglists_base) ?: 0L
        val hdr = RngLists.readHeaderAt(sec, base)
        val at = (hdr.offsetArrayBase + index * hdr.offsetSize).toInt()
        if (at + hdr.offsetSize > sec.size)
            throw DwarfParseException("rnglistx index $index out of offset array")
        val rr = sec.subReader(at, hdr.offsetSize)
        val rel = if (hdr.offsetSize == 4) rr.u4().toLong() and 0xffffffffL else rr.u8()
        return base + rel
    }
}
