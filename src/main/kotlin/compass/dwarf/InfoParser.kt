package compass.dwarf

import compass.elf.ByteReader

/**
 * Parses .debug_info headers and DIE trees.
 *
 * Safety contract:
 *  - recursion into children is explicit (worklist) and DIE nesting depth is
 *    capped at [MAX_DIE_DEPTH].
 *  - reference / form skips never move the cursor beyond the unit boundary.
 *  - an unknown form is decoded as [RawValue.Unknown] only when its byte size
 *    is deterministically known; forms whose size cannot be derived (exprloc,
 *    block*, indirect-to-unknown) abort the whole CU so the cursor cannot
 *    desynchronize and fabricate later DIEs.
 */
class InfoParser(private val sections: DwarfSections, private val abbrevs: AbbrevTables) {

    companion object {
        const val MAX_DIE_DEPTH = 128
        const val MAX_CU_COUNT = 100_000
    }

    private val warnings = mutableListOf<String>()

    fun parse(): List<CompileUnit> {
        val info = sections.info
            ?: throw DwarfParseException(".debug_info section missing")
        val units = mutableListOf<CompileUnit>()
        val r = ByteReader(info, 0, ByteReader.Endian.LITTLE, 0)
        while (r.remaining > 0) {
            if (units.size >= MAX_CU_COUNT) throw DwarfParseException("too many compilation units")
            val unitStart = r.pos.toLong()
            val unitWarnings = mutableListOf<String>()
            val hdr = readUnitHeader(r, unitStart)
            val cu = try {
                parseUnit(hdr, unitWarnings)
            } catch (e: DwarfParseException) {
                // Corrupt unit: keep whatever position header says to resync at
                // the next unit boundary (headers are the anchor, not a cursor
                // reconstructed after bogus forms).
                unitWarnings += "unit parse failed and was isolated: ${e.message}"
                CompileUnit(hdr, null, emptyList(), emptyMap(), unitWarnings.toList(),
                    splitKindOf(hdr, null), null, -1L)
            }
            units += cu
            r.seek(hdr.unitEnd.toInt())
            if (r.pos == hdr.unitEnd.toInt() && r.remaining == 0) break
        }
        return units
    }

    private fun readUnitHeader(r: ByteReader, unitStart: Long): UnitHeader {
        val lengthField = r.u4()
        val is64: Boolean
        val length: Long
        when (lengthField) {
            0xffffffffL -> {
                is64 = true
                length = r.u8()
            }
            in 0..0xfffffff0L -> {
                is64 = false
                length = lengthField
            }
            else -> throw DwarfParseException("reserved 32-bit unit length $lengthField")
        }
        val unitEnd = unitStart + (if (is64) 12 else 4) + length
        if (unitEnd > sections.info!!.size) {
            throw DwarfParseException("unit at $unitStart runs past .debug_info")
        }
        val version = r.u2()
        if (version < 2 || version > 5) throw DwarfParseException("unsupported DWARF version $version")

        var unitType = DW.UT_compile
        var abbrevOff: Long
        var addressSize = 0
        var segmentSize = 0
        var dwoId: Long? = null
        var typeSig = 0L
        var typeOff = 0L
        if (version >= 5) {
            unitType = r.u1()
            addressSize = r.u1()
            abbrevOff = readOffset(r, is64)
            when (unitType) {
                DW.UT_skeleton, DW.UT_split_compile -> dwoId = r.u8()
                DW.UT_type, DW.UT_split_type -> {
                    typeSig = r.u8()
                    typeOff = readOffset(r, is64).toInt().toLong()
                }
                DW.UT_compile, DW.UT_partial -> {}
                else -> if (unitType in DW.UT_lo_user..DW.UT_hi_user) {
                    throw DwarfParseException("vendor unit type 0x${unitType.toString(16)} not supported")
                }
            }
        } else {
            abbrevOff = readOffset(r, is64)
            addressSize = r.u1()
            // DWARF2/3/4 carry no segment selector in the CU header; zero.
        }
        val firstDie = r.pos.toLong()
        return UnitHeader(
            index = 0, version = version, unitType = unitType, is64Bit = is64,
            unitStart = unitStart, unitLength = length, unitEnd = unitEnd,
            debugAbbrevOffset = abbrevOff, addressSize = addressSize,
            segmentSize = segmentSize, firstDie = firstDie,
            dwoId = dwoId, typeSignature = typeSig, typeOffset = typeOff.toLong(),
        ).copy(index = 0)
    }

    private fun readOffset(r: ByteReader, is64: Boolean): Long =
        if (is64) r.u8() else r.u4()

    private fun parseUnit(hdr: UnitHeader, unitWarnings: MutableList<String>): CompileUnit {
        val table = abbrevs.tableAt(hdr.debugAbbrevOffset)
        val r = ByteReader(sections.info!!, hdr.firstDie.toInt(),
            ByteReader.Endian.LITTLE, hdr.firstDie.toInt())
        val end = hdr.unitEnd.toInt()

        val dies = ArrayList<Die>()
        val byOffset = LinkedHashMap<Long, Die>()

        data class Frame(val die: Die, var remaining: Int)

        val stack = ArrayDeque<Frame>()
        var root: Die? = null
        var depth = 0

        fun boundary() = r.pos >= end

        while (!boundary()) {
            val code = r.uleb()
            if (code == 0L) {
                if (stack.isEmpty()) {
                    // trailing null padding: valid end of root
                    break
                }
                val f = stack.removeLast()
                depth--
                if (stack.isEmpty()) break // root closed; rest should be padding
                continue
            }
            val ab = table[code]
                ?: throw DwarfParseException("unknown abbrev code $code at offset ${r.pos} in unit ${hdr.unitStart}")
            val dieOffset = r.pos.toLong() - ulebSize(code)
            val attrs = LinkedHashMap<Int, RawValue>(ab.specs.size)
            for ((attr, form) in ab.specs) {
                val v = decodeForm(r, form, hdr, ab.implicitConsts[attr]) { msg ->
                    unitWarnings += msg
                }
                attrs[attr] = v
            }
            if (r.pos > end) throw DwarfParseException("DIE at $dieOffset read past unit boundary")
            val die = Die(dieOffset, ab.tag, code, hdr.index, attrs)
            dies += die
            byOffset[dieOffset] = die
            if (stack.isEmpty()) {
                root = die
            } else {
                val parent = stack.last().die
                die.parent = parent
                parent.children += die
            }
            if (ab.hasChildren) {
                depth++
                if (depth > MAX_DIE_DEPTH) throw DwarfParseException("DIE nesting exceeds $MAX_DIE_DEPTH")
                stack.addLast(Frame(die, -1))
            } else if (stack.isEmpty()) {
                // root with no children: null terminator still required
                val terminator = r.uleb()
                if (terminator != 0L) throw DwarfParseException("missing null terminator after root")
                break
            }
        }

        val rootDie = root
        val splitKind = splitKindOf(hdr, rootDie)
        val dwoName = rootDie?.let { dieDwoName(it) }
        val stmtList = rootDie?.attr(DW.AT_stmt_list)
        val lineTableOff = when (stmtList) {
            is RawValue.UInt -> stmtList.v
            else -> -1L
        }
        return CompileUnit(hdr.copy(index = 0), rootDie, dies, byOffset,
            unitWarnings.toList(), splitKind, dwoName, lineTableOff)
    }

    private fun ulebSize(v: Long): Int {
        var x = v
        var n = 0
        do { n++; x = x ushr 7 } while (x != 0L)
        return n
    }

    private fun splitKindOf(hdr: UnitHeader, root: Die?): String = when {
        hdr.version >= 5 && hdr.unitType == DW.UT_skeleton -> "skeleton"
        hdr.version >= 5 && (hdr.unitType == DW.UT_split_compile || hdr.unitType == DW.UT_split_type) -> "split"
        root?.hasAttr(DW.AT_GNU_dwo_name) == true -> "skeleton"
        else -> "full"
    }

    private fun dieDwoName(die: Die): String? {
        val a = die.attr(DW.AT_dwo_name) ?: die.attr(DW.AT_GNU_dwo_name) ?: return null
        return (a as? RawValue.StrInline)?.v
    }

    /**
     * Decode a single form value. [warn] collects non-fatal form issues.
     * Forms whose encoded size is not statically known abort the CU via
     * [DwarfParseException] rather than guessing where the next attribute is.
     */
    private fun decodeForm(
        r: ByteReader,
        form: Int,
        hdr: UnitHeader,
        implicit: Long?,
        warn: (String) -> Unit,
    ): RawValue {
        val offSize = if (hdr.is64Bit) 8 else 4
        return when (form) {
            DW.FORM_addr -> RawValue.Addr(readAddr(r, hdr.addressSize))
            DW.FORM_data1 -> RawValue.UInt(r.u1().toLong())
            DW.FORM_data2 -> RawValue.UInt(r.u2().toLong())
            DW.FORM_data4 -> RawValue.UInt(r.u4())
            DW.FORM_data8 -> RawValue.UInt(r.u8())
            DW.FORM_sdata -> RawValue.SInt(r.sleb())
            DW.FORM_udata -> RawValue.UInt(r.uleb())
            DW.FORM_flag -> RawValue.UInt(r.u1().toLong())
            DW.FORM_flag_present -> RawValue.FlagPresent
            DW.FORM_string -> RawValue.StrInline(r.cstring())
            DW.FORM_strp -> when (hdr.version) {
                // .debug_str offset, size depends on 32/64-bit DWARF
                else -> RawValue.StrPtr(StrSection.DEBUG_STR, readFixed(r, offSize))
            }
            DW.FORM_line_strp -> RawValue.StrPtr(StrSection.DEBUG_LINE_STR, readFixed(r, offSize))
            DW.FORM_sec_offset -> RawValue.UInt(readFixed(r, offSize))
            DW.FORM_ref1 -> RawValue.Ref(r.u1().toLong(), RefKind.UNIT_REL)
            DW.FORM_ref2 -> RawValue.Ref(r.u2().toLong(), RefKind.UNIT_REL)
            DW.FORM_ref4 -> RawValue.Ref(r.u4(), RefKind.UNIT_REL)
            DW.FORM_ref8 -> RawValue.Ref(r.u8(), RefKind.UNIT_REL)
            DW.FORM_ref_udata -> RawValue.Ref(r.uleb(), RefKind.UNIT_REL)
            DW.FORM_ref_addr -> RawValue.Ref(readFixed(r, offSize), RefKind.REF_ADDR)
            DW.FORM_ref_sig8 -> RawValue.Ref(r.u8(), RefKind.REF_ADDR)
            DW.FORM_block1 -> { val n = r.u1(); RawValue.Bytes(r.bytes(n)) }
            DW.FORM_block2 -> { val n = r.u2(); RawValue.Bytes(r.bytes(n)) }
            DW.FORM_block4 -> { val n = r.u4().toInt(); RawValue.Bytes(r.bytes(n)) }
            DW.FORM_block -> { val n = r.ulebInt(); RawValue.Bytes(r.bytes(n)) }
            DW.FORM_exprloc -> { val n = r.ulebInt(); RawValue.Bytes(r.bytes(n)) }
            DW.FORM_data16 -> RawValue.Bytes(r.bytes(16))
            DW.FORM_strx -> RawValue.StrIndex(r.uleb(), -1L)
            DW.FORM_strx1 -> RawValue.StrIndex(r.u1().toLong(), -1L)
            DW.FORM_strx2 -> RawValue.StrIndex(r.u2().toLong(), -1L)
            DW.FORM_strx3 -> RawValue.StrIndex(r.u4().toInt().toLong(), -1L).also { r.bytes(0) }
            DW.FORM_strx4 -> RawValue.StrIndex(r.u4(), -1L)
            DW.FORM_addrx -> RawValue.AddrIndex(r.uleb())
            DW.FORM_addrx1 -> RawValue.AddrIndex(r.u1().toLong())
            DW.FORM_addrx2 -> RawValue.AddrIndex(r.u2().toLong())
            DW.FORM_addrx3 -> {
                val v = r.u4().toInt() and 0xffffff
                RawValue.AddrIndex(v.toLong())
            }
            DW.FORM_addrx4 -> RawValue.AddrIndex(r.u4())
            DW.FORM_rnglistx -> RawValue.RngListIndex(r.uleb())
            DW.FORM_implicit_const -> RawValue.SInt(immediate ?: 0L)
            DW.FORM_indirect -> {
                val actual = r.ulebInt()
                if (actual == form) throw DwarfParseException("FORM_indirect points at itself")
                decodeForm(r, actual, hdr, implicit, warn)
            }
            else -> {
                // Unknown form: we cannot know how many bytes it occupies.
                // Abort this CU so parsing cannot continue on a shifted cursor.
                throw DwarfParseException(
                    "unknown DWARF form 0x${form.toString(16)} at offset ${r.pos - 1}; unit parsing aborted to prevent cursor desync"
                )
            }
        }
    }

    private fun readFixed(r: ByteReader, n: Int): Long = when (n) {
        1 -> r.u1().toLong()
        2 -> r.u2().toLong()
        4 -> r.u4()
        8 -> r.u8()
        else -> throw DwarfParseException("bad fixed width $n")
    }

    private fun readAddr(r: ByteReader, addressSize: Int): Long = when (addressSize) {
        1 -> r.u1().toLong()
        2 -> r.u2().toLong()
        4 -> r.u4()
        8 -> r.u8()
        else -> throw DwarfParseException("bad address_size $addressSize")
    }
}
