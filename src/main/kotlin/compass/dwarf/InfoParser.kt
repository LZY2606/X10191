package compass.dwarf

import compass.model.DwarfBundle

class InfoParser(private val bundle: DwarfBundle) {

    fun parseAll(): List<CompileUnit> {
        val info = bundle.section(".debug_info") ?: return emptyList()
        val c = DwarfCursor(info)
        val units = ArrayList<CompileUnit>()
        while (!c.atEnd()) {
            val start = c.pos.toLong()
            val unit = try {
                parseUnit(c, start)
            } catch (e: DwarfParseException) {
                // A corrupt unit cannot be safely skipped: record a tombstone
                // and stop so no later bytes are misread as DIEs.
                units += CompileUnit(
                    offset = start, version = 0, unitType = 0, is64 = false,
                    abbrevOffset = -1, addressSize = 8, stmtList = null,
                    root = RawDie(start, 0, emptyList(), emptyList(), 0, 0),
                    allDies = emptyList(), dwoName = null, dwoId = null,
                    fatal = e.message ?: "parse error", unitEnd = start,
                )
                break
            }
            units += unit
            c.seek(unit.unitEnd)
        }
        return units
    }

    private fun parseUnit(c: DwarfCursor, start: Long): CompileUnit {
        val initial = readInitialLength(c)
        val is64 = initial.is64
        val unitEnd = if (initial.length == 0L) start + 4 else start + (if (is64) 12 else 4) + initial.length
        val version = c.u16()
        if (version < 2 || version > 5) throw DwarfParseException("unsupported DWARF version $version at $start")
        var unitType = DwUt.COMPILE
        var addressSize = 8
        var abbrevOffset: Long
        if (version >= 5) {
            unitType = c.u8()
            addressSize = c.u8()
            abbrevOffset = if (is64) c.u64() else c.u32()
            if (unitType == DwUt.SKELETON) c.u64() // DWO id
            if (unitType == DwUt.SPLIT_COMPILE) c.u64()
            if (unitType == DwUt.TYPE || unitType == DwUt.SPLIT_TYPE) {
                c.u64(); c.u64()
            }
        } else {
            abbrevOffset = if (is64) c.u64() else c.u32()
            addressSize = c.u8()
        }
        if (addressSize !in 1..8) throw DwarfParseException("bad address_size $addressSize at $start")
        if (abbrevOffset < 0 || (bundle.section(".debug_abbrev")?.let { abbrevOffset > it.size } == true)) {
            throw DwarfParseException("debug_abbrev_offset out of bounds: $abbrevOffset")
        }
        val abbrevs = AbbrevParser.parse(bundle.section(".debug_abbrev"), abbrevOffset)
        val warnings = ArrayList<String>()

        val dieEnd = unitEnd
        var ordinalCounter = 0
        val root = parseDie(c, abbrevs, is64, addressSize, version, depth = 0, ordinal = { ordinalCounter++ }, dieEnd, warnings)
            ?: throw DwarfParseException("CU at $start has no root DIE")
        if (c.pos.toLong() > dieEnd) throw DwarfParseException("CU DIEs overrun unit at $start")

        val all = ArrayList<RawDie>()
        fun collect(d: RawDie) {
            all += d
            d.children.forEach(::collect)
        }
        collect(root)

        val stmtList = (root.attr(DwAt.STMT_LIST)?.value as? RawValue.Num)?.v
            ?: (root.attr(DwAt.STMT_LIST)?.value as? RawValue.RngListOffset)?.offset
        val dwoName = (root.attr(DwAt.DWO_NAME)?.value as? RawValue.Str)?.v
        val dwoId = when (val v = root.attr(DwAt.DWO_ID)?.value ?: root.attr(DwAt.GNU_DWO_ID)?.value) {
            is RawValue.Num -> v.v
            else -> null
        }

        return CompileUnit(
            offset = start, version = version, unitType = unitType, is64 = is64,
            abbrevOffset = abbrevOffset, addressSize = addressSize,
            stmtList = stmtList, root = root, allDies = all,
            dwoName = dwoName, dwoId = dwoId,
            unitEnd = dieEnd,
            warnings = warnings,
        )
    }

    private fun parseDie(
        c: DwarfCursor,
        abbrevs: AbbreviationTable,
        is64: Boolean,
        addressSize: Int,
        version: Int,
        depth: Int,
        ordinal: () -> Int,
        dieEnd: Long,
        warnings: MutableList<String>,
    ): RawDie? {
        if (c.pos.toLong() >= dieEnd) return null
        val offset = c.pos.toLong()
        val code = c.uleb()
        if (code == 0L) {
            // null DIE marks end of sibling list; signal by tag 0
            return RawDie(offset, 0, emptyList(), emptyList(), depth, ordinal())
        }
        val abbr = abbrevs.get(code)
            ?: throw DwarfParseException("unknown abbrev code $code at cu-die $offset")
        val attrs = ArrayList<RawAttr>(abbr.attrs.size)
        for (a in abbr.attrs) {
            val v = readAttrValue(c, a.form, is64, addressSize, version, warnings)
                ?: run {
                    // Unknown form: abort this CU rather than guess the cursor.
                    throw DwarfParseException("unknown/unsupported DWARF form 0x${a.form.toString(16)} at cu-die $offset attr 0x${a.name.toString(16)}")
                }
            attrs += RawAttr(a.name, a.form, v)
        }
        val children = ArrayList<RawDie>()
        if (abbr.hasChildren) {
            while (true) {
                if (c.pos.toLong() >= dieEnd) {
                    throw DwarfParseException("unterminated children of die $offset")
                }
                val child = parseDie(c, abbrevs, is64, addressSize, version, depth + 1, ordinal, dieEnd, warnings)
                    ?: break
                if (child.tag == 0) break // null terminator
                children += child
            }
        }
        return RawDie(offset, abbr.tag, attrs, children, depth, ordinal())
    }

    private fun readAttrValue(
        c: DwarfCursor,
        formIn: Int,
        is64: Boolean,
        addressSize: Int,
        version: Int,
        warnings: MutableList<String>,
    ): RawValue? {
        var form = formIn
        if (form == DwForm.INDIRECT) form = c.uleb().toInt()
        return when (form) {
            DwForm.ADDR -> RawValue.Addr(c.fixed(addressSize))
            DwForm.DATA1 -> RawValue.Num(c.u8().toLong())
            DwForm.DATA2 -> RawValue.Num(c.u16().toLong())
            DwForm.DATA4 -> RawValue.Num(c.u32())
            DwForm.DATA8 -> RawValue.Num(c.u64())
            DwForm.DATA16 -> RawValue.Bytes(c.bytes(16))
            DwForm.UDATA -> RawValue.Num(c.uleb())
            DwForm.SDATA -> RawValue.Num(c.sleb())
            DwForm.FLAG -> if (c.u8() != 0) RawValue.Flag else RawValue.Num(0)
            DwForm.FLAG_PRESENT -> RawValue.Present
            DwForm.STRING -> RawValue.Str(c.cstring())
            DwForm.BLOCK1 -> { val n = c.u8(); RawValue.Bytes(c.bytes(n)) }
            DwForm.BLOCK2 -> { val n = c.u16(); RawValue.Bytes(c.bytes(n)) }
            DwForm.BLOCK4 -> { val n = c.u32().toInt(); RawValue.Bytes(c.bytes(n)) }
            DwForm.BLOCK -> { val n = c.uleb().toInt(); RawValue.Bytes(c.bytes(n)) }
            DwForm.EXPRLOC -> { val n = c.uleb().toInt(); RawValue.Bytes(c.bytes(n)) }
            DwForm.STRP -> RawValue.StrRef(if (is64) c.u64() else c.u32())
            DwForm.LINE_STRP -> RawValue.LineStrRef(if (is64) c.u64() else c.u32())
            DwForm.STRP_SUP -> {
                // Supplementary object unavailable: consume, mark unresolvable.
                RawValue.StrRef(-c.fixed(if (is64) 8 else 4) - 1)
            }
            DwForm.REF_SUP4 -> { c.fixed(4); RawValue.GlobalRef(-1) }
            DwForm.REF_SUP8 -> { c.fixed(8); RawValue.GlobalRef(-1) }
            DwForm.REF_ADDR -> RawValue.GlobalRef(if (version >= 5 && is64) c.u64() else c.fixed(if (is64) 8 else 4))
            DwForm.REF1 -> RawValue.CuRef(c.u8().toLong())
            DwForm.REF2 -> RawValue.CuRef(c.u16().toLong())
            DwForm.REF4 -> RawValue.CuRef(c.u32())
            DwForm.REF8 -> RawValue.CuRef(c.u64())
            DwForm.REF_UDATA -> RawValue.CuRef(c.uleb())
            DwForm.SEC_OFFSET -> RawValue.RngListOffset(if (is64) c.u64() else c.u32())
            DwForm.IMPLICIT_CONST -> RawValue.Present // size zero, value carried by abbrev (ignored)
            DwForm.STRX -> RawValue.StrIndex(c.uleb())
            DwForm.STRX1 -> RawValue.StrIndex(c.u8().toLong())
            DwForm.STRX2 -> RawValue.StrIndex(c.u16().toLong())
            DwForm.STRX3 -> RawValue.StrIndex(c.u32() and 0xffffff)
            DwForm.STRX4 -> RawValue.StrIndex(c.u32())
            DwForm.ADDRX -> RawValue.AddrIndex(c.uleb())
            DwForm.ADDRX1 -> RawValue.AddrIndex(c.u8().toLong())
            DwForm.ADDRX2 -> RawValue.AddrIndex(c.u16().toLong())
            DwForm.ADDRX3 -> RawValue.AddrIndex(c.u32() and 0xffffff)
            DwForm.ADDRX4 -> RawValue.AddrIndex(c.u32())
            DwForm.RNGLISTX -> RawValue.RngListIndex(c.uleb())
            DwForm.LOCLISTX -> { c.uleb(); RawValue.Num(0) }
            DwForm.REF_SIG8 -> RawValue.Signature(c.u64())
            else -> null
        }
    }

    data class InitialLength(val length: Long, val is64: Boolean)

    companion object {
        fun readInitialLength(c: DwarfCursor): InitialLength {
            val w = c.u32()
            return if (w == 0xffffffffL) InitialLength(c.u64(), true) else InitialLength(w, false)
        }
    }
}
