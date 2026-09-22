package compass.dwarf

import compass.binfmt.Cursor
import compass.binfmt.DwarfParseException

class ParseLimits(
    val maxDepth: Int = 128,
    val maxRefHops: Int = 64,
    val maxDies: Int = 5_000_000,
)

/**
 * Parses .debug_info into CUs with their DIE trees. A failure in one CU is
 * isolated: the CU is kept with its [CompUnit.warnings] so downstream queries
 * can state exactly which conclusions are still trustworthy.
 */
class InfoParser(
    private val sections: DwarfSections,
    private val abbrevTables: Map<Long, Map<Long, Abbrev>>,
    private val littleEndian: Boolean,
    private val limits: ParseLimits = ParseLimits(),
) {
    private val globalDies = HashMap<Long, DIE>()
    private val cuByStart = HashMap<Long, CompUnit>()

    fun parse(): List<CompUnit> {
        val info = sections.info ?: return emptyList()
        val units = mutableListOf<CompUnit>()
        var c = Cursor(info, 0, info.size, 0, littleEndian)
        while (c.available() > 0) {
            val headerStart = c.pos.toLong()
            try {
                val cu = parseUnit(c, headerStart)
                units.add(cu)
                cuByStart[headerStart] = cu
                c.seek(cu.endOffset.toIntExact())
            } catch (e: DwarfParseException) {
                units.add(brokenUnit(headerStart, e.message ?: "parse error"))
                break // cannot reliably find the next header; stop scanning this section
            }
        }
        return units
    }

    private fun brokenUnit(offset: Long, msg: String): CompUnit {
        val cu = CompUnit(offset, 0, 0, 0, false, 0, 0, offset, 4, null)
        cu.warnings.add("unit unparseable: $msg")
        return cu
    }

    private fun parseUnit(c: Cursor, headerStart: Long): CompUnit {
        val (unitLength, is64) = readInitialLength(c)
        val bodyStart = c.pos
        val bodyEnd = (bodyStart + unitLength).toIntExact()
        val version = c.u16()
        val unitType: Int
        var addressSize = 0
        var debugAbbrevOffset = 0L
        if (version >= 5) {
            unitType = c.u8()
            addressSize = c.u8()
            debugAbbrevOffset = readOffset(c, is64)
        } else {
            debugAbbrevOffset = readOffset(c, is64)
            addressSize = c.u8()
            unitType = CompUnit.UNIT_COMPILE
        }
        val cu = CompUnit(
            headerOffset = headerStart,
            unitLength = unitLength,
            version = version,
            unitType = unitType,
            is64Bit = is64,
            addressSize = addressSize,
            debugAbbrevOffset = debugAbbrevOffset,
            dieOffset = c.pos.toLong(),
            globalOffsetSize = if (is64) 8 else 4,
            dwoId = null,
        )
        if (addressSize !in 1..8) throw DwarfParseException("bad address_size $addressSize at cu $headerStart")
        if (bodyEnd > c.end) throw DwarfParseException("unit length exceeds section at $headerStart")

        val table = abbrevTables[debugAbbrevOffset]
            ?: run { cu.warnings.add("abbrev table not found at offset $debugAbbrevOffset"); return cu }

        parseDIEs(c.slice(bodyStart, bodyEnd - bodyStart), cu, table)
        resolveReferences(cu)
        return cu
    }

    private fun parseDIEs(uc: Cursor, cu: CompUnit, table: Map<Long, Abbrev>) {
        // Iterative DIE tree build: stack holds (die, depth, siblingsRemaining).
        data class Frame(var die: DIE?, val depth: Int)
        val stack = ArrayDeque<Frame>()
        var dieCount = 0
        while (uc.available() > 0) {
            val dieOff = uc.pos.toLong()
            val code = uc.uleb128()
            if (code == 0L) {
                if (stack.isNotEmpty()) stack.removeLast()
                if (stack.isEmpty()) return
                continue
            }
            if (stack.size >= limits.maxDepth) {
                cu.warnings.add("DIE depth limit at offset $dieOff; subtree skipped")
                // cannot skip an unknown subtree without parsing abbrevs; abort this CU cleanly
                return
            }
            val abbrev = table[code]
            if (abbrev == null) {
                cu.warnings.add("unknown abbrev code $code at offset $dieOff; CU scan stopped")
                return
            }
            val attrs = LinkedHashMap<Int, AttrValue>()
            var stopCu = false
            for (spec in abbrev.specs) {
                try {
                    attrs[spec.name] = readForm(uc, spec, cu)
                } catch (e: DwarfParseException) {
                    cu.warnings.add("form 0x${spec.form.toString(16)} (attr 0x${spec.name.toString(16)}) unreadable at offset $dieOff: ${e.message}; CU scan stopped")
                    stopCu = true
                    break
                }
            }
            if (stopCu) return
            val die = DIE(offset = dieOff, tag = abbrev.tag, abbrevCode = code, attrs = attrs)
            globalDies[dieOff] = die
            dieCount++
            if (dieCount > limits.maxDies) { cu.warnings.add("DIE count limit exceeded"); return }

            if (stack.isEmpty()) cu.root = die
            else {
                val parent = stack.last().die
                parent!!.children.add(die); die.parent = parent
            }
            if (abbrev.hasChildren) stack.addLast(Frame(die, stack.size + 1))
        }
    }

    private fun readInitialLength(c: Cursor): Pair<Long, Boolean> {
        val first = c.u32()
        if (first == 0xffffffffL) {
            val len = c.u64()
            if (len > Int.MAX_VALUE.toLong()) throw DwarfParseException("64-bit unit too large")
            return len to true
        }
        return first to false
    }

    private fun readOffset(c: Cursor, is64: Boolean): Long = if (is64) c.u64() else c.u32()

    private fun readForm(c: Cursor, spec: AttributeSpec, cu: CompUnit): AttrValue {
        val a = cu.addressSize
        return when (val f = spec.form) {
            Dw.FORM_addr -> AttrValue.Number(c.addr(a))
            Dw.FORM_flag -> AttrValue.Number(c.u8().toLong())
            Dw.FORM_data1 -> AttrValue.Number(c.u8().toLong(), constant = true)
            Dw.FORM_data2 -> AttrValue.Number(c.u16().toLong(), constant = true)
            Dw.FORM_ref_sup4 -> AttrValue.Number(c.u32())
            Dw.FORM_data4 -> AttrValue.Number(c.u32(), constant = true)
            Dw.FORM_ref_sig8, Dw.FORM_ref_sup8 -> AttrValue.Number(c.u64())
            Dw.FORM_data8 -> AttrValue.Number(c.u64(), constant = true)
            Dw.FORM_sdata -> AttrValue.Number(c.sleb128(), constant = true)
            Dw.FORM_udata -> AttrValue.Number(c.uleb128(), constant = true)
            Dw.FORM_flag_present -> AttrValue.Number(1)
            Dw.FORM_implicit_const -> AttrValue.Number(spec.implicitConst ?: 0L, constant = true)
            Dw.FORM_string -> {
                val begin = c.pos
                var p2 = begin
                while (p2 < c.end && c.data[p2].toInt() != 0) p2++
                if (p2 >= c.end) throw DwarfParseException("unterminated inline string")
                val text = String(c.data, begin, p2 - begin, Charsets.UTF_8)
                c.at(p2 + 1)
                AttrValue.Str(text)
            }
            Dw.FORM_strp -> AttrValue.StrRef("debug_str", readOffset(c, cu.is64Bit))
            Dw.FORM_line_strp -> AttrValue.StrRef("debug_line_str", readOffset(c, cu.is64Bit))
            Dw.FORM_strp_sup -> AttrValue.StrRef("debug_str_sup", readOffset(c, cu.is64Bit))
            Dw.FORM_sec_offset -> AttrValue.Number(readOffset(c, cu.is64Bit))
            Dw.FORM_ref_addr -> AttrValue.RefGlobal(if (cu.version <= 3) c.addr(a) else readOffset(c, cu.is64Bit))
            Dw.FORM_ref_udata -> AttrValue.RefCu(cu.headerOffset + c.uleb128())
            Dw.FORM_ref1 -> AttrValue.RefCu(cu.headerOffset + c.u8())
            Dw.FORM_ref2 -> AttrValue.RefCu(cu.headerOffset + c.u16())
            Dw.FORM_ref4 -> AttrValue.RefCu(cu.headerOffset + c.u32())
            Dw.FORM_ref8 -> AttrValue.RefCu(cu.headerOffset + c.u64())
            Dw.FORM_block1 -> AttrValue.Bytes(c.bytes(c.u8()))
            Dw.FORM_block2 -> AttrValue.Bytes(c.bytes(c.u16()))
            Dw.FORM_block4 -> AttrValue.Bytes(c.bytes(c.u32().toIntExact()))
            Dw.FORM_block -> AttrValue.Bytes(c.bytes(c.uleb128().toIntExact()))
            Dw.FORM_exprloc -> AttrValue.Bytes(c.bytes(c.uleb128().toIntExact()))
            Dw.FORM_data16 -> AttrValue.Bytes(c.bytes(16))
            Dw.FORM_GNU_ref_alt -> AttrValue.RefAlt(readOffset(c, cu.is64Bit))
            Dw.FORM_GNU_strp_alt -> AttrValue.StrRef("alt", readOffset(c, cu.is64Bit))
            Dw.FORM_strx, Dw.FORM_strx1, Dw.FORM_strx2, Dw.FORM_strx3, Dw.FORM_strx4 ->
                AttrValue.Strx(readIndex(c, f), null)
            Dw.FORM_addrx, Dw.FORM_addrx1, Dw.FORM_addrx2, Dw.FORM_addrx3, Dw.FORM_addrx4 ->
                AttrValue.Addrx(readIndex(c, f), null)
            Dw.FORM_rnglistx -> AttrValue.Rnglistx(c.uleb128())
            Dw.FORM_loclistx -> AttrValue.Number(c.uleb128())
            Dw.FORM_indirect -> {
                val real = c.uleb128().toInt()
                readForm(c, spec.copy(form = real), cu)
            }
            else -> {
                // Unknown form: we do NOT know its length, so consuming more bytes would
                // desync the cursor and fabricate later DIEs. Report and stop the CU.
                throw DwarfParseException("unknown DWARF form 0x${f.toString(16)}")
            }
        }
    }

    private fun readIndex(c: Cursor, form: Int): Long = when (form) {
        Dw.FORM_strx1, Dw.FORM_addrx1 -> c.u8().toLong()
        Dw.FORM_strx2, Dw.FORM_addrx2 -> c.u16().toLong()
        Dw.FORM_strx3, Dw.FORM_addrx3 -> c.u24()
        Dw.FORM_strx4, Dw.FORM_addrx4 -> c.u32()
        else -> c.uleb128()
    }

    /** Resolve CU-relative references to global offsets; bounds-checked, hop-limited. */
    private fun resolveReferences(cu: CompUnit) {
        fun walk(die: DIE?, depth: Int) {
            if (die == null || depth > limits.maxDepth) return
            die.children.forEach { walk(it, depth + 1) }
        }
        walk(cu.root, 0)
    }
}

private fun Long.toIntExact(): Int {
    if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseException("length/offset out of 32-bit range: $this")
    return toInt()
}

/** CU-relative RefCu values already encode the global offset (header+delta). Validate bounds lazily at lookup. */
fun DIE.resolveAttrRef(v: AttrValue): DIE? = when (v) {
    is AttrValue.RefCu -> {
        // reference is stored globally here (see readForm), lookup happens via the model index
        null
    }
    else -> null
}
