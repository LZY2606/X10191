package compass.dwarf

import compass.Limits

/** Parses one .debug_info (or .debug_info.dwo) section into compilation units. */
object InfoParser {

    fun parse(info: ByteArray, sections: SectionSet, fromDwo: Boolean, fileWarnings: MutableList<String>): List<ParsedCu> {
        val cus = ArrayList<ParsedCu>()
        var pos = 0
        while (pos < info.size) {
            val cuStart = pos
            try {
                val cu = parseCu(info, cuStart, sections, fromDwo)
                cus.add(cu.first)
                pos = cu.second
            } catch (e: DwarfException) {
                fileWarnings.add("CU at 0x${cuStart.toString(16)}: ${e.message}")
                break // cannot locate the next CU reliably; stop the section
            }
        }
        return cus
    }

    private class CuHeader(
        val version: Int, val unitType: Int, val addrSize: Int,
        val dwarf64: Boolean, val abbrevOffset: Long, val dataStart: Int, val cuEnd: Int,
    )

    private fun header(info: ByteArray, cuStart: Int): CuHeader {
        val r = Reader(info, cuStart)
        val len0 = r.u32()
        val dwarf64: Boolean
        val unitLen: Long
        if (len0 == 0xFFFF_FFFFL) { dwarf64 = true; unitLen = r.u64() } else { dwarf64 = false; unitLen = len0 }
        if (unitLen <= 0 || cuStart + r.pos - cuStart + unitLen > Int.MAX_VALUE)
            throw ParseException("bad CU length 0x${unitLen.toString(16)}")
        val cuEnd = minOf(info.size, r.pos + unitLen.toInt())
        if (cuEnd < r.pos + 4) throw ParseException("CU truncated by section end")
        val version = r.u16()
        return if (version >= 5) {
            val unitType = r.u8()
            val addrSize = r.u8()
            val abbrevOff = r.offset(dwarf64)
            CuHeader(version, unitType, addrSize, dwarf64, abbrevOff, r.pos, cuEnd)
        } else {
            val abbrevOff = r.offset(dwarf64)
            val addrSize = r.u8()
            CuHeader(version, -1, addrSize, dwarf64, abbrevOff, r.pos, cuEnd)
        }
    }

    private fun parseCu(info: ByteArray, cuStart: Int, sections: SectionSet, fromDwo: Boolean): Pair<ParsedCu, Int> {
        val h = header(info, cuStart)
        val warnings = ArrayList<String>()
        val abbrevSec = sections.get(".debug_abbrev")
            ?: throw ParseException("missing .debug_abbrev section")
        val abbrevs = try {
            parseAbbrevTable(abbrevSec, h.abbrevOffset.toInt())
        } catch (e: DwarfException) {
            throw ParseException("bad abbrev table at 0x${h.abbrevOffset.toString(16)}: ${e.message}")
        }

        val dies = ArrayList<Die>()
        val dieByOffset = HashMap<Long, Die>()
        var truncated = false

        fun parseDie(r: Reader, depth: Int): Die? {
            if (depth > Limits.MAX_DIE_DEPTH)
                throw ParseException("DIE nesting deeper than ${Limits.MAX_DIE_DEPTH}")
            if (dies.size >= Limits.MAX_DIES_PER_CU)
                throw ParseException("too many DIEs in CU")
            val off = (r.pos - 0).toLong()
            val code = r.uleb()
            if (code == 0L) return null
            val ab = abbrevs[code] ?: throw ParseException("unknown abbrev code $code at DIE 0x${off.toString(16)}")
            val attrs = ArrayList<AttrEnt>(ab.attrs.size)
            for (aa in ab.attrs) {
                val v = readFormValue(r, aa.form, h.addrSize, h.dwarf64, aa.implicitConst)
                attrs.add(AttrEnt(aa.attr, aa.form, v))
            }
            val die = Die(off, ab.tag, depth, attrs)
            dies.add(die)
            dieByOffset[off] = die
            if (ab.hasChildren) {
                while (true) {
                    val child = parseDie(r, depth + 1) ?: break
                    die.children.add(child)
                }
            }
            return die
        }

        val r = Reader(info, h.dataStart, h.cuEnd)
        val root: Die? = try {
            parseDie(r, 0)
        } catch (e: UnknownFormException) {
            truncated = true
            warnings.add("isolated: ${e.message}; CU truncated, cursor not resynchronized")
            null
        } catch (e: ParseException) {
            truncated = true
            warnings.add("parse error: ${e.message}; CU truncated")
            null
        }
        // Consume any sibling CUs' null terminator implicitly via cuEnd; next CU starts at cuEnd.

        val interp = Interpreter(info, sections, h, warnings, dieByOffset)
        val rootInfo = root?.let { interp.interpret(it, parentOffset = -1, out = ArrayList()) }
        val dieInfos = rootInfo?.second ?: emptyList()

        val cuAttrs = root?.attrs ?: emptyList()
        fun numAttr(a: Int): Long? = (cuAttrs.firstOrNull { it.attr == a }?.value as? AttrValue.Num)?.v

        val lowPc = interp.addrOf(cuAttrs.firstOrNull { it.attr == At.LOW_PC })
        val highPc = interp.highPc(cuAttrs.firstOrNull { it.attr == At.HIGH_PC }, lowPc)
        val ranges = interp.rangesOf(cuAttrs.firstOrNull { it.attr == At.RANGES }, lowPc)
        val name = interp.stringOf(cuAttrs.firstOrNull { it.attr == At.NAME })
        val compDir = interp.stringOf(cuAttrs.firstOrNull { it.attr == At.COMP_DIR })
        val producer = interp.stringOf(cuAttrs.firstOrNull { it.attr == At.PRODUCER })

        val skeleton = (root?.tag == Tag.SKELETON_UNIT) || h.unitType == 0x04 ||
            cuAttrs.any { it.attr == At.DWO_ID || it.attr == At.DWO_NAME }
        val dwoMissing = skeleton && !fromDwo && !sections.has(".debug_info.dwo")
        if (dwoMissing)
            warnings.add("skeleton CU references missing .dwo: file/line data unavailable; CU address ranges remain trustworthy")

        var lineVersion: Int? = null
        val rows = ArrayList<LineRow>()
        val stmtList = numAttr(At.STMT_LIST)
        if (stmtList != null) {
            val lineSec = sections.get(".debug_line")
            if (lineSec == null) {
                warnings.add("stmt_list present but .debug_line missing")
            } else if (stmtList < 0 || stmtList >= lineSec.size) {
                warnings.add("stmt_list 0x${stmtList.toString(16)} outside .debug_line (size 0x${lineSec.size.toString(16)})")
            } else {
                try {
                    val table = parseLineProgram(lineSec, stmtList.toInt()) { off, lineStr -> sections.str(off, lineStr) }
                    lineVersion = table.version
                    rows.addAll(table.rows)
                    warnings.addAll(table.warnings)
                } catch (e: DwarfException) {
                    warnings.add("line program at 0x${stmtList.toString(16)} failed: ${e.message}")
                }
            }
        }

        val cu = ParsedCu(
            offset = cuStart.toLong(), version = h.version, unitType = h.unitType,
            dwarf64 = h.dwarf64, addrSize = h.addrSize,
            name = name, compDir = compDir, producer = producer,
            lowPc = lowPc, highPc = highPc, ranges = ranges,
            skeleton = skeleton, dwoMissing = dwoMissing, truncated = truncated,
            fromDwo = fromDwo, lineVersion = lineVersion, rows = rows,
            dies = dieInfos, warnings = warnings,
        )
        return cu to h.cuEnd
    }

    /** Attribute interpretation with bounded reference chasing. */
    private inner class Interpreter(
        private val info: ByteArray,
        private val sections: SectionSet,
        private val h: CuHeader,
        private val warnings: MutableList<String>,
        private val dieByOffset: Map<Long, Die>,
    ) {
        private var strOffsetsBase = 0L
        private var addrBase = 0L
        private var rnglistsBase = 0L

        fun stringOf(ent: AttrEnt?): String? {
            if (ent == null) return null
            return when (val v = ent.value) {
                is AttrValue.Str -> v.s
                is AttrValue.Strp -> sections.str(v.offset, v.lineStr)
                    ?: run { warnings.add("string offset 0x${v.offset.toString(16)} unresolvable"); null }
                is AttrValue.Strx -> sections.strx(v.index, strOffsetsBase, h.dwarf64)
                    ?: run { warnings.add("strx index ${v.index} unresolvable"); null }
                else -> null
            }
        }

        fun addrOf(ent: AttrEnt?): Long? {
            if (ent == null) return null
            return when (val v = ent.value) {
                is AttrValue.Addr -> v.v
                is AttrValue.Addrx -> sections.addrx(v.index, addrBase, h.addrSize)
                    ?: run { warnings.add("addrx index ${v.index} unresolvable"); null }
                else -> null
            }
        }

        /** high_pc: address class means absolute; constant class means offset from low_pc. */
        fun highPc(ent: AttrEnt?, lowPc: Long?): Long? {
            if (ent == null) return null
            return when (ent.value) {
                is AttrValue.Addr, is AttrValue.Addrx -> addrOf(ent)
                is AttrValue.Num -> lowPc?.let { it + (ent.value as AttrValue.Num).v }
                else -> null
            }
        }

        fun rangesOf(ent: AttrEnt?, lowPc: Long?): List<AddrRange> {
            if (ent == null) return emptyList()
            val base = lowPc ?: 0
            return when (ent.form) {
                F.SEC_OFFSET -> {
                    val off = (ent.value as AttrValue.Num).v
                    if (h.version >= 5 && sections.has(".debug_rnglists")) {
                        parseRnglists(sections.get(".debug_rnglists")!!, off.toInt(), h.addrSize, base.toLong(),
                            { idx -> sections.addrx(idx, addrBase, h.addrSize) }, warnings)
                    } else {
                        val sec = sections.get(".debug_ranges")
                        if (sec == null) { warnings.add("ranges attr but no .debug_ranges"); emptyList() }
                        else parseDebugRanges(sec, off.toInt(), h.addrSize, base.toLong(), warnings)
                    }
                }
                F.RNGLISTX -> {
                    val idx = (ent.value as AttrValue.Num).v
                    val sec = sections.get(".debug_rnglists")
                    if (sec == null) { warnings.add("rnglistx but no .debug_rnglists"); emptyList() }
                    else {
                        val off = rnglistsOffsetFor(sec, idx, rnglistsBase, warnings)
                        if (off == null) emptyList()
                        else parseRnglists(sec, off.toInt(), h.addrSize, base.toLong(),
                            { i -> sections.addrx(i, addrBase, h.addrSize) }, warnings)
                    }
                }
                else -> emptyList()
            }
        }

        private fun refTarget(ent: AttrEnt?): Die? {
            val v = ent?.value as? AttrValue.Ref ?: return null
            if (v.offset < 0 || v.offset >= info.size) {
                warnings.add("reference offset 0x${v.offset.toString(16)} out of .debug_info bounds (size 0x${info.size.toString(16)}); ignored")
                return null
            }
            val target = dieByOffset[v.offset]
            if (target == null) warnings.add("reference to unparsed DIE at 0x${v.offset.toString(16)}; ignored")
            return target
        }

        private fun dieName(die: Die, depth: Int): String? {
            if (depth > Limits.MAX_REF_DEPTH) {
                warnings.add("reference chain deeper than ${Limits.MAX_REF_DEPTH}; stopped")
                return null
            }
            stringOf(die.attr(At.NAME))?.let { return it }
            stringOf(die.attr(At.LINKAGE_NAME))?.let { return it }
            val ref = die.attr(At.ABSTRACT_ORIGIN) ?: die.attr(At.SPECIFICATION) ?: return null
            val target = refTarget(ref) ?: return null
            return dieName(target, depth + 1)
        }

        fun interpret(die: Die, parentOffset: Long, out: ArrayList<DieInfo>): Pair<Long, List<DieInfo>> {
            if (die.depth == 0) {
                // CU-level bases must be known before interpreting children.
                strOffsetsBase = (die.attr(At.STR_OFFSETS_BASE)?.value as? AttrValue.Num)?.v ?: 0
                addrBase = (die.attr(At.ADDR_BASE)?.value as? AttrValue.Num)?.v ?: 0
                rnglistsBase = (die.attr(At.RNGLISTS_BASE)?.value as? AttrValue.Num)?.v ?: 0
            }
            val low = addrOf(die.attr(At.LOW_PC))
            val high = highPc(die.attr(At.HIGH_PC), low)
            val ranges = rangesOf(die.attr(At.RANGES), low)
            val callFile = (die.attr(At.CALL_FILE)?.value as? AttrValue.Num)?.v
            val callLine = (die.attr(At.CALL_LINE)?.value as? AttrValue.Num)?.v
            val name = dieName(die, 0)
            out.add(
                DieInfo(
                    offset = die.offset, parentOffset = parentOffset, depth = die.depth,
                    tag = die.tag, name = name, lowPc = low, highPc = high,
                    ranges = ranges, callFile = callFile, callLine = callLine,
                )
            )
            for (c in die.children) interpret(c, die.offset, out)
            return die.offset to out
        }
    }
}
