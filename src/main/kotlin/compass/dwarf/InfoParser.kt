package compass.dwarf

import compass.binary.ByteReader
import compass.binary.ParseException
import compass.binary.uleb

/**
 * Parses all compilation units in a .debug_info(.dwo) section.
 *
 * Robustness rules:
 *  - per-unit length and DIE-depth caps;
 *  - an unknown form aborts the *current* CU exactly at a DIE boundary,
 *    keeping every already-decoded DIE but marking the unit partial/untrusted;
 *  - all other sections remain usable.
 */
object InfoParser {
    private const val MAX_DIE_DEPTH = 256
    private const val MAX_DIES_PER_UNIT = 5_000_000

    fun parse(sections: DwarfSections, infoName: String): Pair<List<CompUnit>, Map<Long, DIE>> {
        val info = sections.bytes(infoName)
            ?: return emptyList<CompUnit>() to emptyMap()
        val abbrevSection = when (infoName) {
            ".debug_info" -> sections.bytes(".debug_abbrev")
            ".debug_types" -> sections.bytes(".debug_abbrev")
            ".debug_info.dwo" -> sections.bytes(".debug_abbrev.dwo") ?: sections.bytes(".debug_abbrev")
            else -> sections.bytes(".debug_abbrev.dwo")
        } ?: throw ParseException("missing abbrev section for $infoName")

        val r = ByteReader(info)
        val units = mutableListOf<CompUnit>()
        val dies = LinkedHashMap<Long, DIE>()

        while (r.remaining() > 0) {
            val headerOffset = r.pos.toLong()
            val unitStartPos = r.pos
            val lengthField = r.u4().toLong() and 0xffffffffL
            if (lengthField == 0L) break
            val is64 = lengthField == 0xffffffffL
            val unitLength: Long
            if (is64) unitLength = r.u8() else unitLength = lengthField
            val afterLength = r.pos
            val unitEnd = (if (is64) afterLength + unitLength else (unitStartPos + 4 + unitLength)).toInt()
            if (unitEnd <= r.pos || unitEnd > info.size) {
                throw ParseException("CU at 0x${headerOffset.toString(16)} has bad length $unitLength")
            }
            val body = ByteReader(info, afterLength, unitEnd, afterLength)
            val version = body.u2()
            var unitType = DW.UT.compile
            var addressSize = 4
            var abbrevOffset: Long
            var dwoId: Long? = null
            when {
                version >= 5 -> {
                    unitType = body.u1()
                    addressSize = body.u1()
                    abbrevOffset = readOffset(body, is64)
                    if (unitType == DW.UT.skeleton || unitType == DW.UT.split_compile ||
                        unitType == DW.UT.type || unitType == DW.UT.split_type
                    ) {
                        dwoId = body.u8()
                    }
                    if (unitType == DW.UT.type || unitType == DW.UT.split_type) {
                        body.u8() // type signature
                        body.u8().let { /* type offset, 64-bit in v5 */ }
                    }
                }
                version == 4 || version == 3 -> {
                    abbrevOffset = readOffset(body, is64)
                    addressSize = body.u1()
                }
                else -> throw ParseException("CU at 0x${headerOffset.toString(16)}: unsupported DWARF version $version")
            }

            val root = DIE(offset = body.pos.toLong(), tag = 0)
            val cu = CompUnit(
                version = version,
                is64BitDwarf = is64,
                unitType = unitType,
                headerOffset = headerOffset,
                endOffset = unitEnd.toLong(),
                abbrevOffset = abbrevOffset,
                addressSize = addressSize,
                dwoId = dwoId,
                root = root,
                infoSection = infoName,
            )

            val abbrev = AbbrevParser.parseAt(abbrevSection, abbrevOffset)
                ?: throw ParseException("abbrev table at 0x${abbrevOffset.toString(16)} not found")

            var dieCount = 0
            var parseError: String? = null
            try {
                val depthStack = ArrayDeque<DIE>()
                depthStack.addLast(root)
                var lastWasSibling = false
                while (body.remaining() > 0) {
                    val diePos = body.pos.toLong()
                    val code = body.uleb()
                    if (code == 0L) {
                        if (depthStack.size <= 1) {
                            // CU-level null terminator
                            if (body.pos != unitEnd) {
                                throw ParseException("CU at 0x${headerOffset.toString(16)} ended early at 0x${body.pos.toString(16)}")
                            }
                            break
                        }
                        depthStack.removeLast()
                        lastWasSibling = false
                        continue
                    }
                    if (depthStack.size >= MAX_DIE_DEPTH) {
                        throw ParseException("DIE nesting exceeds $MAX_DIE_DEPTH in CU 0x${headerOffset.toString(16)}")
                    }
                    if (++dieCount > MAX_DIES_PER_UNIT) {
                        throw ParseException("DIE count exceeds $MAX_DIES_PER_UNIT in CU 0x${headerOffset.toString(16)}")
                    }
                    val decl = abbrev.get(code)
                        ?: throw ParseException("abbrev code $code missing in table 0x${abbrevOffset.toString(16)}")
                    val die = DIE(offset = diePos, tag = decl.tag)
                    die.unit = cu
                    val ctx = FormContext(cu, sections, headerOffset, infoName)
                    for (a in decl.attributes) {
                        val v = FormReader.read(a.form, a.implicitConst, body, ctx)
                        die.attributes.add(Attribute(a.name, a.form, v))
                    }
                    val parent = depthStack.last()
                    die.parent = parent
                    parent.children.add(die)
                    dies[diePos] = die
                    if (decl.hasChildren) depthStack.addLast(die)
                    lastWasSibling = false
                }
            } catch (e: UnknownFormException) {
                parseError = "isolated CU: unsupported form 0x${e.form.toString(16)} at 0x${body.pos.toString(16)}"
            } catch (e: ParseException) {
                parseError = "corrupt CU: ${e.message}"
            }
            if (parseError != null) {
                cu.parseError = parseError
                cu.partial = true
            }

            applyUnitBases(cu)
            resolvePending(cu, dies, sections)
            units.add(cu)
            r.seek(unitEnd)
        }
        return units to dies
    }

    private fun readOffset(r: ByteReader, is64: Boolean): Long =
        if (is64) r.u8() else (r.u4().toLong() and 0xffffffffL)

    private fun applyUnitBases(cu: CompUnit) {
        (cu.root.attrValue(DW.AT.addr_base) ?: cu.root.attrValue(DW.AT.GNU_addr_base))
            ?.let { if (it is AttrValue.SectionOffset) cu.addrBase = it.offset }
        (cu.root.attrValue(DW.AT.str_offsets_base) ?: cu.root.attrValue(DW.AT.GNU_str_offsets_base))
            ?.let { if (it is AttrValue.SectionOffset) cu.strOffsetsBase = it.offset }
        cu.root.attrValue(DW.AT.rnglists_base)
            ?.let { if (it is AttrValue.SectionOffset) cu.rnglistsBase = it.offset }
    }

    private fun resolvePending(cu: CompUnit, dies: Map<Long, DIE>, sections: DwarfSections) {
        cu.root.walk { die ->
            for (i in die.attributes.indices) {
                val a = die.attributes[i]
                when (val v = a.value) {
                    is AttrValue.PendingStrIndex -> {
                        val resolved = resolveStrx(cu, sections, v.index)
                        die.attributes[i] = a.copy(value = resolved)
                    }
                    is AttrValue.PendingAddrIndex -> {
                        val resolved = resolveAddrx(cu, sections, v.index)
                        if (resolved != null) die.attributes[i] = a.copy(value = resolved)
                    }
                    else -> {}
                }
            }
        }
    }

    private fun resolveStrx(cu: CompUnit, sections: DwarfSections, index: Int): AttrValue {
        val candidates = listOf(".debug_str_offsets.dwo", ".debug_str_offsets")
        val strCandidates = listOf(".debug_str.dwo", ".debug_str")
        for (soName in candidates) {
            val so = sections.bytes(soName) ?: continue
            val hdr = ByteReader(so)
            var entrySize = 4
            if (so.size >= 8) {
                val length0 = hdr.u4().toLong() and 0xffffffffL
                if (length0 != 0xffffffffL) {
                    val end = 4 + length0
                    hdr.u2() // version
                    hdr.u2() // padding
                    entrySize = if (cu.is64BitDwarf) 8 else 4
                    val base = cu.strOffsetsBase.toInt().coerceAtLeast(8)
                    val at = base + index * entrySize
                    if (at < 0 || at + entrySize > end) continue
                    hdr.seek(at)
                    val strOff = if (entrySize == 8) hdr.u8() else (hdr.u4().toLong() and 0xffffffffL)
                    for (sn in strCandidates) {
                        val ss = sections.bytes(sn) ?: continue
                        if (strOff in 0 until ss.size) return AttrValue.Str(ByteReader(ss).cStringAt(strOff.toInt()))
                    }
                }
            }
            // v4/GNU str_offsets: raw array of offsets with no header.
            val at = cu.strOffsetsBase.toInt() + index * (if (cu.is64BitDwarf) 8 else 4)
            if (at + 4 <= so.size) {
                hdr.seek(at)
                val strOff = (hdr.u4().toLong() and 0xffffffffL)
                sections.bytes(".debug_str")?.let { ss ->
                    if (strOff in 0 until ss.size) return AttrValue.Str(ByteReader(ss).cStringAt(strOff.toInt()))
                }
            }
        }
        return AttrValue.Str("<unresolved strx $index>")
    }

    private fun resolveAddrx(cu: CompUnit, sections: DwarfSections, index: Int): AttrValue? {
        val addr = sections.bytes(".debug_addr") ?: return null
        val entry = cu.addressSize.coerceAtLeast(1)
        // v5 .debug_addr has an 8-byte header (length/version) but DW_AT_addr_base points
        // past it, so cu.addrBase is already the array start.
        val at = cu.addrBase + index.toLong() * entry
        if (at + entry > addr.size) return null
        val r = ByteReader(addr, at.toInt(), (at + entry).toInt().coerceAtMost(addr.size), at.toInt())
        return when (entry) {
            4 -> AttrValue.Addr(r.u4().toLong() and 0xffffffffL)
            8 -> AttrValue.Addr(r.u8())
            else -> null
        }
    }
}
