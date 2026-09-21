package compass.dwarf

import compass.util.ByteReader
import compass.util.Limits
import compass.util.ParseException
import compass.util.U64

/**
 * Parses .debug_info / .debug_info.dwo into CompilationUnits.
 *
 * Robustness rules:
 *  - each CU is parsed independently; a bad CU records issues and keeps whatever DIEs were read
 *  - unknown forms abort the *current* CU (cursor stays inside that CU's declared length,
 *    so subsequent CUs are still parsed)
 *  - DIE depth is capped at Limits.MAX_DIE_DEPTH
 */
class CuParser(
    private val sections: Sections,
    private val abbrevs: AbbreviationTables,
    private val debugData: DebugData,
    private val dwo: Boolean
) {
    private val infoName = if (dwo) ".debug_info.dwo" else ".debug_info"

    fun parse(): List<CompilationUnit> {
        val bytes = sections[infoName] ?: return emptyList()
        val units = ArrayList<CompilationUnit>()
        var global = 0
        var p = 0
        while (p < bytes.size) {
            if (units.size >= Limits.MAX_CU_COUNT) break
            val cuStart = p
            val unit: CompilationUnit = parseOneSafe(bytes, p, global)
            units += unit
            global++
            // unitLength excludes the 4/12-byte length prefix; advance by prefix + length.
            val prefix = if (unit.dwarf64) 12 else 4
            val next = cuStart + prefix + unit.unitLength.toInt()
            if (unit.unitLength <= 0 || next <= p || next > bytes.size) break
            p = next
        }
        return units
    }

    private fun parseOneSafe(bytes: ByteArray, cuStart: Int, index: Int): CompilationUnit {
        return try {
            parseOne(bytes, cuStart, index)
        } catch (e: ParseException) {
            // Header-level failure: length/version unknown, safe advance is impossible — stop scan
            // by returning a broken unit with zero length; caller halts after it.
            brokenUnit(cuStart, index, listOf(
                ParseIssue("error", "BAD_CU_HEADER", e.message ?: "CU header parse failed", infoName, U64(cuStart.toLong()), null)
            ))
        }
    }

    private fun brokenUnit(offset: Int, index: Int, issues: List<ParseIssue>) = CompilationUnit(
        index = index, dwarfVersion = 0, unitType = null, dwarf64 = false,
        offset = U64(offset.toLong()), unitLength = 0, headerSize = 0, abbrevOffset = null,
        addressSize = 0, kind = "unknown", name = null, compDir = null, dwoId = null,
        dwoName = null, strOffsetsBase = null, addrBase = null, rnglistsBase = null,
        loclistsBase = null, stmtList = null, dies = emptyList(),
        issues = issues, parsedCompletely = false
    )

    private fun parseOne(bytes: ByteArray, cuStart: Int, index: Int): CompilationUnit {
        val r = ByteReader(bytes, cuStart)
        val initialLen = r.u32()
        val dwarf64: Boolean
        val unitLength: Long
        val offsetSize: Int
        if (initialLen == 0xffffffffL) {
            dwarf64 = true; offsetSize = 8; unitLength = r.u64().v
        } else {
            dwarf64 = false; offsetSize = 4; unitLength = initialLen
        }
        if (unitLength <= 0 || unitLength > Limits.MAX_CU_BYTES ||
            cuStart + (if (dwarf64) 12 else 4) + unitLength > bytes.size
        ) {
            throw ParseException("CU at $cuStart has invalid length $unitLength")
        }
        val cuEnd = cuStart + (if (dwarf64) 12 else 4) + unitLength.toInt()
        val version = r.u16()
        if (version !in 2..5) throw ParseException("unsupported DWARF version $version at $cuStart")

        var unitType: Int? = null
        var abbrevOff: U64
        var addressSize = if (version <= 3) 4 else 0
        var dwoId: U64? = null

        if (version >= 5) {
            unitType = r.u8()
            addressSize = r.u8()
            abbrevOff = readOff(r, offsetSize)
            if (unitType == DwUnit.SKELETON || unitType == DwUnit.SPLIT_COMPILE) {
                dwoId = r.u64()
            }
            if (unitType == DwUnit.TYPE || unitType == DwUnit.SPLIT_TYPE) {
                // type_signature (8) + type_offset
                r.u64(); readOff(r, offsetSize)
            }
        } else {
            abbrevOff = readOff(r, offsetSize)
            addressSize = r.u8()
        }
        val headerSize = r.snapshot() - cuStart

        val kind = when {
            unitType == DwUnit.SKELETON -> "skeleton"
            unitType == DwUnit.SPLIT_COMPILE || dwo -> "split"
            else -> "full"
        }

        val issues = ArrayList<ParseIssue>()
        val dies = ArrayList<Die>()

        val table = abbrevs.tableAt(abbrevOff, dwo || kind == "split")
        if (table is AbbreviationTables.ParseResult.Bad) {
            issues += table.issue
            return CompilationUnit(
                index, version, unitType, dwarf64, U64(cuStart.toLong()), unitLength, headerSize,
                abbrevOff, addressSize, 0, kind, null, null, dwoId, null,
                null, null, null, null, null, dies, issues, false
            )
        }
        val decls = (table as AbbreviationTables.ParseResult.Ok).decls

        val ctx = FormContext(
            dwarfVersion = version, dwarf64 = dwarf64, offsetSize = offsetSize,
            addressSize = addressSize, dwo = dwo || kind == "split",
            cuOffset = U64(cuStart.toLong()),
            strOffsetsBase = if (version >= 5) U64(cuStart.toLong() + headerSize.toLong()) else null,
            addrBase = if (version >= 5) U64(0) else null,
            debugData = debugData
        )

        var cuName: String? = null
        var compDir: String? = null
        var dwoName: String? = null
        var strBase: U64? = ctx.strOffsetsBase
        var addrBase: U64? = ctx.addrBase
        var rngBase: U64? = if (version >= 5) U64(0) else null
        var locBase: U64? = if (version >= 5) U64(0) else null
        var stmtList: U64? = null

        val dieEnd = cuEnd
        var complete = true
        val parentStack = ArrayDeque<Int>() // indexes into dies
        try {
            var dieCount = 0
            while (r.pos < dieEnd) {
                val dieOffset = U64(r.pos.toLong())
                val code = r.uleb128()
                if (code == 0L) {
                    if (parentStack.isNotEmpty()) parentStack.removeLast()
                    continue
                }
                if (++dieCount > Limits.MAX_DIE_PER_CU) throw ParseException("too many DIEs in CU")
                if (parentStack.size > Limits.MAX_DIE_DEPTH) throw ParseException("DIE depth exceeds ${Limits.MAX_DIE_DEPTH}")
                val decl = decls[code] ?: throw ParseException("abbreviation code $code not found at ${dieOffset}")
                val attrs = LinkedHashMap<Int, AttrValue>(decl.attrs.size)
                for (aa in decl.attrs) {
                    val v = FormReader.read(r, aa.form, ctx, aa.implicitValue)
                    attrs[aa.attr] = v
                }

                if (decl.tag == DwTag.COMPILE_UNIT && parentStack.isEmpty()) {
                    cuName = (attrs[DwAt.NAME] as? AttrValue.Str)?.v
                    compDir = (attrs[DwAt.COMP_DIR] as? AttrValue.Str)?.v
                    dwoName = (attrs[DwAt.DWO_NAME] as? AttrValue.Str)?.v
                    stmtList = when (val s = attrs[DwAt.STMT_LIST]) {
                        is AttrValue.SecOff -> s.v
                        is AttrValue.UConst -> s.v
                        else -> null
                    }
                    (attrs[DwAt.STR_OFFSETS_BASE] as? AttrValue.SecOff)?.let {
                        strBase = it.v; ctx.strOffsetsBase = it.v
                    }
                    (attrs[DwAt.ADDR_BASE] as? AttrValue.SecOff)?.let {
                        addrBase = it.v; ctx.addrBase = it.v
                    }
                    (attrs[DwAt.RANGES_BASE] as? AttrValue.SecOff)?.let { rngBase = it.v }
                    (attrs[DwAt.LOCLISTS_BASE] as? AttrValue.SecOff)?.let { locBase = it.v }
                }

                val name = (attrs[DwAt.NAME] as? AttrValue.Str)?.v
                val linkage = (attrs[DwAt.LINKAGE_NAME] as? AttrValue.Str)?.v
                val inlineCode = (attrs[DwAt.INLINE] as? AttrValue.UConst)?.let { it.v.v.toInt() }
                val parentIdx = parentStack.lastOrNull()
                val d = Die(
                    offset = dieOffset,
                    parentOffset = parentIdx?.let { dies[it].offset },
                    depth = parentStack.size,
                    tag = decl.tag,
                    name = name,
                    linkageName = linkage,
                    inlineCode = inlineCode,
                    declarationFile = null,
                    declarationLine = (attrs[DwAt.DECL_LINE] as? AttrValue.UConst)?.let { it.v.v.toInt() },
                    callFile = null,
                    callLine = (attrs[DwAt.CALL_LINE] as? AttrValue.UConst)?.let { it.v.v.toInt() },
                    abstractOrigin = (attrs[DwAt.ABSTRACT_ORIGIN] as? AttrValue.Ref)?.v,
                    specification = (attrs[DwAt.SPECIFICATION] as? AttrValue.Ref)?.v,
                    attrs = attrs
                )
                val newIdx = dies.size
                if (parentIdx != null) {
                    val pd = dies[parentIdx]
                    dies[parentIdx] = pd.copy(childOffsets = pd.childOffsets + dieOffset)
                }
                dies += d
                if (decl.hasChildren) parentStack.addLast(newIdx)
            }
        } catch (e: UnknownFormException) {
            complete = false
            issues += ParseIssue(
                "error", "UNKNOWN_FORM",
                "${e.message ?: "unsupported form"} — CU parsing stopped; previously parsed DIEs retained",
                infoName, null, U64(cuStart.toLong())
            )
        } catch (e: ParseException) {
            complete = false
            issues += ParseIssue(
                "error", "BAD_DIE", "${e.message ?: "DIE parse failed"} — CU parsing stopped; previously parsed DIEs retained",
                infoName, null, U64(cuStart.toLong())
            )
        }

        // DWARF 5 split CUs may carry stmt_list on the (single) subprogram rather than the CU root
        if (stmtList == null) {
            for (d in dies) {
                val sl = when (val v = d.attrs[DwAt.STMT_LIST]) {
                    is AttrValue.SecOff -> v.v
                    is AttrValue.UConst -> v.v
                    else -> null
                }
                if (sl != null) { stmtList = sl; break }
            }
        }

        return CompilationUnit(
            index = index, dwarfVersion = version, unitType = unitType, dwarf64 = dwarf64,
            offset = U64(cuStart.toLong()), unitLength = unitLength, headerSize = headerSize,
            abbrevOffset = abbrevOff, addressSize = addressSize,
            segmentSelectorSize = 0, kind = kind, name = cuName, compDir = compDir,
            dwoId = dwoId, dwoName = dwoName, strOffsetsBase = strBase, addrBase = addrBase,
            rnglistsBase = rngBase, loclistsBase = locBase, stmtList = stmtList,
            dies = dies, issues = issues, parsedCompletely = complete
        )
    }

    private fun readOff(r: ByteReader, size: Int): U64 = if (size == 4) U64(r.u32()) else r.u64()
}
