package compass.dwarf

import compass.ByteReader
import compass.DwarfFormatException
import compass.DwarfTruncationException
import compass.unitLength

/**
 * Parses .debug_info into [CompilationUnit]s.
 *
 * Safety model:
 *  - every read goes through a [ByteReader] clamped to the unit's declared length;
 *  - an unknown/unsupported form aborts the *current* CU (we cannot know how many bytes it
 *    occupies, so continuing would desynchronise the cursor and fabricate DIEs);
 *  - reference targets are validated later against section bounds; an out-of-range reference
 *    produces an issue on the referencing CU, never an exception leaking to the UI.
 */
class InfoParser(private val obj: DebugObject) {

    private val info = obj.section(".debug_info")
    private val abbrev = obj.section(".debug_abbrev")
    private val maxUnits = 100_000
    private val maxDiesPerCu = 10_000_000

    fun parse(): List<CompilationUnit> {
        if (info == null) return emptyList()
        val cus = mutableListOf<CompilationUnit>()
        val r = ByteReader(info, 0, info.size, obj.littleEndian)
        var guard = 0
        while (!r.exhausted) {
            if (++guard > maxUnits) {
                obj.issues += DebugIssue(DebugIssue.Severity.ERROR, "too_many_units", "unit limit reached")
                break
            }
            val cuStart = r.pos
            val cu = tryParseCu(r, cuStart)
            if (cu != null) {
                cus += cu
                if (r.pos < cuStart) throw DwarfFormatException("cursor moved backwards")
            }
            if (r.pos < cuStart) break
        }
        return cus
    }

    private fun tryParseCu(outer: ByteReader, cuStart: Int): CompilationUnit? {
        val ul = try {
            outer.unitLength()
        } catch (e: DwarfFormatException) {
            obj.issues += DebugIssue(DebugIssue.Severity.ERROR, "bad_unit_length", e.message ?: "?", cuStart.toLong(), ".debug_info")
            return null
        }
        val end = ul.end.coerceAtMost(outer.limit)
        if (end > outer.limit) {
            obj.issues += DebugIssue(DebugIssue.Severity.ERROR, "truncated_unit", "unit at $cuStart overruns section", cuStart.toLong())
        }
        val r = outer.slice(cuStart + (if (ul.is64Bit) 12 else 4), end - (cuStart + (if (ul.is64Bit) 12 else 4)))
        val version = try { r.u16() } catch (e: DwarfFormatException) {
            obj.issues += issue(cuStart, "truncated_unit_header", e); return finish(outer, end, null)
        }
        val unitType: Int
        var debugAbbrevOffset: Long
        val addressSize: Int
        var dwoId: ULong? = null
        when {
            version >= 5 -> {
                unitType = r.u8()
                addressSize = r.u8()
                debugAbbrevOffset = if (ul.is64Bit) r.u64() else r.u32()
                when (unitType) {
                    DW.UT_SKELETON, DW.UT_SPLIT_COMPILE, DW.UT_SPLIT_TYPE -> {
                        dwoId = r.u64().toULong()
                    }
                    DW.UT_TYPE -> {
                        r.u64() // type signature
                        if (ul.is64Bit) r.u64() else r.u32() // type offset
                    }
                }
            }
            else -> {
                debugAbbrevOffset = if (ul.is64Bit) r.u64() else r.u32()
                addressSize = r.u8()
                unitType = DW.UT_COMPILE
            }
        }
        if (addressSize !in 1..8) {
            obj.issues += issue(cuStart, "bad_address_size", "address_size=$addressSize")
            return finish(outer, end, null)
        }

        val abbrevs: List<AbbrevDecl> = try {
            if (abbrev == null) throw DwarfFormatException("missing .debug_abbrev")
            AbbrevParser.parse(abbrev, debugAbbrevOffset, obj.littleEndian)
        } catch (e: DwarfFormatException) {
            obj.issues += issue(cuStart, "bad_abbrev", e)
            val cu = CompilationUnit(
                obj, cuStart.toLong(), ul.length, ul.is64Bit, version, unitType, addressSize,
                debugAbbrevOffset, emptyList(), emptyList(), Die(null as CompilationUnit?, 0, 0, 0, emptyMap()),
            ).apply { corrupt = true }
            cu.issues += DebugIssue(DebugIssue.Severity.ERROR, "bad_abbrev", e.message ?: "?")
            return finish(outer, end, cu)
        }
        val byCode = abbrevs.associateBy { it.code }

        // DIE tree
        val dies = mutableListOf<Die>()
        var root: Die? = null
        val cuShim = CompilationUnit(
            obj, cuStart.toLong(), ul.length, ul.is64Bit, version, unitType, addressSize,
            debugAbbrevOffset, abbrevs, dies, Die(null as CompilationUnit?, 0, 0, 0, emptyMap()),
        ).apply { this.dwoId = dwoId }
        var corrupt = false
        var dieGuard = 0
        try {
            var depth = 0
            val stack = ArrayDeque<Die>()
            while (!r.exhausted) {
                if (++dieGuard > maxDiesPerCu) throw DwarfFormatException("DIE limit exceeded")
                val dieOff = cuStart + (if (ul.is64Bit) 12 else 4) + (r.pos - r.start)
                val code = r.uleb128()
                if (code == 0UL) {
                    if (depth == 0) break
                    depth--
                    stack.removeLastOrNull()
                    continue
                }
                val decl = byCode[code]
                    ?: throw DwarfFormatException("abbrev code $code not found in table")
                val attrs = readAttributes(r, decl, cuShim)
                val die = Die(cuShim, dieOff.toLong(), decl.tag, depth, attrs)
                if (root == null) root = die
                stack.lastOrNull()?.children?.add(die)
                die.parent = stack.lastOrNull()
                dies += die
                if (decl.hasChildren) {
                    depth++
                    stack.addLast(die)
                }
            }
        } catch (e: DwarfFormatException) {
            corrupt = true
            cuShim.issues += DebugIssue(DebugIssue.Severity.ERROR, "die_parse", e.message ?: "?")
        }

        if (root == null) {
            corrupt = true
            cuShim.issues += DebugIssue(DebugIssue.Severity.ERROR, "no_root_die", "CU at $cuStart has no DIEs")
            val stub = Die(cuShim, 0, DW.TAG_COMPILE_UNIT, 0, emptyMap())
            root = stub
        }
        cuShim.corrupt = corrupt
        classify(cuShim)
        return finish(outer, end, cuShim)
    }

    private fun finish(outer: ByteReader, end: Int, cu: CompilationUnit?): CompilationUnit? {
        outer.seek(end)
        return cu
    }

    private fun classify(cu: CompilationUnit) {
        val root = cu.root
        val dwoNameAttr = root.attr(DW.AT_DWO_NAME)?.asString(obj, cu)
            ?: root.attr(DW.AT_GNU_DWO_NAME)?.asString(obj, cu)
        cu.dwoName = dwoNameAttr
        cu.isSkeleton = cu.unitType == DW.UT_SKELETON ||
            (cu.version <= 4 && dwoNameAttr != null && cu.obj.section(".debug_addr") != null &&
                root.attr(DW.AT_GNU_DWO_ID) != null)
        cu.isSplit = cu.unitType == DW.UT_SPLIT_COMPILE || cu.unitType == DW.UT_SPLIT_TYPE ||
            cu.obj.isDwo
    }

    private fun issue(off: Int, kind: String, e: Exception) =
        DebugIssue(DebugIssue.Severity.ERROR, kind, e.message ?: "?", off.toLong(), ".debug_info")

    private fun readAttributes(r: ByteReader, decl: AbbrevDecl, cu: CompilationUnit): Map<Int, AttrValue> {
        val out = LinkedHashMap<Int, AttrValue>(decl.attrs.size)
        for ((attr, form) in decl.attrs) {
            out[attr] = readForm(r, form, cu, decl.implicitConst)
        }
        return out
    }

    private fun readForm(r: ByteReader, form: Int, cu: CompilationUnit, implicitConst: Long?): AttrValue {
        val addrSize = cu.addressSize
        return when (form) {
            DW.FORM_ADDR -> AttrValue.Addr(addrRead(r, addrSize))
            DW.FORM_DATA1 -> AttrValue.Constant(r.u8().toLong())
            DW.FORM_DATA2 -> AttrValue.Constant(r.u16().toLong())
            DW.FORM_DATA4 -> AttrValue.Constant(r.u32())
            DW.FORM_DATA8 -> AttrValue.Constant(r.u64())
            DW.FORM_SDATA -> AttrValue.Constant(r.sleb128())
            DW.FORM_UDATA -> AttrValue.UConstant(r.uleb128())
            DW.FORM_STRING -> AttrValue.Str(r.nullTerminatedString())
            DW.FORM_STRP -> AttrValue.StrPtr(if (cu.is64BitDwarf()) r.u64() else r.u32(), false)
            DW.FORM_LINE_STRP -> AttrValue.StrPtr(if (cu.is64BitDwarf()) r.u64() else r.u32(), true)
            DW.FORM_SEC_OFFSET -> AttrValue.SecOffset(if (cu.is64BitDwarf()) r.u64() else r.u32())
            DW.FORM_FLAG -> AttrValue.Constant(r.u8().toLong())
            DW.FORM_FLAG_PRESENT -> AttrValue.Flag
            DW.FORM_REF1 -> AttrValue.Ref(r.u8().toULong(), global = false)
            DW.FORM_REF2 -> AttrValue.Ref(r.u16().toULong(), global = false)
            DW.FORM_REF4 -> AttrValue.Ref(r.u32().toULong(), global = false)
            DW.FORM_REF8 -> AttrValue.Ref(r.u64().toULong(), global = false)
            DW.FORM_REF_UDATA -> AttrValue.Ref(r.uleb128(), global = true)
            DW.FORM_REF_ADDR -> AttrValue.Ref(if (cu.is64BitDwarf()) r.u64().toULong() else r.u32().toULong(), global = true)
            DW.FORM_REF_SIG8 -> AttrValue.Ref(r.u64().toULong(), global = false, signature = true)
            DW.FORM_BLOCK1 -> AttrValue.Block(r.bytes(r.u8()))
            DW.FORM_BLOCK2 -> AttrValue.Block(r.bytes(r.u16()))
            DW.FORM_BLOCK4 -> AttrValue.Block(r.bytes(r.u32().toIntChecked4()))
            DW.FORM_BLOCK -> { val n = r.uleb128().toIntCheckedU(); AttrValue.Block(r.bytes(n)) }
            DW.FORM_EXPRLOC -> { val n = r.uleb128().toIntCheckedU(); AttrValue.Block(r.bytes(n)) }
            DW.FORM_DATA16 -> AttrValue.Block(r.bytes(16))
            DW.FORM_IMPLICIT_CONST -> AttrValue.Constant(implicitConst ?: 0L)
            DW.FORM_STRX, DW.FORM_GNU_STR_INDEX -> AttrValue.StrIndex(r.uleb128())
            DW.FORM_STRX1 -> AttrValue.StrIndex(r.u8().toULong())
            DW.FORM_STRX2 -> AttrValue.StrIndex(r.u16().toULong())
            DW.FORM_STRX3 -> AttrValue.StrIndex(r.u32().toULong())
            DW.FORM_STRX4 -> AttrValue.StrIndex(r.u64().toULong())
            DW.FORM_ADDRX, DW.FORM_GNU_ADDR_INDEX -> AttrValue.AddrIndex(r.uleb128())
            DW.FORM_ADDRX1 -> AttrValue.AddrIndex(r.u8().toULong())
            DW.FORM_ADDRX2 -> AttrValue.AddrIndex(r.u16().toULong())
            DW.FORM_ADDRX3 -> AttrValue.AddrIndex(r.u32().toULong())
            DW.FORM_ADDRX4 -> AttrValue.AddrIndex(r.u64().toULong())
            DW.FORM_RNGLISTX, DW.FORM_LOCLISTX -> AttrValue.RngListIndex(r.uleb128())
            DW.FORM_INDIRECT -> {
                val actual = r.uleb128().toInt()
                if (actual == DW.FORM_INDIRECT) throw DwarfFormatException("nested DW_FORM_indirect")
                readForm(r, actual, cu, implicitConst)
            }
            // Forms that point into supplementary packages we do not consume: isolate the CU
            // rather than guessing a size for an external reference of unknown section layout.
            DW.FORM_STRP_SUP, DW.FORM_GNU_STRP_ALT, DW.FORM_GNU_REF_ALT ->
                throw UnsupportedFormException(form)
            else -> throw UnsupportedFormException(form)
        }
    }

    private fun CompilationUnit.is64BitDwarf() = is64BitDwarf

    private fun addrRead(r: ByteReader, size: Int): Long = when (size) {
        1 -> r.u8().toLong()
        2 -> r.u16().toLong()
        4 -> r.u32()
        8 -> r.u64()
        else -> throw DwarfFormatException("unsupported address size $size")
    }

    private fun Long.toIntChecked4(): Int =
        if (this < 0 || this > 1_000_000_000L) throw DwarfFormatException("block length too big: $this") else toInt()
    private fun ULong.toIntCheckedU(): Int =
        if (this > 1_000_000_000UL) throw DwarfFormatException("uleb length too big: $this") else toInt()
}

class UnsupportedFormException(val form: Int) :
    DwarfFormatException("unsupported DW_FORM 0x${form.toString(16)} (CU isolated; cursor alignment unknown)")
