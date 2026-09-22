package compass.dwarf

import compass.elf.ByteReader
import compass.elf.DwarfParseException

/**
 * Parses .debug_info (+ .dwo): CU headers, abbreviations, DIE trees.
 * All LEB/section reads are bounded; unknown forms are isolated as Unsupported while
 * fixed-size forms still consume their bytes, but variable-size unknown forms abort the
 * current CU (never continue with a misaligned cursor).
 */
class DebugInfoParser(
    private val bundle: DebugBundle,
    private val useDwo: Boolean = false
) {
    private val info: ByteArray = (if (useDwo) bundle.infoDwo else bundle.info)
        ?: throw DwarfParseException("no .debug_info${if (useDwo) ".dwo" else ""} section")
    private val abbrevTable: AbbrevTable =
        (if (useDwo) bundle.abbrevDwoTable else bundle.abbrevTable)
            ?: throw DwarfParseException("no .debug_abbrev${if (useDwo) ".dwo" else ""} section")
    private val bigEndian = bundle.elf.bigEndian

    private val globalDies = HashMap<Int, DieNode>()

    fun parse(): List<ParsedCu> {
        val out = ArrayList<ParsedCu>()
        val r = ByteReader(info, bigEndian, if (useDwo) ".debug_info.dwo" else ".debug_info")
        var guard = 0
        while (r.remaining() > 0) {
            if (++guard > 100_000) throw DwarfParseException("too many CUs")
            val cuStart = r.pos
            val unitLength = r.u32()
            val is64: Boolean
            val length: Long
            if (unitLength == 0xffffffffL) {
                is64 = true; length = r.u64()
            } else {
                is64 = false; length = unitLength
            }
            val unitEnd = if (is64) r.pos + length else cuStart + 4 + length
            if (unitEnd <= r.pos || unitEnd > info.size) {
                throw DwarfParseException("CU at 0x${cuStart.toString(16)}: length past section")
            }
            val headerStart = r.pos
            val version = r.u16()
            if (version !in 2..5) throw DwarfParseException("CU at 0x${cuStart.toString(16)}: unsupported version $version")

            var unitType = 0
            var addressSize = 8
            var abbrevOffset = 0L
            when {
                version >= 5 -> {
                    unitType = r.u8()
                    addressSize = r.u8()
                    abbrevOffset = if (is64) r.u64() else r.u32()
                }
                version == 4 -> {
                    abbrevOffset = if (is64) r.u64() else r.u32()
                    addressSize = r.u8()
                }
                else -> {
                    abbrevOffset = if (is64) r.u64() else r.u32()
                    addressSize = r.u8()
                }
            }

            var dwoId = 0L
            if (version >= 5 && (unitType == DW_UT_SPLIT_COMPILE || unitType == DW_UT_SKELETON ||
                        unitType == DW_UT_SPLIT_TYPE)) {
                dwoId = if (is64) r.u64() else r.u32().toLong()
            }
            val headerEnd = r.pos

            val notes = ArrayList<String>()
            val abbrevs = try {
                abbrevTable.tableAt(abbrevOffset.toIntSafe())
            } catch (e: DwarfParseException) {
                notes.add("abbrev table unreadable at 0x${abbrevOffset.toString(16)}: ${e.message}")
                r.seek(unitEnd.toIntSafe())
                out.add(ParsedCu(cuStart, version, unitType, is64, addressSize, headerEnd, unitEnd.toIntSafe(),
                    null, notes, dwoId))
                continue
            }

            val ctx = CuContext(version, is64, addressSize, cuStart, abbrevOffset)
            // DWARF5 default bases: 0 for str_offsets/addr until root DIE overrides.
            val dieReader = ByteReader(info, bigEndian, if (useDwo) ".debug_info.dwo" else ".debug_info")
            dieReader.seek(headerEnd)
            val root = try {
                parseDieTree(dieReader, unitEnd.toIntSafe(), abbrevs, ctx, 0, notes)
            } catch (e: DwarfParseException) {
                notes.add("DIE tree parse aborted: ${e.message}")
                null
            }
            root?.let { register(it) }
            r.seek(unitEnd.toIntSafe())
            out.add(ParsedCu(cuStart, version, unitType, is64, addressSize, headerEnd, unitEnd.toIntSafe(),
                root, notes, dwoId))
        }
        return out
    }

    private fun register(node: DieNode) {
        globalDies[node.offset] = node
        node.children.forEach(::register)
    }

    fun dieAt(globalOffset: Int): DieNode? = globalDies[globalOffset]

    private fun parseDieTree(
        r: ByteReader,
        unitEnd: Int,
        abbrevs: Map<ULong, Abbreviation>,
        ctx: CuContext,
        depth: Int,
        notes: MutableList<String>
    ): DieNode? {
        if (depth > 200) throw DwarfParseException("DIE nesting exceeds 200")
        val offset = r.pos
        val code = r.uleb128()
        if (code == 0UL) return null
        val abbrev = abbrevs[code] ?: throw DwarfParseException("unknown abbrev code $code at 0x${offset.toString(16)}")
        val attrs = HashMap<Int, AttrValue>()
        for (aa in abbrev.attrs) {
            val value = readAttr(aa.form, aa.implicitConst, r, ctx, notes)
            if (value !is AttrValue.Unsupported) attrs[aa.attr] = value
        }
        if (depth == 0) {
            (attrs[DW.AT_STRL_OFFSETS_BASE] as? AttrValue.Constant)?.let { ctx.strOffsetsBase = it.v }
            (attrs[DW.AT_ADDR_BASE] as? AttrValue.Constant)?.let { ctx.addrBase = it.v }
        }
        val children = ArrayList<DieNode>()
        if (abbrev.hasChildren) {
            var n = 0
            while (r.pos < unitEnd) {
                if (++n > 2_000_000) throw DwarfParseException("DIE count budget exceeded")
                if (r.pos + 1 > unitEnd) throw DwarfParseException("child scan overruns CU")
                if (r.data[r.pos].toInt() and 0xff == 0) { r.u8(); break }
                val child = parseDieTree(r, unitEnd, abbrevs, ctx, depth + 1, notes) ?: break
                children.add(child)
            }
        }
        return DieNode(offset, abbrev.tag, attrs, depth, children)
    }

    private fun readAttr(
        form: Int,
        implicitConst: Long,
        r: ByteReader,
        ctx: CuContext,
        notes: MutableList<String>
    ): AttrValue {
        return when (form) {
            DW.FORM_FLAG_PRESENT -> AttrValue.Flags(true)
            DW.FORM_IMPLICIT_CONST -> AttrValue.Constant(implicitConst)
            DW.FORM_FLAG -> AttrValue.Flags(r.u8() != 0)
            DW.FORM_DATA1 -> AttrValue.Constant(r.u8().toLong())
            DW.FORM_DATA2 -> AttrValue.Constant(r.u16().toLong())
            DW.FORM_DATA4 -> AttrValue.Constant(r.u32())
            DW.FORM_DATA8 -> AttrValue.Constant(r.u64())
            DW.FORM_SDATA -> AttrValue.Constant(r.sleb128().toLong())
            DW.FORM_UDATA -> AttrValue.Constant(r.uleb128().toLong())
            DW.FORM_ADDR -> AttrValue.Address(r.readUInt(ctx.addressSize))
            DW.FORM_ADDR2 -> AttrValue.Address(r.u16().toLong())
            DW.FORM_ADDR8 -> AttrValue.Address(r.u64())
            DW.FORM_SEC_OFFSET -> AttrValue.Constant(if (ctx.is64) r.u64() else r.u32())
            DW.FORM_REF1 -> AttrValue.Reference(r.u8())
            DW.FORM_REF2 -> AttrValue.Reference(r.u16())
            DW.FORM_REF4 -> AttrValue.Reference(r.u32().toIntSafe())
            DW.FORM_REF8 -> AttrValue.Reference(r.u64().toIntSafe())
            DW.FORM_REF_UDATA -> AttrValue.Reference(r.uleb128().toLong().toIntSafe())
            DW.FORM_REF_ADDR -> AttrValue.Reference(
                (if (ctx.is64) r.u64() else r.u32()).toIntSafe()
            )
            DW.FORM_STRING -> {
                val s = r.cStringAt(r.pos)
                r.pos += s.toByteArray().size + 1
                AttrValue.StringVal(s)
            }
            DW.FORM_STRP -> readStrp(r, ctx)
            DW.FORM_LINE_STRP -> readLineStrp(r, ctx)
            DW.FORM_STRX, DW.FORM_STRX1, DW.FORM_STRX2, DW.FORM_STRX3, DW.FORM_STRX4,
            DW.FORM_GNU_STR_INDEX -> {
                val idx = readIndexFor(form, r)
                val base = ctx.strOffsetsBase
                resolveStrx(idx, base, ctx, notes)
            }
            DW.FORM_ADDRX, DW.FORM_ADDRX1, DW.FORM_ADDRX2, DW.FORM_ADDRX3, DW.FORM_ADDRX4,
            DW.FORM_GNU_ADDR_X -> {
                val idx = readIndexFor(form, r)
                AttrValue.Address(readAddrx(idx, ctx.addrBase, ctx.addressSize))
            }
            DW.FORM_RNGLISTX, DW.FORM_GNU_RANGELIST_X -> {
                val idx = readIndexFor(form, r)
                AttrValue.Indexed(idx, form)
            }
            DW.FORM_BLOCK1 -> AttrValue.Block(r.bytes(r.u8()))
            DW.FORM_BLOCK2 -> AttrValue.Block(r.bytes(r.u16()))
            DW.FORM_BLOCK4 -> AttrValue.Block(r.bytes(r.u32().toIntSafe()))
            DW.FORM_BLOCK, DW.FORM_EXPRLOC -> AttrValue.Block(r.bytes(r.uleb128().toInt()))
            DW.FORM_DATA16 -> AttrValue.Block(r.bytes(16))
            DW.FORM_REF_SIG8 -> AttrValue.Block(r.bytes(8))
            DW.FORM_INDIRECT -> {
                val real = r.uleb128().toInt()
                if (real == DW.FORM_INDIRECT) throw DwarfParseException("nested DW_FORM_indirect")
                readAttr(real, 0, r, ctx, notes)
            }
            DW.FORM_REF_SUP4 -> AttrValue.Block(r.bytes(4))
            DW.FORM_REF_SUP8 -> AttrValue.Block(r.bytes(8))
            else -> {
                // Unknown variable-length form: cannot know its size — abort CU scan
                // rather than continue misaligned and fabricate DIEs.
                throw DwarfParseException("unknown/unsupported form 0x${form.toString(16)}")
            }
        }
    }

    private fun readIndexFor(form: Int, r: ByteReader): ULong = when (form) {
        DW.FORM_STRX1, DW.FORM_ADDRX1 -> r.u8().toULong()
        DW.FORM_STRX2, DW.FORM_ADDRX2 -> r.u16().toULong()
        DW.FORM_STRX3, DW.FORM_ADDRX3 -> read3Bytes(r)
        DW.FORM_STRX4, DW.FORM_ADDRX4 -> r.u32().toULong()
        else -> r.uleb128()
    }

    private fun read3Bytes(r: ByteReader): ULong =
        (r.u8().toULong()) or (r.u8().toULong() shl 8) or (r.u8().toULong() shl 16)

    private fun readStrp(r: ByteReader, ctx: CuContext): AttrValue.StringVal {
        val off = if (ctx.is64) r.u64() else r.u32()
        var data = if (useDwo) bundle.strDwo else bundle.str
        if (data == null) data = bundle.str
        data = data ?: throw DwarfParseException("DW_FORM_strp but .debug_str missing")
        val sr = ByteReader(data, bigEndian, ".debug_str")
        return AttrValue.StringVal(sr.cStringAt(off.toIntSafe()))
    }

    private fun readLineStrp(r: ByteReader, ctx: CuContext): AttrValue.StringVal {
        val off = if (ctx.is64) r.u64() else r.u32()
        var data = if (useDwo) bundle.lineStrDwo else bundle.valLineStr
        if (data == null) data = bundle.valLineStr
        data = data ?: throw DwarfParseException("DW_FORM_line_strp but .debug_line_str missing")
        val sr = ByteReader(data, bigEndian, ".debug_line_str")
        return AttrValue.StringVal(sr.cStringAt(off.toIntSafe()))
    }

    private fun resolveStrx(idx: ULong, base: Long, ctx: CuContext, notes: MutableList<String>): AttrValue {
        val data = if (useDwo) (bundle.strOffsetsDwo ?: bundle.strOffsets) else bundle.strOffsets
        if (data == null) {
            notes.add("DW_FORM_strx but .debug_str_offsets missing")
            return AttrValue.Unsupported
        }
        val sr = ByteReader(data, bigEndian, ".debug_str_offsets")
        val entrySize = if (ctx.is64) 8 else 4
        val entryOff = (base + idx.toLong() * entrySize).toIntSafe()
        sr.seek(entryOff)
        val strOff = if (ctx.is64) sr.u64() else sr.u32()
        var strData = if (useDwo) bundle.strDwo else bundle.str
        if (strData == null) strData = bundle.str
        if (strData == null) { notes.add("strx target string section missing"); return AttrValue.Unsupported }
        val tr = ByteReader(strData, bigEndian, ".debug_str")
        return AttrValue.StringVal(tr.cStringAt(strOff.toIntSafe()))
    }

    private fun readAddrx(idx: ULong, base: Long, addressSize: Int): Long {
        val data = bundle.addr ?: throw DwarfParseException("DW_FORM_addrx but .debug_addr missing")
        val ar = ByteReader(data, bigEndian, ".debug_addr")
        val off = (base + idx.toLong() * addressSize).toIntSafe()
        ar.seek(off)
        return ar.readUInt(addressSize)
    }

    private fun Long.toIntSafe(): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw DwarfParseException("offset out of 32-bit range")
        return toInt()
    }

    private class CuContext(
        val version: Int,
        val is64: Boolean,
        val addressSize: Int,
        val cuStart: Int,
        val abbrevOffset: Long,
        var strOffsetsBase: Long = 0,
        var addrBase: Long = 0
    )

    companion object {
        const val DW_UT_SKELETON = 0x04
        const val DW_UT_SPLIT_COMPILE = 0x05
        const val DW_UT_SPLIT_TYPE = 0x06
    }
}

data class ParsedCu(
    val start: Int,
    val version: Int,
    val unitType: Int,
    val is64: Boolean,
    val addressSize: Int,
    val headerEnd: Int,
    val unitEnd: Int,
    val root: DieNode?,
    val notes: List<String>,
    val dwoId: Long
)
