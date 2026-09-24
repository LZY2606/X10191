package compass.dwarf

import compass.elf.ElfModel

class InfoParser(
    private val sections: SectionSet,
    private val elf: ElfModel,
    private val fileIndex: Int,
    private val infoSectionName: String = ".debug_info",
) {
    private val info: ByteArray = sections[infoSectionName]
        ?: throw ParseException("缺少 $infoSectionName")
    private val abbrev: ByteArray = sections.require(".debug_abbrev")
    private val str: ByteArray = sections[".debug_str"] ?: ByteArray(0)
    private val lineStr: ByteArray = sections[".debug_line_str"] ?: ByteArray(0)
    private val le: Boolean = elf.endian == 1

    private val abbrevCache = HashMap<Long, AbbrevTable>()
    private val strOffsetsCache = HashMap<Long, IntArray>()

    fun parse(): List<CompUnit> {
        val units = mutableListOf<CompUnit>()
        var cuIndex = 0
        val r = BinReader(info, 0, le)
        while (r.remaining() > 0) {
            val cuStart = r.pos
            val unit = try {
                parseCu(r, cuIndex, cuStart)
            } catch (e: ParseException) {
                CompUnit(
                    index = cuIndex, fileIndex = fileIndex, offset = cuStart.toLong(), length = 0,
                    dwarf64 = false, version = 0, unitType = 0, addressSize = 4, abbrevOffset = -1,
                    dwoId = null, stmtList = null, strOffsetsBase = null, addrBase = null,
                    rnglistsBase = null, rootName = null, compDir = null, producer = null,
                    dies = emptyList(), lineProgram = null, error = e.message ?: "解析失败",
                )
            }
            units.add(unit)
            // 下一个 CU：靠 length 字段推进；损坏时停止整个 section，避免游标错位产生伪结果
            if (unit.length <= 0) break
            r.seek((cuStart + unit.length).toInt())
            cuIndex++
        }
        return units
    }

    private fun readInitialLength(r: BinReader): Pair<Boolean, Long> {
        val v = r.u32()
        return if (v == 0xffffffffL) true to r.u64() else false to v
    }

    private fun parseCu(r: BinReader, cuIndex: Int, cuStart: Int): CompUnit {
        val (dwarf64, unitLen) = readInitialLength(r)
        val length = (r.pos - cuStart) + unitLen
        val offsetSize = if (dwarf64) 8 else 4
        val version = r.u16()
        var unitType = 0
        var addressSize = 4
        var debugAbbrevOffset: Long
        if (version >= 5) {
            unitType = r.u8()
            addressSize = r.u8()
            debugAbbrevOffset = r.readOffset(offsetSize)
        } else {
            debugAbbrevOffset = r.readOffset(offsetSize)
            addressSize = r.u8()
        }
        val dwoId: Long? = if (version >= 5 && (unitType == DW_UT.SKELETON || unitType == DW_UT.SPLIT_COMPILE ||
                unitType == DW_UT.SPLIT_TYPE || unitType == DW_UT.TYPE)) r.u64() else null

        val table = abbrevCache.getOrPut(debugAbbrevOffset) {
            AbbrevTable.parse(abbrev, debugAbbrevOffset)
        }

        val dies = mutableListOf<Die>()
        var depth = 0
        var parentStack = ArrayDeque<Int>()
        var rootSeen = false
        var parseError: String? = null
        try {
            while (r.pos < cuStart + length) {
                val diePos = r.pos
                val code = r.uleb()
                if (code == 0L) {
                    if (parentStack.isNotEmpty()) parentStack.removeLast()
                    depth--
                    if (depth < 0) break
                    continue
                }
                val decl = table.get(code)
                    ?: throw ParseException("CU 中出现 abbrev 表外的 code=$code", diePos.toLong())
                val attrs = readAttrs(r, decl, addressSize, dwarf64, cuStart.toLong())
                val parentOff = parentStack.lastOrNull()?.toLong()
                val die = Die(diePos.toLong(), decl.tag, depth, parentOff, attrs = attrs)
                if (parentOff != null) dies[parentStack.last()].childOffsets.add(die.offset)
                dies.add(die)
                if (decl.hasChildren) {
                    parentStack.addLast(dies.size - 1)
                    depth++
                }
                rootSeen = true
            }
        } catch (e: UnknownFormException) {
            parseError = e.message
        } catch (e: ParseException) {
            parseError = e.message
        }

        val root = dies.firstOrNull()
        fun strAttr(a: Int) = (root?.attr(a) as? AttrValue.Str)?.v
        val stmtList = (root?.attr(DW_AT.STMT_LIST) as? AttrValue.Data)?.v
        val strOffBase = (root?.attr(DW_AT.STR_OFFSETS_BASE) as? AttrValue.Data)?.v
        val addrBase = (root?.attr(DW_AT.ADDR_BASE) as? AttrValue.Data)?.v
            ?: (root?.attr(DW_AT.GNU_ADDR_BASE) as? AttrValue.Data)?.v
        val rngBase = (root?.attr(DW_AT.RNGLISTS_BASE) as? AttrValue.Data)?.v
            ?: (root?.attr(DW_AT.GNU_RANGES_BASE) as? AttrValue.Data)?.v
        return CompUnit(
            index = cuIndex, fileIndex = fileIndex, offset = cuStart.toLong(), length = length,
            dwarf64 = dwarf64, version = version, unitType = unitType, addressSize = addressSize,
            abbrevOffset = debugAbbrevOffset, dwoId = dwoId, stmtList = stmtList,
            strOffsetsBase = strOffBase, addrBase = addrBase, rnglistsBase = rngBase,
            rootName = strAttr(DW_AT.NAME), compDir = strAttr(DW_AT.COMP_DIR),
            producer = strAttr(DW_AT.PRODUCER), dies = dies, lineProgram = null, error = parseError,
        )
    }

    private fun BinReader.readOffset(width: Int): Long = uword(width)

    private fun readAttrs(
        r: BinReader, decl: AbbrevDecl, addressSize: Int, dwarf64: Boolean, cuStart: Long,
    ): Map<Int, AtVal> {
        val out = linkedMapOf<Int, AtVal>()
        for (a in decl.attrs) {
            val indirect = if (a.form == DW_FORM.INDIRECT) r.uleb().toInt() else 0
            val value = readForm(r, a.form, a.implicitConst, addressSize, dwarf64, cuStart, out, indirect)
            out[a.name] = AtVal(if (a.form == DW_FORM.INDIRECT) indirect else a.form, value)
        }
        return out
    }

    private fun readForm(
        r: BinReader, formIn: Int, implicitConst: Long?, addressSize: Int, dwarf64: Boolean,
        cuStart: Long, prior: Map<Int, AtVal>, indirectForm: Int = 0,
    ): AttrValue {
        val form = if (formIn == DW_FORM.INDIRECT) indirectForm else formIn
        return when (form) {
            DW_FORM.ADDR -> AttrValue.Addr(r.uword(addressSize))
            DW_FORM.DATA1, DW_FORM.REF1 -> dataOrRef(r, 1, form, cuStart, dwarf64)
            DW_FORM.DATA2, DW_FORM.REF2 -> dataOrRef(r, 2, form, cuStart, dwarf64)
            DW_FORM.DATA4, DW_FORM.REF4 -> dataOrRef(r, 4, form, cuStart, dwarf64)
            DW_FORM.DATA8 -> AttrValue.Data(r.uword(8))
            DW_FORM.REF8 -> AttrValue.Ref(r.uword(8))
            DW_FORM.REF_UDATA, DW_FORM.REF_ADDR -> AttrValue.Ref(r.uword(if (dwarf64) 8 else 4))
            DW_FORM.UDATA -> AttrValue.Data(r.uleb())
            DW_FORM.SDATA -> AttrValue.Data(r.sleb())
            DW_FORM.FLAG -> AttrValue.Data(if (r.u8() != 0) 1 else 0)
            DW_FORM.FLAG_PRESENT -> AttrValue.Data(1)
            DW_FORM.SEC_OFFSET -> AttrValue.Data(r.uword(if (dwarf64) 8 else 4))
            DW_FORM.STRING -> AttrValue.Str(r.cstring())
            DW_FORM.STRP -> AttrValue.Str(BinReader(str).seek(r.uword(if (dwarf64) 8 else 4).toInt()).cstring())
            DW_FORM.LINE_STRP -> AttrValue.Str(BinReader(lineStr).seek(r.uword(if (dwarf64) 8 else 4).toInt()).cstring())
            DW_FORM.EXPRLOC -> AttrValue.ExprLoc(r.take(r.uleb().toInt()))
            DW_FORM.BLOCK -> AttrValue.Block(r.take(r.uleb().toInt()))
            DW_FORM.BLOCK1 -> AttrValue.Block(r.take(r.u8()))
            DW_FORM.BLOCK2 -> AttrValue.Block(r.take(r.u16()))
            DW_FORM.BLOCK4 -> AttrValue.Block(r.take(r.u32().toInt()))
            DW_FORM.REF_SIG8 -> AttrValue.Signature(r.uword(8))
            DW_FORM.DATA16 -> AttrValue.Block(r.take(16))
            DW_FORM.IMPLICIT_CONST -> AttrValue.Data(implicitConst ?: 0)
            DW_FORM.STRX, DW_FORM.STRX1, DW_FORM.STRX2, DW_FORM.STRX3, DW_FORM.STRX4 -> {
                val width = strxWidth(form)
                AttrValue.StrIndex(r.uint(width))
            }
            DW_FORM.ADDRX, DW_FORM.ADDRX1, DW_FORM.ADDRX2, DW_FORM.ADDRX3, DW_FORM.ADDRX4 -> {
                val width = addrxWidth(form)
                AttrValue.AddrIndex(r.uint(width))
            }
            else -> throw UnknownFormException(form, r.pos.toLong())
        }
    }

    private fun strxWidth(form: Int) = when (form) {
        DW_FORM.STRX1 -> 1; DW_FORM.STRX2 -> 2; DW_FORM.STRX3 -> 3; DW_FORM.STRX4 -> 4
        else -> 0 // ULEB
    }
    private fun addrxWidth(form: Int) = when (form) {
        DW_FORM.ADDRX1 -> 1; DW_FORM.ADDRX2 -> 2; DW_FORM.ADDRX3 -> 3; DW_FORM.ADDRX4 -> 4
        else -> 0
    }

    private fun dataOrRef(r: BinReader, width: Int, form: Int, cuStart: Long, dwarf64: Boolean): AttrValue {
        val raw = r.uword(width)
        return when (form) {
            DW_FORM.REF1, DW_FORM.REF2, DW_FORM.REF4 -> AttrValue.Ref(cuStart + raw)
            else -> AttrValue.Data(raw)
        }
    }

    private fun BinReader.uint(width: Int): Long = if (width == 0) uleb() else uword(width)
}
