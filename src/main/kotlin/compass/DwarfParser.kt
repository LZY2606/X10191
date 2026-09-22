package compass

class DwarfParser(private val warnings: MutableList<ParseWarning>) {

    fun parseFile(elf: ElfInfo, reader: ElfReader, fileBytes: ByteArray, fileName: String, fileIndex: Int): RawFile? {
        val store = SectionStore(elf, reader, fileBytes)
        if (store.bytes(".debug_info") == null) return null
        val ctx = ParseContext(store, fileName)
        val units = mutableListOf<RawUnit>()
        val dwoIds = HashMap<Long, Int>()
        val info = store.bytes(".debug_info")!!
        var pos = 0
        while (pos < info.size) {
            val unitStart = pos
            try {
                val (unit, next) = parseUnit(ctx, info, pos, fileIndex)
                units.add(unit)
                unit.dwoId?.let { dwoIds[it] = units.size - 1 }
                pos = next
            } catch (e: Exception) {
                warnings.add(ParseWarning("info", "error", "$fileName: CU at $unitStart abandoned: ${e.message}"))
                break
            }
        }
        val pf = ParsedFile(
            fileName = fileName, kind = "elf", buildId = elf.buildId,
            elfClass = if (elf.is64) "ELF64" else "ELF32", machine = elf.machine,
            sha256 = ElfReader.sha256(fileBytes), sections = elf.sections, loads = elf.loads,
            cus = emptyList(), hasDwarf = true,
        )
        return RawFile(pf, ctx, units, warnings, dwoIds)
    }

    private fun parseUnit(ctx: ParseContext, info: ByteArray, start: Int, fileIndex: Int): Pair<RawUnit, Int> {
        val c = ByteCursor(info, start, info.size, ".debug_info")
        val (is64, unitEnd) = RangeReader.readInitialLength(c)
        val b = CompilationUnitBuilder(offsetSize = if (is64) 8 else 4)
        b.version = c.u16()
        b.dwarf5 = b.version >= 5
        val unitWarnings = mutableListOf<String>()

        if (b.dwarf5) {
            b.unitType = c.u8()
            b.addressSize = c.u8()
            b.segmentSelectorSize = c.u8()
            b.abbrevOffset = sizedOffset(c, b.offsetSize)
            if (b.unitType == Dw.UT_TYPE || b.unitType == Dw.UT_SPLIT_TYPE) {
                c.u64() // type signature
                sizedOffset(c, b.offsetSize) // type DIE offset
            }
        } else {
            b.abbrevOffset = sizedOffset(c, b.offsetSize)
            b.addressSize = c.u8()
            b.unitType = Dw.UT_COMPILE
        }

        val abbrevSection = ctx.store.bytes(".debug_abbrev")
            ?: ctx.altCtx?.store?.bytes(".debug_abbrev")
            ?: throw CursorException(".debug_abbrev section missing")
        val abbrev = AbbrevParser.parse(abbrevSection, b.abbrevOffset.toInt(), warnings)
        if (abbrev.warnings.isNotEmpty()) unitWarnings.addAll(abbrev.warnings)

        ctx.cu = b
        val dies = LinkedHashMap<Long, RawDie>()
        val stack = ArrayDeque<Long>()
        var depth = 0
        var dieCount = 0
        var rootOffset = -1L

        while (c.pos < unitEnd) {
            val dieOff = c.pos.toLong()
            val code = c.uleb()
            if (code == 0L) {
                depth--
                stack.removeLastOrNull()
                if (depth == 0) break
                if (depth < 0) throw CursorException("DIE nesting underflow at offset $dieOff")
                continue
            }
            val ab = abbrev.entries[code] ?: throw CursorException("abbrev code $code not found at offset $dieOff")
            if (++dieCount > Limits.MAX_DIES_PER_CU) throw CursorException("DIE count exceeds limit")
            if (depth > Limits.MAX_DIE_DEPTH) throw CursorException("DIE depth exceeds limit")
            val parent = stack.lastOrNull()
            val die = RawDie(dieOff, ab.tag, depth, parent)
            if (rootOffset < 0) rootOffset = dieOff

            for (aa in ab.attrs) {
                val value = readAttr(ctx, c, b, aa.formCode, aa.implicitConst, dieOff, unitWarnings)
                die.attrs.add(RawAttr(aa.nameCode, aa.formCode, value, displayValue(value)))
            }
            dies[dieOff] = die
            parent?.let { dies[it]?.children?.add(dieOff) }

            // Root DIE contributes bases used by later DIEs' indexed forms.
            if (depth == 0) {
                die.at(Dw.AT_LOW_PC)?.let { (it.value as? TargetAddress)?.let { a -> b.rootLowPc = a.offset } }
                (die.at(Dw.AT_ADDR_BASE)?.value as? Long)?.let { b.addrBase = it }
                (die.at(Dw.AT_GNU_ADDR_BASE)?.value as? Long)?.let { b.addrBase = it }
                (die.at(Dw.AT_STR_OFFSETS_BASE)?.value as? Long)?.let { b.strOffsetsBase = it }
                (die.at(Dw.AT_GNU_STR_OFFSETS_BASE)?.value as? Long)?.let { b.strOffsetsBase = it }
                (die.at(Dw.AT_RNGLISTS_BASE)?.value as? Long)?.let { b.rnglistsBase = it }
                (die.at(Dw.AT_GNU_RANGES_BASE)?.value as? Long)?.let { b.rnglistsBase = it }
                (die.at(Dw.AT_DWO_ID)?.value as? Long)?.let { b.dwoId = it }
                (die.at(Dw.AT_DWO_NAME)?.value as? String)?.let { b.dwoName = it }
            }

            if (ab.hasChildren) {
                stack.addLast(dieOff)
                depth++
            }
        }
        if (depth != 0 || stack.isNotEmpty()) throw CursorException("CU at $start: DIE tree not terminated (depth=$depth)")
        if (rootOffset < 0) throw CursorException("CU at $start has no root DIE")
        if (c.pos != unitEnd) {
            unitWarnings.add("CU has ${unitEnd - c.pos} trailing bytes")
        }

        val unit = RawUnit(fileIndex, start.toLong(), b.offsetSize, b.addressSize, b.segmentSelectorSize,
            b.version, b.dwarf5, b.unitType, b.abbrevOffset, b.dwoId, b.dwoName,
            b.strOffsetsBase, b.addrBase, b.rnglistsBase, dies, rootOffset, unitWarnings)
        ctx.cu = null
        return unit to unitEnd
    }

    private fun readAttr(
        ctx: ParseContext, c: ByteCursor, b: CompilationUnitBuilder,
        form: Long, implicit: Long?, dieOffset: Long, unitWarnings: MutableList<String>,
        hops: Int = 0,
    ): Any? {
        if (hops > Limits.MAX_INDIRECT_HOPS) throw CursorException("DW_FORM_indirect hop limit at DIE $dieOffset")
        return when (form) {
            Dw.FORM_ADDR -> TargetAddress(c.address(b.addressSize))
            Dw.FORM_BLOCK1 -> c.bytes(c.u8())
            Dw.FORM_BLOCK2 -> c.bytes(c.u16())
            Dw.FORM_BLOCK4 -> c.bytes(c.u32().toInt())
            Dw.FORM_BLOCK -> c.bytes(c.uleb().toInt())
            Dw.FORM_EXPRLOC -> c.bytes(c.uleb().toInt())
            Dw.FORM_DATA1 -> c.fixed(1)
            Dw.FORM_DATA2 -> c.fixed(2)
            Dw.FORM_DATA4 -> c.fixed(4)
            Dw.FORM_DATA8 -> c.fixed(8)
            Dw.FORM_DATA16 -> c.bytes(16)
            Dw.FORM_SDATA -> c.sleb()
            Dw.FORM_UDATA -> c.uleb()
            Dw.FORM_FLAG -> c.u8().toLong()
            Dw.FORM_FLAG_PRESENT -> 1L
            Dw.FORM_STRING -> c.cString()
            Dw.FORM_STRP -> ctx.readString(".debug_str", sizedOffset(c, b.offsetSize))
            Dw.FORM_LINE_STRP -> ctx.readString(".debug_line_str", sizedOffset(c, b.offsetSize))
            Dw.FORM_GNU_STRP_ALT -> {
                val off = sizedOffset(c, b.offsetSize)
                try { ctx.altCtx!!.readString(".debug_str", off) }
                catch (e: Exception) { UnresolvedRef(off, "gnu_strp_alt") }
            }
            Dw.FORM_REF_ADDR -> UnresolvedRef(sizedOffset(c, b.offsetSize), "ref_addr")
            Dw.FORM_REF1 -> UnresolvedRef(c.u8().toLong(), "ref_cu")
            Dw.FORM_REF2 -> UnresolvedRef(c.u16().toLong(), "ref_cu")
            Dw.FORM_REF4 -> UnresolvedRef(c.u32(), "ref_cu")
            Dw.FORM_REF8 -> UnresolvedRef(c.u64(), "ref_cu")
            Dw.FORM_REF_UDATA -> UnresolvedRef(c.uleb(), "ref_cu")
            Dw.FORM_REF_SUP4 -> { c.u32(); UnresolvedRef(0, "ref_sup") }
            Dw.FORM_REF_SUP8 -> { c.u64(); UnresolvedRef(0, "ref_sup") }
            Dw.FORM_REF_SIG8 -> { c.u64(); UnresolvedRef(0, "ref_sig8") }
            Dw.FORM_SEC_OFFSET -> sizedOffset(c, b.offsetSize)
            Dw.FORM_STRX, Dw.FORM_GNU_STR_INDEX -> readIndexedStringSafe(ctx, c.uleb(), unitWarnings)
            Dw.FORM_STRX1 -> readIndexedStringSafe(ctx, c.u8().toLong(), unitWarnings)
            Dw.FORM_STRX2 -> readIndexedStringSafe(ctx, c.u16().toLong(), unitWarnings)
            Dw.FORM_STRX3 -> readIndexedStringSafe(ctx, c.u32(), unitWarnings)
            Dw.FORM_STRX4 -> readIndexedStringSafe(ctx, c.u64(), unitWarnings)
            Dw.FORM_ADDRX, Dw.FORM_GNU_ADDR_INDEX -> readAddrSafe(ctx, c.uleb(), unitWarnings)
            Dw.FORM_ADDRX1 -> readAddrSafe(ctx, c.u8().toLong(), unitWarnings)
            Dw.FORM_ADDRX2 -> readAddrSafe(ctx, c.u16().toLong(), unitWarnings)
            Dw.FORM_ADDRX3 -> readAddrSafe(ctx, c.u32(), unitWarnings)
            Dw.FORM_ADDRX4 -> readAddrSafe(ctx, c.u64(), unitWarnings)
            Dw.FORM_RNGLISTX -> c.uleb()
            Dw.FORM_LOCLISTX -> { c.uleb(); UnresolvedRef(0, "loclistx") }
            Dw.FORM_IMPLICIT_CONST -> implicit ?: throw CursorException("implicit_const without value")
            Dw.FORM_INDIRECT -> {
                val actual = c.uleb()
                if (!FormReader.isSkippable(actual))
                    throw CursorException("unknown form ${Dw.formName(actual)} behind DW_FORM_indirect; CU isolated")
                readAttr(ctx, c, b, actual, null, dieOffset, unitWarnings, hops + 1)
            }
            else -> throw CursorException("unknown/unhandled form ${Dw.formName(form)} at DIE $dieOffset; CU isolated to avoid desync")
        }
    }

    private fun sizedOffset(c: ByteCursor, size: Int): Long = if (size == 8) c.u64() else c.u32()

    private fun readIndexedStringSafe(ctx: ParseContext, idx: Long, unitWarnings: MutableList<String>): Any? =
        try { ctx.readIndexedString(idx) }
        catch (e: Exception) {
            unitWarnings.add("strx index $idx unresolvable: ${e.message}")
            "<strx:$idx>"
        }

    private fun readAddrSafe(ctx: ParseContext, idx: Long, unitWarnings: MutableList<String>): Any? =
        try { ctx.readAddrIndex(idx) }
        catch (e: Exception) {
            unitWarnings.add("addrx index $idx unresolvable: ${e.message}")
            UnresolvedRef(idx, "addrx")
        }

    private fun displayValue(v: Any?): String = when (v) {
        null -> "null"
        is TargetAddress -> v.hex
        is ByteArray -> "<block ${v.size}B>"
        is UnresolvedRef -> "<unresolved:${v.kind}:0x${TargetAddress.unsignedHex(v.target)}>"
        else -> v.toString()
    }
}
