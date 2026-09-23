package compass.dwarf

class UnknownFormException(val form: Int, at: Long) :
    Exception("unknown DWARF form 0x${form.toString(16)} at offset 0x${at.toString(16)}")

class DwarfParseException(message: String) : Exception(message)

data class AbbrevDecl(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    val attrs: List<Pair<Int, Int>>,
    val implicitConsts: Map<Int, Long>,
)

object Limits {
    const val MAX_DEPTH = 128
    const val MAX_DIES_PER_CU = 500_000
    const val MAX_ABBREV_DECLS = 65_536
    const val MAX_ABBREV_ATTRS = 4_096
    const val MAX_INDIRECT = 8
    const val MAX_REF_FOLLOW = 16
    const val MAX_RANGE_ENTRIES = 1_000_000
    const val MAX_LINE_ROWS = 2_000_000
}

/** Parsed .debug_abbrev table starting at [offset]. */
class AbbrevTable(val decls: Map<Long, AbbrevDecl>) {
    fun decl(code: Long): AbbrevDecl? = decls[code]

    companion object {
        fun parse(bytes: ByteArray, offset: Long, littleEndian: Boolean): AbbrevTable {
            if (offset < 0 || offset >= bytes.size) throw DwarfParseException("abbrev offset 0x${offset.toString(16)} outside .debug_abbrev")
            val r = ByteReader(bytes, offset.toInt(), bytes.size, littleEndian)
            val decls = LinkedHashMap<Long, AbbrevDecl>()
            while (r.hasRemaining()) {
                if (decls.size >= Limits.MAX_ABBREV_DECLS) throw DwarfParseException("too many abbrev declarations")
                val code = r.uleb()
                if (code == 0L) break
                val tag = r.uleb().toInt()
                val hasChildren = r.u8() == 1
                val attrs = ArrayList<Pair<Int, Int>>()
                val implicit = HashMap<Int, Long>()
                while (true) {
                    if (attrs.size >= Limits.MAX_ABBREV_ATTRS) throw DwarfParseException("too many abbrev attributes")
                    val attr = r.uleb().toInt()
                    val form = r.uleb().toInt()
                    if (attr == 0 && form == 0) break
                    attrs.add(attr to form)
                    if (form == Form.IMPLICIT_CONST) implicit[attr] = r.sleb()
                }
                decls[code] = AbbrevDecl(code, tag, hasChildren, attrs, implicit)
            }
            return AbbrevTable(decls)
        }
    }
}

/** All debug sections a CU parse may consult. Absent sections map to null. */
class DebugSections(val map: Map<String, ByteArray>, val littleEndian: Boolean) {
    fun get(name: String): ByteArray? = map[name]
    fun reader(name: String): ByteReader? = map[name]?.let { ByteReader(it, 0, it.size, littleEndian) }
}

class CuContext(
    val cuOffset: Long,
    val version: Int,
    val addressSize: Int,
    val offsetSize: Int,
    val littleEndian: Boolean,
)

/** Parses .debug_info into compilation units with bounded recursion and isolation of damage. */
class DebugInfoParser(
    private val sections: DebugSections,
    private val notes: MutableList<String>,
) {
    private val infoBytes = sections.get(".debug_info")
        ?: throw DwarfParseException("no .debug_info section")
    private val abbrevBytes = sections.get(".debug_abbrev")
        ?: throw DwarfParseException("no .debug_abbrev section")
    private val little = sections.littleEndian
    private val abbrevCache = HashMap<Long, AbbrevTable>()

    fun parse(): List<CompilationUnit> {
        val units = ArrayList<CompilationUnit>()
        val r = ByteReader(infoBytes, 0, infoBytes.size, little)
        var index = 0
        while (r.remaining >= 4) {
            val unitStart = r.pos
            try {
                val cu = parseUnit(r, unitStart, index)
                if (cu != null) units.add(cu)
                index++
            } catch (e: Exception) {
                notes.add("CU at 0x${unitStart.toString(16)}: ${e.message}; skipped to next unit")
                // Resync: we cannot know the unit length if the header itself is broken.
                if (e is DwarfParseException && e.message?.contains("unit length") == true) break
                break
            }
        }
        if (r.remaining in 1..3) notes.add("${r.remaining} trailing bytes in .debug_info ignored")
        return units
    }

    private fun parseUnit(r: ByteReader, unitStart: Int, index: Int): CompilationUnit? {
        var length = r.u32()
        val is64 = length == 0xFFFFFFFFL
        if (is64) length = r.u64()
        val offsetSize = if (is64) 8 else 4
        if (length <= 0 || unitStart.toLong() + (if (is64) 12 else 4) + length > infoBytes.size) {
            throw DwarfParseException("bad unit length $length at 0x${unitStart.toString(16)}")
        }
        val unitEnd = (unitStart + (if (is64) 12 else 4) + length).toInt()
        val version = r.u16()
        if (version < 2 || version > 5) throw DwarfParseException("unsupported DWARF version $version")
        var unitType = 0x01 // DW_UT_compile
        var addressSize: Int
        var abbrevOffset: Long
        if (version >= 5) {
            unitType = r.u8()
            addressSize = r.u8()
            abbrevOffset = r.uN(offsetSize)
        } else {
            abbrevOffset = r.uN(offsetSize)
            addressSize = r.u8()
        }
        if (addressSize != 4 && addressSize != 8) throw DwarfParseException("unsupported address size $addressSize")
        val cu = CompilationUnit(unitStart.toLong(), version, unitType, addressSize, abbrevOffset, is64, index)
        val ctx = CuContext(unitStart.toLong(), version, addressSize, offsetSize, little)
        val abbrevs = abbrevCache.getOrPut(abbrevOffset) {
            AbbrevTable.parse(abbrevBytes, abbrevOffset, little)
        }
        try {
            val dieParser = DieParser(ctx, abbrevs, cu.notes)
            cu.root = dieParser.parseTree(r, unitEnd)
        } catch (e: Exception) {
            cu.degraded = true
            cu.notes.add("DIE parse stopped: ${e.message}")
        }
        if (cu.root == null) {
            cu.degraded = true
            cu.notes.add("no root DIE parsed")
        } else {
            CuAttributeResolver(sections, cu).resolve()
        }
        // Always resync the outer cursor to the declared unit end.
        r.pos = unitEnd
        return cu
    }

    private inner class DieParser(
        private val ctx: CuContext,
        private val abbrevs: AbbrevTable,
        private val cuNotes: MutableList<String>,
    ) {
        private var dieCount = 0
        var unknownFormHit: String? = null

        fun parseTree(r: ByteReader, unitEnd: Int): Die? {
            var root: Die? = null
            // Top-level loop: sibling CUs' roots are handled by caller; here one root plus
            // any stray top-level DIEs are attached under a synthetic guard.
            while (r.pos < unitEnd) {
                val die = parseDie(r, 0, unitEnd) ?: break
                if (root == null) root = die else {
                    // Extra top-level DIEs: keep them reachable via a synthetic root list.
                    root.children.add(die)
                    die.parent = root
                }
                if (r.pos >= unitEnd) break
            }
            return root
        }

        private fun parseDie(r: ByteReader, depth: Int, unitEnd: Int): Die? {
            if (depth > Limits.MAX_DEPTH) throw DwarfParseException("DIE nesting deeper than ${Limits.MAX_DEPTH}")
            if (dieCount >= Limits.MAX_DIES_PER_CU) throw DwarfParseException("too many DIEs in CU")
            if (r.pos >= unitEnd) return null
            val entryOffset = r.pos
            val code = r.uleb()
            if (code == 0L) return null
            val decl = abbrevs.decl(code)
                ?: throw DwarfParseException("DIE at 0x${entryOffset.toString(16)} references unknown abbrev code $code")
            dieCount++
            val absolute = entryOffset.toLong() // absolute offset inside .debug_info
            val fixed = Die(absolute, decl.tag, depth, code)
            for ((attr, form) in decl.attrs) {
                try {
                    val value = readForm(r, form, decl.implicitConsts[attr], 0)
                    fixed.attrs[attr] = value
                } catch (e: UnknownFormException) {
                    fixed.truncated = true
                    cuNotes.add("DIE 0x${absolute.toString(16)}: isolated unknown ${Form.name(e.form)}; remaining attributes and children skipped")
                    return fixed
                }
            }
            if (decl.hasChildren) {
                while (r.pos < unitEnd) {
                    val child = parseDie(r, depth + 1, unitEnd) ?: break
                    fixed.children.add(child)
                    child.parent = fixed
                }
            }
            return fixed
        }

        private fun readForm(r: ByteReader, formIn: Int, implicitConst: Long?, indirections: Int): AttrValue {
            var form = formIn
            if (form == Form.INDIRECT) {
                if (indirections >= Limits.MAX_INDIRECT) throw DwarfParseException("DW_FORM_indirect chain too long")
                val actual = r.uleb().toInt()
                return readForm(r, actual, implicitConst, indirections + 1)
            }
            if (form !in Form.KNOWN) throw UnknownFormException(form, r.pos.toLong())
            return when (form) {
                Form.ADDR -> AttrValue.Addr(r.uN(ctx.addressSize))
                Form.BLOCK1 -> AttrValue.Block(r.bytes(r.u8()))
                Form.BLOCK2 -> AttrValue.Block(r.bytes(r.u16()))
                Form.BLOCK4 -> AttrValue.Block(r.bytes(r.u32().toInt()))
                Form.BLOCK, Form.EXPRLOC -> AttrValue.Block(r.bytes(r.uleb().toInt()))
                Form.DATA1 -> AttrValue.UInt(r.u8().toLong())
                Form.DATA2 -> AttrValue.UInt(r.u16().toLong())
                Form.DATA4 -> AttrValue.UInt(r.u32())
                Form.DATA8 -> AttrValue.UInt(r.u64())
                Form.DATA16 -> AttrValue.Block(r.bytes(16))
                Form.SDATA -> AttrValue.SInt(r.sleb())
                Form.UDATA -> AttrValue.UInt(r.uleb())
                Form.STRING -> AttrValue.Str(r.cstring())
                Form.STRP -> AttrValue.Strp(r.uN(ctx.offsetSize))
                Form.LINE_STRP -> AttrValue.LineStrp(r.uN(ctx.offsetSize))
                Form.STRP_SUP -> AttrValue.Strp(r.uN(ctx.offsetSize))
                Form.FLAG -> AttrValue.Flag(r.u8() != 0)
                Form.FLAG_PRESENT -> AttrValue.Flag(true)
                Form.SEC_OFFSET -> AttrValue.SecOffset(r.uN(ctx.offsetSize))
                Form.REF1 -> AttrValue.Ref(ctx.cuOffset + r.u8())
                Form.REF2 -> AttrValue.Ref(ctx.cuOffset + r.u16())
                Form.REF4 -> AttrValue.Ref(ctx.cuOffset + r.u32())
                Form.REF8 -> AttrValue.Ref(ctx.cuOffset + r.u64())
                Form.REF_UDATA -> AttrValue.Ref(ctx.cuOffset + r.uleb())
                Form.REF_ADDR -> {
                    val size = if (ctx.version <= 2) ctx.addressSize else ctx.offsetSize
                    AttrValue.Ref(r.uN(size))
                }
                Form.REF_SIG8 -> AttrValue.UInt(r.u64())
                Form.REF_SUP4 -> AttrValue.UInt(r.u32())
                Form.REF_SUP8 -> AttrValue.UInt(r.u64())
                Form.STRX -> AttrValue.StrIndex(r.uleb())
                Form.STRX1 -> AttrValue.StrIndex(r.u8().toLong())
                Form.STRX2 -> AttrValue.StrIndex(r.u16().toLong())
                Form.STRX3 -> AttrValue.StrIndex(readU24(r))
                Form.STRX4 -> AttrValue.StrIndex(r.u32())
                Form.ADDRX -> AttrValue.AddrIndex(r.uleb())
                Form.ADDRX1 -> AttrValue.AddrIndex(r.u8().toLong())
                Form.ADDRX2 -> AttrValue.AddrIndex(r.u16().toLong())
                Form.ADDRX3 -> AttrValue.AddrIndex(readU24(r))
                Form.ADDRX4 -> AttrValue.AddrIndex(r.u32())
                Form.RNGLISTX -> AttrValue.RngListIndex(r.uleb())
                Form.LOCLISTX -> AttrValue.UInt(r.uleb())
                Form.IMPLICIT_CONST -> AttrValue.SInt(implicitConst ?: 0L)
                else -> throw UnknownFormException(form, r.pos.toLong())
            }
        }

        private fun readU24(r: ByteReader): Long {
            val b = r.bytes(3)
            return if (ctx.littleEndian)
                (b[0].toLong() and 0xFF) or ((b[1].toLong() and 0xFF) shl 8) or ((b[2].toLong() and 0xFF) shl 16)
            else
                ((b[0].toLong() and 0xFF) shl 16) or ((b[1].toLong() and 0xFF) shl 8) or (b[2].toLong() and 0xFF)
        }
    }
}
