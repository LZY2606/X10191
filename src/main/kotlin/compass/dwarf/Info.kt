package compass.dwarf

import java.nio.ByteOrder

class Die(
    val offset: Long,
    val tag: Int,
    val attrs: Map<Int, AttrValue>,
    val depth: Int,
) {
    val children = mutableListOf<Die>()
    fun attr(at: Int): AttrValue? = attrs[at]
    fun name(): String? = attrs[Dw.AT_name]?.asString()
}

class CompilationUnit(
    val unitOffset: Long,          // offset of the unit header in .debug_info
    val dieOffset: Long,           // offset where DIEs begin
    val unitEnd: Long,             // offset just past this unit
    val version: Int,
    val unitType: Int,             // UT_compile for DWARF<=4
    val addrSize: Int,
    val abbrevOffset: Long,
    val is64Dwarf: Boolean,
) {
    val roots = mutableListOf<Die>()
    var error: String? = null      // set when the CU was isolated / truncated
    val notes = mutableListOf<String>()

    val isolated: Boolean get() = error != null
}

/**
 * Parses .debug_info into compilation units. A unit that hits an unknown form
 * or corrupt data is isolated: its remaining bytes are skipped using the
 * length in its own header, so later units still parse cleanly.
 */
class DebugInfoParser(
    private val info: ByteArray,
    private val abbrev: ByteArray?,
    private val formCtx: (version: Int, addrSize: Int, is64: Boolean) -> FormContext,
    private val order: ByteOrder,
) {
    val units = mutableListOf<CompilationUnit>()
    val globalNotes = mutableListOf<String>()

    fun parse(): List<CompilationUnit> {
        var pos = 0
        var guard = 0
        while (pos + 4 <= info.size) {
            if (++guard > 1_000_000) { globalNotes += "unit count limit hit"; break }
            val unitStart = pos
            try {
                pos = parseUnit(pos)
            } catch (e: DwarfParseException) {
                globalNotes += "unit at 0x${unitStart.toString(16)} dropped: ${e.message}"
                break // cannot know unit length reliably; stop section walk
            }
            if (pos <= unitStart) break // paranoia: always make progress
        }
        return units
    }

    /** Returns the offset just past this unit. */
    private fun parseUnit(pos: Int): Int {
        val c = Cursor(info, pos, info.size, order)
        var length = c.u32()
        val is64 = length == 0xFFFFFFFFL
        if (is64) length = c.u64()
        if (length <= 0 || length > Int.MAX_VALUE) throw DwarfParseException("bad unit length $length")
        val unitEnd = (c.pos + length).coerceAtMost(info.size.toLong())
        val truncated = c.pos + length > info.size

        val version = c.u16()
        val unitType: Int
        val addrSize: Int
        val abbrevOff: Long
        if (version >= 5) {
            unitType = c.u8()
            addrSize = c.u8()
            abbrevOff = c.uintN(if (is64) 8 else 4)
        } else {
            unitType = Dw.UT_compile
            abbrevOff = c.uintN(if (is64) 8 else 4)
            addrSize = c.u8()
        }
        val cu = CompilationUnit(
            pos.toLong(), c.pos.toLong(), unitEnd, version, unitType, addrSize, abbrevOff, is64,
        )
        units += cu
        if (truncated) cu.notes += "unit length exceeds section; truncated"
        if (abbrev == null) {
            cu.error = "no .debug_abbrev section"
            return unitEnd.toInt()
        }
        val decls = try {
            AbbrevTable.parse(abbrev, abbrevOff.toInt(), order)
        } catch (e: DwarfParseException) {
            cu.error = "abbrev table unreadable: ${e.message}"
            return unitEnd.toInt()
        }
        val ctx = formCtx(version, addrSize, is64)
        try {
            parseDies(cu, c, decls, ctx, unitEnd.toInt())
        } catch (e: UnknownFormException) {
            // Isolate: do NOT guess the form's size. The rest of this CU is
            // untrusted; the cursor realigns at the next unit via unitEnd.
            cu.error = "unknown ${e.message}; CU isolated to keep cursor aligned"
            cu.roots.clear()
        } catch (e: DwarfParseException) {
            cu.error = "parse stopped: ${e.message}"
        }
        return unitEnd.toInt()
    }

    private fun parseDies(
        cu: CompilationUnit,
        c: Cursor,
        decls: Map<Long, AbbrevDecl>,
        ctx: FormContext,
        unitEnd: Int,
    ) {
        // Stack of (die with children). Null markers terminate sibling lists.
        val stack = ArrayDeque<Die>()
        var count = 0
        while (c.pos < unitEnd) {
            if (++count > Dw.MAX_DIES_PER_CU) throw DwarfParseException("DIE count limit exceeded")
            val dieOff = c.pos
            val code = c.uleb()
            if (code == 0L) {
                if (stack.isEmpty()) {
                    // Stray null; tolerate at top level by finishing.
                    if (c.pos >= unitEnd) break
                } else stack.removeLast()
                continue
            }
            val decl = decls[code] ?: throw DwarfParseException(
                "abbrev code $code not declared (DIE at 0x${dieOff.toString(16)})")
            if (stack.size >= Dw.MAX_DIE_DEPTH) throw DwarfParseException("DIE depth limit exceeded")
            val attrs = LinkedHashMap<Int, AttrValue>()
            for (spec in decl.attrs) {
                var v = ctx.decode(spec.form, c) // UnknownFormException propagates -> isolate CU
                if (spec.implicitConst != null) v = AttrValue.SData(spec.implicitConst)
                attrs[spec.name] = v
            }
            val die = Die(dieOff.toLong(), decl.tag, attrs, stack.size)
            if (stack.isEmpty()) cu.roots += die else stack.last().children += die
            if (decl.hasChildren) stack.addLast(die)
        }
    }
}
