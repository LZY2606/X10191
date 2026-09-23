package compass.dwarf

class Die(
    val offset: Long,
    val tag: Int,
    val depth: Int,
    val attrs: MutableMap<Int, AttrValue> = LinkedHashMap(),
) {
    val children = mutableListOf<Die>()
    var unknownFormIsolated: Int? = null

    fun attr(name: Int): AttrValue? = attrs[name]
    fun strAttr(name: Int, resolve: (AttrValue) -> String?): String? = attrs[name]?.let(resolve)
}

data class DieParseLimits(
    val maxDepth: Int = 64,
    val maxDies: Int = 500_000,
)

/**
 * Parses the DIE tree of one compilation unit.
 * Safety rules:
 *  - recursion depth and DIE count are capped;
 *  - the cursor never leaves the unit's byte range;
 *  - an unknown DW_FORM isolates the rest of that DIE's attribute list and
 *    stops descent into the remaining siblings (cursor realigns to unit end),
 *    so no misaligned bytes are ever interpreted as DIEs.
 */
class DieParser(
    private val info: ByteArray,
    private val unitStart: Int,
    private val unitEnd: Int,
    private val abbrevs: Map<Int, AbbrevDecl>,
    private val decoder: FormDecoder,
    private val limits: DieParseLimits = DieParseLimits(),
    private val bigEndian: Boolean = false,
) {
    var dieCount = 0
        private set
    val warnings = mutableListOf<String>()

    fun parse(): Die? {
        val r = Reader(info, ".debug_info", unitStart, bigEndian)
        return parseDie(r, 0)
    }

    private fun parseDie(r: Reader, depth: Int): Die? {
        if (depth > limits.maxDepth) {
            warnings.add("DIE depth limit ${limits.maxDepth} exceeded at 0x${r.pos.toString(16)}; subtree skipped")
            return null
        }
        if (++dieCount > limits.maxDies) throw DwarfException(".debug_info: DIE count limit exceeded")
        val offset = r.pos.toLong()
        val code = r.uleb128()
        if (code == 0L) return null // null entry: end of sibling list
        val decl = abbrevs[code.toInt()]
            ?: throw DwarfException(".debug_info: abbrev code $code at 0x${offset.toString(16)} not in table")
        val die = Die(offset, decl.tag, depth)
        for (spec in decl.attrs) {
            try {
                val v = decoder.read(r, spec.form)
                die.attrs[spec.name] = if (spec.form == Dw.FORM_implicit_const) AttrValue.SData(spec.implicitConst) else v
            } catch (e: UnknownFormException) {
                // Isolate: record and stop parsing this unit's remaining DIEs.
                die.unknownFormIsolated = e.form
                warnings.add("unknown DW_FORM 0x${e.form.toString(16)} at DIE 0x${offset.toString(16)}; rest of unit isolated")
                r.seek(unitEnd)
                return die
            }
        }
        if (r.pos > unitEnd) throw DwarfException(".debug_info: DIE at 0x${offset.toString(16)} overruns unit end")
        if (decl.hasChildren) {
            while (r.pos < unitEnd) {
                val child = parseDie(r, depth + 1) ?: break
                die.children.add(child)
            }
        }
        return die
    }
}
