package compass.dwarf

import compass.elf.ByteReader

/** One abbreviation declaration. */
class Abbrev(
    val code: Long,
    val tag: Int,
    val hasChildren: Boolean,
    /** attr -> form pairs in declaration order */
    val specs: List<Pair<Int, Int>>,
    /** implicit const value indexed like [specs] for FORM_implicit_const */
    val implicitConsts: Map<Int, Long>,
)

/**
 * Abbreviation tables keyed by their offset in .debug_abbrev.
 *
 * Parsing is defensive: an unknown form is tolerated here (the DIE decoder
 * decides whether it can skip the value safely), but a truncated abbrev
 * section raises and is isolated to the CU that referenced that table.
 */
class AbbrevTables(private val data: ByteArray?) {
    private val cache = HashMap<Long, Map<Long, Abbrev>>()
    private val failures = HashMap<Long, String>()

    fun tableAt(offset: Long): Map<Long, Abbrev> {
        cache[offset]?.let { return it }
        failures[offset]?.let { throw DwarfParseException("abbrev table @$offset: $it") }
        if (data == null) throw DwarfParseException(".debug_abbrev section missing")
        val r = ByteReader(data, offset.toInt(), ByteReader.Endian.LITTLE, 0)
        val table = LinkedHashMap<Long, Abbrev>()
        while (true) {
            val code = r.uleb()
            if (code == 0L) break
            val tag = r.ulebInt()
            val child = r.u1() == 1
            val specs = ArrayList<Pair<Int, Int>>()
            val implicits = HashMap<Int, Long>()
            while (true) {
                val attr = r.ulebInt()
                val form = r.ulebInt()
                if (attr == 0 && form == 0) break
                specs += attr to form
                if (form == DW.FORM_implicit_const) {
                    implicits[attr] = r.sleb()
                }
            }
            if (table.containsKey(code)) throw DwarfParseException("duplicate abbrev code $code")
            table[code] = Abbrev(code, tag, child, specs, implicits)
        }
        cache[offset] = table
        return table
    }

    fun known(offset: Long): Boolean = cache.containsKey(offset)
}

class DwarfParseException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
