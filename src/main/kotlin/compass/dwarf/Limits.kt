package compass.dwarf

/** Hard caps preventing pathological or malicious debug data from exhausting resources. */
object Limits {
    const val MAX_DIE_DEPTH = 64
    const val MAX_DIES_PER_UNIT = 200_000
    const val MAX_ABBREV_DECLS = 100_000
    const val MAX_ATTRS_PER_DIE = 256
    const val MAX_UNITS = 100_000
    const val MAX_LINE_OPCODES = 5_000_000
    const val MAX_LINE_ROWS = 1_000_000
    const val MAX_RANGES_PER_DIE = 100_000
    const val MAX_RANGE_LISTS = 500_000
    const val MAX_REF_HOPS = 8
    const val MAX_LINE_FILES = 1_000_000
}
