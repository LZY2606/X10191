package compass.dwarf

/** Mutable per-CU state populated from the CU header before DIE parsing. */
class CuInfo(
    var version: Int = 4,
    var dwarf64: Boolean = false,
    var addressSize: Int = 8,
    var segmentSize: Int = 0,
    var unitType: Int = 0,
    var unitStart: Long = 0,
    var abbrevOffset: Long = 0,
    var strOffsetsBase: Long = 0,
    var addrBase: Long = 0,
    var rnglistsBase: Long = 0,
    var isSplit: Boolean = false
)
