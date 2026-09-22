package compass.dwarf

/** Raw section bytes plus identity digest, captured at import time. */
data class SectionInfo(
    val name: String,
    val offset: Long,
    val size: Long,
    val sha256: String,
    val data: ByteArray,
)

data class AttrEnt(val attr: Int, val form: Int, val value: AttrValue)

class Die(
    val offset: Long, // relative to .debug_info start
    val tag: Int,
    val depth: Int,
    val attrs: List<AttrEnt>,
) {
    val children = ArrayList<Die>()
    fun attr(attr: Int): AttrEnt? = attrs.firstOrNull { it.attr == attr }
}

data class DieInfo(
    val offset: Long,
    val parentOffset: Long,
    val depth: Int,
    val tag: Int,
    val name: String?,
    val lowPc: Long?,
    val highPc: Long?,
    val ranges: List<AddrRange>,
    val callFile: Long?,
    val callLine: Long?,
)

data class ParsedCu(
    val offset: Long,
    val version: Int,
    val unitType: Int,
    val dwarf64: Boolean,
    val addrSize: Int,
    val name: String?,
    val compDir: String?,
    val producer: String?,
    val lowPc: Long?,
    val highPc: Long?,
    val ranges: List<AddrRange>,
    val skeleton: Boolean,
    val dwoMissing: Boolean,
    val truncated: Boolean,
    val fromDwo: Boolean,
    val lineVersion: Int?,
    val rows: List<LineRow>,
    val dies: List<DieInfo>,
    val warnings: List<String>,
)

data class ParsedFile(
    val sections: List<SectionInfo>,
    val cus: List<ParsedCu>,
    val warnings: List<String>,
)
