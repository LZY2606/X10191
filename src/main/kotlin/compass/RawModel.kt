package compass

/** Attribute value before name resolution; Raw.value holds Long/String/ByteArray/TargetAddress/UnresolvedRef. */
data class RawAttr(val atCode: Long, val formCode: Long, val value: Any?, val display: String)

data class RawDie(
    val globalOffset: Long,
    val tag: Long,
    val depth: Int,
    val parent: Long?,
    val children: MutableList<Long> = mutableListOf(),
    val attrs: MutableList<RawAttr> = mutableListOf(),
) {
    fun at(code: Long): RawAttr? = attrs.firstOrNull { it.atCode == code }
}

class UnresolvedRef(val target: Long, val kind: String)

class CompilationUnitBuilder(
    var offsetSize: Int = 8,
    var addressSize: Int = 8,
    var segmentSelectorSize: Int = 0,
) {
    var dwarf5 = false
    var version = 4
    var unitType = Dw.UT_COMPILE
    var abbrevOffset = 0L
    var dwoId: Long? = null
    var dwoName: String? = null
    var strOffsetsBase: Long? = null
    var addrBase: Long? = null
    var rnglistsBase: Long? = null
    var rootLowPc: Long = 0
    lateinit var raw: RawUnit
}

data class RawUnit(
    val fileIndex: Int,
    val headerStart: Long,
    var offsetSize: Int,
    var addressSize: Int,
    var segmentSelectorSize: Int,
    var version: Int,
    var dwarf5: Boolean,
    var unitType: Int,
    var abbrevOffset: Long,
    var dwoId: Long?,
    var dwoName: String?,
    var strOffsetsBase: Long?,
    var addrBase: Long?,
    var rnglistsBase: Long?,
    var dies: LinkedHashMap<Long, RawDie>,
    var rootOffset: Long,
    var warnings: MutableList<String>,
)

data class RawFile(
    val parsedFile: ParsedFile,
    val ctx: ParseContext,
    val units: List<RawUnit>,
    val warnings: MutableList<ParseWarning>,
    val dwoIds: Map<Long, Int>, // dwoId -> unit index (skeletons and splits)
)
