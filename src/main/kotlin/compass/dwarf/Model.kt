package compass.dwarf

class AddrRange(val begin: Long, val end: Long, val source: String) {
    val zeroLength: Boolean get() = begin == end
    val width: Long get() = end - begin
    fun contains(addr: Long) = addr in begin until end || (zeroLength && addr == begin)
}

class LineRow(
    val sequence: Int,
    val rowIndex: Int,
    val address: Long,
    val fileIndex: Int,
    val file: String,
    val line: Long,
    val column: Long,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Long,
    val discriminator: Long,
)

class ParsedDie(
    val offset: Long,
    val depth: Int,
    val tag: Long,
    val name: String?,
    val lowPc: Long?,
    val highPc: Long?,
    val ranges: List<AddrRange>,
    val callFileIndex: Int?,
    val callLine: Long?,
    val callColumn: Long?,
    val originName: String?,
    val parentIndex: Int,   // index into ParsedCu.dies, -1 = root
)

class ParsedCu(
    val cuIndex: Int,
    val offset: Long,
    val version: Int,
    val unitType: Int,
    val addrSize: Int,
    val dwarf64: Boolean,
    var name: String?,
    var compDir: String?,
    var producer: String?,
    var lowPc: Long?,
    var highPc: Long?,
    var stmtList: Long?,
    var dwoName: String?,
    var degraded: Boolean,
    val warnings: MutableList<String>,
    val dies: MutableList<ParsedDie>,
    val lineRows: MutableList<LineRow>,
    val files: MutableList<String>,
    var lineVersion: Int = 0,
    var rnglistsVersion: Int = 0,
    var sequences: Int = 0,
)

class ParsedModule(
    val cus: List<ParsedCu>,
    val warnings: List<String>,
    val hasDwoSections: Boolean,
)
