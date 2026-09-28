package compass.dwarf

data class SourceFile(val index: Int, val name: String, val directory: String = "", val fullPath: String = name)

data class LineState(
    val address: Long,
    val segment: Long,
    val file: Int,
    val line: Int,
    val column: Int,
    val isStatement: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
    val opIndex: Int
)

data class LineSequence(val start: Long, val end: Long, val segment: Long, val rows: List<LineState>) {
    val width: Long get() = (end - start).coerceAtLeast(0)
}

data class LineProgram(
    val cuOffset: Long?,
    val offset: Long,
    val version: Int,
    val dwarfVersion: Int,
    val addressSize: Int,
    val segmentSize: Int,
    val compilationDirectory: String,
    val files: List<SourceFile>,
    val sequences: List<LineSequence>,
    val warnings: List<String>
)

data class AddressRange(
    val start: Long,
    val end: Long,
    val zeroLength: Boolean = start == end,
    val source: String = "die",
    val priority: Long? = null
) {
    val width: Long get() = (end - start).coerceAtLeast(0)
    fun contains(address: Long): Boolean = if (zeroLength) address == start else address in start until end
}

data class DwarfAttribute(val name: String, val rawTag: Long, val form: String, val rawForm: Long, val value: Any?)

data class Die(
    val offset: Long,
    val tag: String,
    val rawTag: Long,
    val depth: Int,
    val parentOffset: Long?,
    val childOffsets: List<Long>,
    val attributes: List<DwarfAttribute>,
    val ranges: List<AddressRange>,
    val cuOffset: Long,
    val name: String?,
    val callFile: Int?,
    val callLine: Int?,
    val callColumn: Int?,
    val originOffset: Long?,
    val priority: Long?
)

data class CompilationUnit(
    val offset: Long,
    val length: Long,
    val version: Int,
    val unitType: String,
    val addressSize: Int,
    val abbrevOffset: Long,
    val name: String?,
    val compDir: String?,
    val dwoName: String?,
    val dwoId: Long?,
    val dies: List<Die>,
    val warnings: List<String>
)

data class DwarfSections(
    val debugInfo: ByteArray = ByteArray(0),
    val debugAbbrev: ByteArray = ByteArray(0),
    val debugLine: ByteArray = ByteArray(0),
    val debugStr: ByteArray = ByteArray(0),
    val debugLineStr: ByteArray = ByteArray(0),
    val debugRanges: ByteArray = ByteArray(0),
    val debugRnglists: ByteArray = ByteArray(0),
    val debugStrOffsets: ByteArray = ByteArray(0),
    val debugAddr: ByteArray = ByteArray(0)
)

data class DwarfImage(
    val elf: compass.dwarf.ElfSegments
    val sections: DwarfSections,
    val cus: List<CompilationUnit>,
    val linePrograms: List<LineProgram>,
    val warnings: List<String>,
    val fileSha256: String,
    val fileSize: Long
)
