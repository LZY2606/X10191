package compass.model

import kotlinx.serialization.Serializable

@Serializable
data class SectionInfo(
    val index: Int,
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val sha256: String,
)

@Serializable
data class RangeInfo(val begin: Long, val end: Long) {
    val width: Long get() = end - begin
}

@Serializable
data class LineRowInfo(
    val address: Long,
    val file: Int,
    val fileName: String?,
    val line: Long,
    val column: Long,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val endSequence: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Long,
    val discriminator: Long,
    val sequence: Int,
)

@Serializable
data class FunctionInfo(
    val dieOffset: Long,
    val parentDieOffset: Long?,
    val tag: Long,
    val name: String?,
    val ranges: List<RangeInfo>,
    val callFile: String?,
    val callLine: Long?,
    val callColumn: Long?,
    val depth: Int,
    val inlineStatus: Long?,
)

@Serializable
data class CuInfo(
    val id: Long = 0,
    val offset: Long,
    val dwarfVersion: Int,
    val unitType: Int,
    val addrSize: Int,
    val name: String?,
    val compDir: String?,
    val producer: String?,
    val lowPc: Long?,
    val ranges: List<RangeInfo>,
    val isSkeleton: Boolean,
    val dwoName: String?,
    val warnings: List<String>,
    val lineVersion: Int?,
    val lineFiles: List<String>,
    val lineDirs: List<String>,
    val rows: List<LineRowInfo>,
    val functions: List<FunctionInfo>,
)

@Serializable
data class ParsedModule(
    val sections: List<SectionInfo>,
    val cus: List<CuInfo>,
    val warnings: List<String>,
)

/** A parsed module plus its identity/version in the store. */
data class IndexedModule(
    val fileId: Long,
    val name: String,
    val version: Int,
    val sha256: String,
    val parsed: ParsedModule,
)
