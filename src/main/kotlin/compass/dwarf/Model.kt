@file:Suppress("ArrayInDataClass")
package compass.dwarf

import compass.util.U64
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ParseIssue(
    val severity: String, // "error" | "warning" | "info"
    val code: String,
    val message: String,
    val section: String? = null,
    val offset: U64? = null,
    val cuOffset: U64? = null
)

@Serializable
sealed interface AttrValue {
    @Serializable @SerialName("addr") data class Addr(val a: U64) : AttrValue
    @Serializable @SerialName("uconst") data class UConst(val v: U64) : AttrValue
    @Serializable @SerialName("sconst") data class SConst(val v: Long) : AttrValue
    @Serializable @SerialName("str") data class Str(val v: String) : AttrValue
    @Serializable @SerialName("expr") data class Expr(val bytesHex: String, val baseAddress: U64?) : AttrValue
    @Serializable @SerialName("secoff") data class SecOff(val v: U64) : AttrValue
    @Serializable @SerialName("ref") data class Ref(val v: U64) : AttrValue
    @Serializable @SerialName("flag") data class Flag(val on: Boolean) : AttrValue
    @Serializable @SerialName("addrx") data class AddrIndex(val index: U64) : AttrValue
    @Serializable @SerialName("rnglistx") data class RngListIndex(val index: U64) : AttrValue
    @Serializable @SerialName("loclistx") data class LocListIndex(val index: U64) : AttrValue
}

@Serializable
data class AddrRange(
    val start: U64,
    val end: U64,
    val segment: Int = 0,
    val source: String = ""
) {
    val zeroLength: Boolean get() = start.compareTo(end) == 0
    fun contains(segment: Int, addr: U64): Boolean =
        this.segment == segment && start <= addr && addr < end
    fun containsEndInclusive(segment: Int, addr: U64): Boolean =
        this.segment == segment && start <= addr && addr <= end && start != end
}

@Serializable
data class Die(
    val offset: U64,
    val parentOffset: U64?,
    val childOffsets: List<U64> = emptyList(),
    val depth: Int,
    val tag: Int,
    val name: String?,
    val linkageName: String? = null,
    val inlineCode: Int? = null,
    val declarationFile: String? = null,
    val declarationLine: Int? = null,
    val callFile: String? = null,
    val callLine: Int? = null,
    val abstractOrigin: U64? = null,
    val specification: U64? = null,
    val ranges: List<AddrRange> = emptyList(),
    val attrs: Map<Int, AttrValue> = emptyMap()
)

@Serializable
data class CompilationUnit(
    val index: Int,
    val dwarfVersion: Int,
    val unitType: Int?,
    val dwarf64: Boolean,
    val offset: U64,
    val unitLength: Long,
    val headerSize: Int,
    val abbrevOffset: U64?,
    val addressSize: Int,
    val segmentSelectorSize: Int = 0,
    val kind: String, // full | skeleton | split
    val name: String?,
    val compDir: String?,
    val dwoId: U64?,
    val dwoName: String?,
    val strOffsetsBase: U64?,
    val addrBase: U64?,
    val rnglistsBase: U64?,
    val loclistsBase: U64?,
    val stmtList: U64?,
    val dies: List<Die>,
    val issues: List<ParseIssue> = emptyList(),
    val parsedCompletely: Boolean
)

@Serializable
data class LineFile(val path: String, val directory: String?, val size: U64?, val mtime: U64?)

@Serializable
data class LineRow(
    val address: U64,
    val segment: Int,
    val opIndex: Int,
    val fileIndex: Int,
    val line: Int,
    val column: Int,
    val isStmt: Boolean,
    val basicBlock: Boolean,
    val prologueEnd: Boolean,
    val epilogueBegin: Boolean,
    val isa: Int,
    val discriminator: Int,
    val endSequence: Boolean,
    val trigger: String
)

@Serializable
data class LineSequence(
    val startRow: Int,
    val endRow: Int,
    val segment: Int,
    val startAddress: U64,
    val endAddress: U64
)

@Serializable
data class LineProgram(
    val cuOffset: U64,
    val cuIndex: Int,
    val dwarfVersion: Int,
    val minInstructionLength: Int,
    val maxOpsPerInstruction: Int,
    val defaultIsStmt: Boolean,
    val lineBase: Int,
    val lineRange: Int,
    val opcodeBase: Int,
    val directories: List<String>,
    val files: List<LineFile>,
    val rows: List<LineRow>,
    val sequences: List<LineSequence>,
    val issues: List<ParseIssue> = emptyList(),
    val parsedCompletely: Boolean
)
