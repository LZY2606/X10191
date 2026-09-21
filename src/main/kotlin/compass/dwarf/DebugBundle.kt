@file:Suppress("ArrayInDataClass")
package compass.dwarf

import compass.elf.ElfSummary
import compass.util.U64
import kotlinx.serialization.Serializable

@Serializable
data class SectionDigest(
    val name: String,
    val size: U64,
    val sha256: String,
    val headHex: String
)

@Serializable
data class DebugBundle(
    val elf: ElfSummary,
    val buildId: String?,
    val contentSha256: String,
    val sections: List<SectionDigest>,
    val cus: List<CompilationUnit>,
    val linePrograms: List<LineProgram>,
    val issues: List<ParseIssue>,
    /** Map skeleton CU offset -> split CU offset within the same bundle (dwo linked at import). */
    val splitLinks: Map<U64, U64>,
    val isDwo: Boolean,
    val dwoIds: List<U64>
)
