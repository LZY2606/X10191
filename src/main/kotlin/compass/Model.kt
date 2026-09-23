package compass

import java.security.MessageDigest

/**
 * 领域模型：ELF/DWARF 解析与地址解析结果。
 *
 * - 字节偏移显式区分 section 内偏移与全局文件偏移。
 * - 解析问题记录为 ParseIssue，不使用异常中断整个文件。
 * - 结论带 Confidence，缺 dwo / section 损坏时仍给出降级答案。
 */

enum class Confidence { EXACT, RELIABLE, DEGRADED, UNKNOWN }

enum class DwarfVersion { V4, V5, OTHER }

class DwarfSections(
    val info: ByteArray = ByteArray(0),
    val abbrev: ByteArray = ByteArray(0),
    val line: ByteArray = ByteArray(0),
    val str: ByteArray = ByteArray(0),
    val lineStr: ByteArray = ByteArray(0),
    val ranges: ByteArray = ByteArray(0),
    val rnglists: ByteArray = ByteArray(0),
    val addr: ByteArray = ByteArray(0),
    val strOffsets: ByteArray = ByteArray(0),
    val loc: ByteArray = ByteArray(0),
    val cuIndex: Map<String, ByteArray> = emptyMap(),
) {
    fun sectionByName(name: String): ByteArray? = when (name) {
        ".debug_info" -> info
        ".debug_abbrev" -> abbrev
        ".debug_line" -> line
        ".debug_str" -> str
        ".debug_line_str" -> lineStr
        ".debug_ranges" -> ranges
        ".debug_rnglists" -> rnglists
        ".debug_addr" -> addr
        ".debug_str_offsets" -> strOffsets
        ".debug_loc" -> loc
        else -> cuIndex[name]
    }
}

data class ElfSection(
    val name: String,
    val nameIndex: Int,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val entsize: Long,
) {
    val isAllocated: Boolean get() = (flags and 0x2L) != 0L
}

data class ProgramHeader(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
)

data class ElfFile(
    val pathHint: String,
    val elfClass: Int,
    val dataEncoding: Int,
    val machine: Int,
    val entry: Long,
    val sections: List<ElfSection>,
    val segments: List<ProgramHeader>,
    val dwarf: DwarfSections,
    val sectionBytes: Map<String, ByteArray>,
    val sha256: String,
    val byteLength: Long,
    val isDebugFile: Boolean,
    val issues: MutableList<ParseIssue> = mutableListOf(),
) {
    fun section(name: String): ElfSection? = sections.firstOrNull { it.name == name }

    fun fileOffsetForVaddr(vaddr: Long): Long? {
        for (seg in segments) {
            if (seg.type != 1) continue
            if (vaddr in seg.vaddr until seg.vaddr + seg.filesz) {
                return seg.offset + (vaddr - seg.vaddr)
            }
        }
        for (s in sections) {
            if (s.addr != 0L && vaddr in s.addr until s.addr + s.size) {
                return s.offset + (vaddr - s.addr)
            }
        }
        return null
    }

    fun debugBytes(name: String): ByteArray = dwarf.sectionByName(name) ?: ByteArray(0)
}

data class ParseIssue(
    val severity: Severity,
    val where: String,
    val message: String,
    val recoverable: Boolean = true,
) {
    enum class Severity { WARNING, ERROR, ISOLATED }
}

fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
