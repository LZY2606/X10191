package compass.dwarf

import compass.elf.ElfFile
import compass.elf.ElfSection
import java.security.MessageDigest

/**
 * Raw DWARF sections extracted from one ELF plus the bytes digest summary.
 * Missing sections are null; a section present but truncated is still loaded
 * and the per-section parser reports a localized error.
 */
class DwarfSections(val elf: ElfFile) {
    val info = elf.sectionBytesOrNull(".debug_info")
    val abbrev = elf.sectionBytesOrNull(".debug_abbrev")
    val line = elf.sectionBytesOrNull(".debug_line")
    val lineStr = elf.sectionBytesOrNull(".debug_line_str")
    val str = elf.sectionBytesOrNull(".debug_str")
    val ranges = elf.sectionBytesOrNull(".debug_ranges")
    val rnglists = elf.sectionBytesOrNull(".debug_rnglists")
    val addr = elf.sectionBytesOrNull(".debug_addr")
    val strOffsets = elf.sectionBytesOrNull(".debug_str_offsets")
    val loclists = elf.sectionBytesOrNull(".debug_loclists")

    /** Map of every section the importer recognized, with digest summary. */
    val summaries: List<SectionSummary> = buildList {
        for (s in elf.sections) {
            if (s.name.startsWith(".debug") || s.name == ".text" ||
                s.name == ".symtab" || s.name == ".strtab"
            ) {
                val ok = s.size == 0L || runCatching { elf.sectionBytes(s) }.isSuccess
                add(
                    SectionSummary(
                        name = s.name,
                        addr = s.addr,
                        offset = s.offset,
                        size = s.size,
                        sha256 = if (ok && s.size > 0) {
                            val bytes = runCatching { elf.sectionBytes(s) }.getOrNull()
                            bytes?.let { MessageDigest.getInstance("SHA-256").digest(it).toHex() }
                        } else null,
                        truncated = !ok,
                    )
                )
            }
        }
    }.sortedBy { it.offset }
}

fun ByteArray.toHex(): String {
    val sb = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xff
        sb.append("0123456789abcdef"[v ushr 4])
        sb.append("0123456789abcdef"[v and 0xf])
    }
    return sb.toString()
}

data class SectionSummary(
    val name: String,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val sha256: String?,
    val truncated: Boolean,
)

/** A parsed attribute value in its "raw" section-relative encoding. */
sealed class RawValue {
    data class Addr(val v: Long) : RawValue()
    data class UInt(val v: Long) : RawValue()
    data class SInt(val v: Long) : RawValue()
    data class Bytes(val v: ByteArray) : RawValue() {
        override fun equals(other: Any?) = other is Bytes && v.contentEquals(other.v)
        override fun hashCode() = v.contentHashCode()
    }
    data class StrInline(val v: String) : RawValue()
    /** .debug_str offset / .debug_line_str offset / .debug_str_offsets index. */
    data class StrPtr(val section: StrSection, val offset: Long) : RawValue()
    data class StrIndex(val index: Long, val baseOffset: Long) : RawValue()
    data class Ref(val target: Long, val kind: RefKind) : RawValue()
    /** addrx with the CU's resolved .debug_addr base. */
    data class AddrIndex(val index: Long) : RawValue()
    data class RngListIndex(val index: Long) : RawValue()
    data object FlagPresent : RawValue()
    data object Unknown : RawValue()
}

enum class StrSection { DEBUG_STR, DEBUG_LINE_STR, STR_OFFSETS_INDIRECT }
enum class RefKind { INFO_ABS, UNIT_REL, REF_ADDR }

/**
 * A DIE as parsed from .debug_info: offset relative to .debug_info start,
 * tag, parent/children and attributes that may still need resolution.
 */
class Die(
    val offset: Long,
    val tag: Int,
    val abbrevCode: Long,
    val cuIndex: Int,
    val attrs: Map<Int, RawValue>,
) {
    var parent: Die? = null
    val children = mutableListOf<Die>()

    fun attr(a: Int): RawValue? = attrs[a]
    fun hasAttr(a: Int): Boolean = attrs.containsKey(a)

    /** DIE chain from the CU root down to this DIE (inclusive). */
    fun chain(): List<Die> = buildList {
        var d: Die? = this@Die
        while (d != null) {
            add(d)
            d = d.parent
        }
    }.reversed()

    /** inline depth: number of inlined_subroutine DIEs on the chain incl self. */
    fun inlineDepth(): Int =
        chain().count { it.tag == DW.TAG_inlined_subroutine }
}

data class UnitHeader(
    val index: Int,
    val version: Int,
    val unitType: Int,
    val is64Bit: Boolean,
    val unitStart: Long,
    val unitLength: Long,
    val unitEnd: Long,
    val debugAbbrevOffset: Long,
    val addressSize: Int,
    val segmentSize: Int = 0,
    val firstDie: Long = 0,
    val dwoId: Long? = null,
    val typeSignature: Long = 0L,
    val typeOffset: Long = 0L,
)

class CompileUnit(
    val header: UnitHeader,
    val root: Die?,
    val dies: List<Die>,
    val dieByOffset: Map<Long, Die>,
    val warnings: List<String>,
    /** "skeleton", "split", or "full". */
    val splitKind: String,
    val dwoName: String?,
    val lineTableOffset: Long,
) {
    val version get() = header.version
    val index get() = header.index

    fun dieAt(globalOffset: Long): Die? = dieByOffset[globalOffset]
}

/** One resolved [start,end) address range, possibly zero length. */
data class AddressRange(
    val start: Long,
    val end: Long,
    val segment: Int = 0,
    val source: String,
    val zeroLength: Boolean = end <= start,
)

/** Resolved ranges of a DIE, with the source description ("low/high_pc", "rnglists#3", ...). */
data class DieRanges(val ranges: List<AddressRange>)
