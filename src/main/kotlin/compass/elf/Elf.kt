@file:Suppress("ArrayInDataClass")
package compass.elf

import compass.util.U64
import kotlinx.serialization.Serializable

@Serializable
data class SectionInfo(
    val name: String,
    val type: Int,
    val flags: U64,
    val addr: U64,
    val fileOffset: U64,
    val size: U64,
    val link: Int,
    val info: Int,
    val addralign: U64,
    val entsize: U64
)

@Serializable
data class SegmentInfo(
    val type: Int,
    val flags: Int,
    val offset: U64,
    val vaddr: U64,
    val paddr: U64,
    val filesz: U64,
    val memsz: U64,
    val align: U64
) {
    fun contains(addr: U64): Boolean = addr >= vaddr && addr < U64(vaddr.v + memsz.v)
    fun fileRelative(addr: U64): U64? =
        if (contains(addr)) U64(offset.v + (addr.v - vaddr.v)) else null
}

@Serializable
data class SymbolInfo(
    val name: String,
    val value: U64,
    val size: U64,
    val type: Int,
    val bind: Int,
    val sectionIndex: Int,
    val source: String = "symtab"
)

@Serializable
data class ElfSummary(
    val elfClass: Int,
    val endian: String,
    val machine: Int,
    val entry: U64,
    val buildId: String?,
    val sections: List<SectionInfo>,
    val segments: List<SegmentInfo>,
    val symbols: List<SymbolInfo>
)

@Serializable
data class RawSection(val name: String, val bytesHex: String, val size: Int)

@Serializable
data class ParsedElf(
    val summary: ElfSummary,
    /** Debug/DWARF related section raw bytes only, keyed by section name. */
    val sectionBytes: Map<String, ByteArray>
) {
    fun section(name: String): ByteArray? = sectionBytes[name]
}
