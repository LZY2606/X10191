package compass.elf

import java.nio.ByteOrder

/** One section from the ELF section header table. */
data class ElfSection(
    val name: String,
    val type: Int,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val data: ByteArray,
) {
    /** Masked segment address (handles thumb bit etc.). */
    fun contains(vaddr: Long): Boolean = vaddr in addr until addr + size
    override fun equals(other: Any?) = this === other
    override fun hashCode() = System.identityHashCode(this)
}

/** A program header / load segment (PT_LOAD etc.). */
data class ElfSegment(
    val type: Int,
    val flags: Int,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
) {
    val isLoad get() = type == PT_LOAD
    val fileRange get() = offset until offset + filesz
    fun contains(addr: Long) = addr in vaddr until vaddr + memsz
    companion object { const val PT_LOAD = 1 }
}

data class ElfFile(
    val path: String?,
    val elfClass: Int,       // 1 = 32-bit, 2 = 64-bit
    val endian: ByteOrder,
    val machine: Int,
    val entry: Long,
    val type: Int,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val raw: ByteArray,
) {
    private val byName = sections.groupBy { it.name }
    fun section(name: String): ElfSection? = byName[name]?.firstOrNull()
    fun sectionsNamed(name: String): List<ElfSection> = byName[name].orEmpty()

    /**
     * Map a file-relative virtual address (st_value style) to the section
     * whose [ElfSection.addr] region contains it. Returns all matches —
     * overlapping sections are legal and callers must keep every candidate.
     */
    fun sectionsAt(vaddr: Long): List<ElfSection> =
        sections.filter { it.addr != 0L && it.contains(vaddr) }

    companion object {
        const val ELFCLASS32 = 1
        const val ELFCLASS64 = 2
        const val SHT_SYMTAB = 2
        const val SHT_STRTAB = 3
    }
}
