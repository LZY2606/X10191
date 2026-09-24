package linecompass.dwarf

import linecompass.elf.ElfFile
import linecompass.elf.ElfSection
import java.security.MessageDigest

/** Digest + raw bytes of every DWARF-relevant section of one ELF file. */
class SectionBundle(val elf: ElfFile) {
    val bytes = HashMap<String, ByteArray>()
    val summaries = LinkedHashMap<String, SectionSummary>()

    init {
        for (s in elf.sections) {
            val isDwarf = s.name.startsWith(".debug") || s.name.startsWith(".zdebug") ||
                s.name == ".symtab" || s.name == ".strtab"
            if (!isDwarf) continue
            if (s.name.startsWith(".zdebug")) {
                summaries[s.name] = summary(s, compressed = true)
                continue
            }
            bytes[s.name] = s.data
            summaries[s.name] = summary(s, compressed = false)
        }
    }

    private fun summary(s: ElfSection, compressed: Boolean): SectionSummary {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(if (compressed) "COMPRESSED".toByteArray() else s.data)
        return SectionSummary(
            name = s.name,
            offset = s.offset,
            size = s.size,
            sha256 = hash.joinToString("") { "%02x".format(it) },
            allocated = s.isAllocated,
            addr = s.addr,
        )
    }

    fun reader(name: String): BoundedReader? = bytes[name]?.let {
        BoundedReader(it, 0, it.size, name)
    }

    fun get(name: String): ByteArray? = bytes[name]

    fun stringAt(offset: Int): String {
        val d = bytes[".debug_str"] ?: throw DwarfFormatException("DW_FORM_strp without .debug_str")
        return BoundedReader(d).stringAt(offset)
    }

    fun lineStringAt(offset: Int): String {
        val d = bytes[".debug_line_str"]
            ?: throw DwarfFormatException("DW_FORM_line_strp without .debug_line_str")
        return BoundedReader(d).stringAt(offset)
    }

    /**
     * DWARF 5 .debug_str_offsets: headers appear per CU contribution. We
     * locate the contribution by scanning for the header at [base] (the
     * value of DW_AT_str_offsets_base, already past the header). To keep
     * indexing simple we remember each base and its unit's address size.
     */
    fun strOffsetEntry(base: Int, index: Long, addressSize: Int): String {
        val d = bytes[".debug_str_offsets"]
            ?: throw DwarfFormatException("DW_FORM_strx* without .debug_str_offsets")
        val entrySize = addressSize
        val off = base + (index * entrySize).toInt()
        if (off < 0 || off + entrySize > d.size) {
            throw DwarfFormatException("str_offsets index $index past section end")
        }
        val r = BoundedReader(d, off, d.size - off, "debug_str_offsets", addressSize = addressSize)
        val strOff = if (entrySize == 4) r.u32() else r.u64()
        return stringAt(strOff.toInt())
    }

    /**
     * DWARF 5 .debug_addr table: [base] is DW_AT_addr_base (post-header).
     */
    fun addrEntry(base: Long, index: Long, addressSize: Int): Long {
        val d = bytes[".debug_addr"]
            ?: throw DwarfFormatException("DW_FORM_addrx* without .debug_addr")
        val off = base.toInt() + (index * addressSize).toInt()
        if (off < 0 || off + addressSize > d.size) {
            throw DwarfFormatException("addr index $index past .debug_addr end")
        }
        val r = BoundedReader(d, off, d.size - off, "debug_addr", addressSize = addressSize)
        return if (addressSize == 4) r.u32() else r.u64()
    }
}
