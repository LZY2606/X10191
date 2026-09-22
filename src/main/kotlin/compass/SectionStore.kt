package compass

/** Raw debug sections extracted from one ELF file (empty section -> null). */
class SectionStore(val elf: ElfInfo, private val reader: ElfReader, private val fileBytes: ByteArray) {
    private val cache = HashMap<String, ByteArray?>()

    val sectionNames: Set<String> get() = elf.sections.map { it.name }.toSet()

    fun bytes(name: String): ByteArray? {
        if (name in cache) return cache[name]
        val sec = elf.sections.firstOrNull { it.name == name }
        val data = when {
            sec == null -> null
            sec.nobits -> ByteArray(0)
            sec.size <= 0 -> ByteArray(0)
            sec.size > Limits.MAX_SECTION_SIZE -> throw CursorException("section $name exceeds size limit (${sec.size})")
            else -> reader.sectionBytes(sec)
        }
        cache[name] = data
        return data
    }

    /** First present section among candidates, e.g. .debug_line vs .debug_line.dwo. */
    fun bytesAny(vararg names: String): Pair<String, ByteArray>? {
        for (n in names) {
            val b = bytes(n)
            if (b != null) return n to b
        }
        return null
    }

    fun sectionDigest(name: String): SectionDigest? = elf.section(name)
}
