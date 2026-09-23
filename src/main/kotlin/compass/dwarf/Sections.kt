package compass.dwarf

import compass.elf.ElfFile
import compass.elf.Reader
import java.nio.ByteOrder

/** Thrown when a form/unit cannot be safely decoded; the CU is isolated. */
class UnknownFormException(val form: Int, message: String) : Exception(message)

/**
 * Access to raw DWARF section bytes. Split-DWARF companion sections
 * (`*.dwo`) are merged into the same lookup: a main executable and its
 * companion contribute different section names where the formats differ
 * (e.g. `.debug_info.dwo`).
 */
class Sections(files: List<ElfFile>, val endian: ByteOrder) {
    private val blobs = HashMap<String, ByteArray>()

    init {
        for (f in files) {
            for (s in f.sections) {
                if (s.name.startsWith(".debug") || s.name.startsWith(".zdebug")) {
                    // First occurrence wins for standard names; .dwo names coexist.
                    blobs.putIfAbsent(stripCompression(s.name), s.data)
                }
            }
        }
    }

    fun has(name: String): Boolean = blobs[name]?.isNotEmpty() == true
    fun bytes(name: String): ByteArray? = blobs[name]
    fun reader(name: String): Reader? = blobs[name]?.let { Reader(it, endian, name) }
    fun size(name: String): Int = blobs[name]?.size ?: 0
    fun names(): Set<String> = blobs.keys.filter { blobs[it]!!.isNotEmpty() }.toSet()

    /** Read a .debug_str / .debug_line_str string at a bounded offset. */
    fun strAt(section: String, off: Long): String {
        val b = blobs[section] ?: throw ParseError("$section section missing")
        val r = Reader(b, endian, section)
        r.seek(off.toIntExact())
        return r.zeroString()
    }

    companion object {
        fun stripCompression(name: String): String =
            name.removePrefix(".zdebug").let { if (name.startsWith(".zdebug")) ".debug$it" else name }
    }
}
