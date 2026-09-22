package compass.dwarf

import compass.elf.ElfFile
import java.security.MessageDigest

data class SectionBlob(
    val name: String,
    val bytes: ByteArray,
    val size: Long,
    val address: Long,
    val sha256: String,
)

class DebugSections(private val blobs: Map<String, SectionBlob>) {
    operator fun get(name: String): SectionBlob? = blobs[name]
    fun has(name: String): Boolean = blobs[name]?.bytes?.isNotEmpty() == true
    fun names(): Set<String> = blobs.keys

    companion object {
        val DEBUG_SECTION_NAMES = listOf(
            ".debug_info", ".debug_abbrev", ".debug_line", ".debug_line_str", ".debug_str",
            ".debug_str_offsets", ".debug_addr", ".debug_ranges", ".debug_rnglists",
            ".debug_types", ".debug_loclists", ".debug_loc", ".debug_frame", ".eh_frame",
            ".debug_cu_index", ".debug_tu_index",
        )

        fun fromElf(elf: ElfFile, dwoElf: ElfFile? = null): DebugSections {
            val map = LinkedHashMap<String, SectionBlob>()
            collect(elf, map)
            if (dwoElf != null) collect(dwoElf, map, suffixNote = true)
            return DebugSections(map)
        }

        private fun collect(elf: ElfFile, map: LinkedHashMap<String, SectionBlob>, suffixNote: Boolean = false) {
            for (sec in elf.sections) {
                if (sec.name.startsWith(".debug") || sec.name == ".eh_frame") {
                    val bytes = try {
                        elf.sectionBytes(sec.name)
                    } catch (_: Exception) {
                        continue
                    } ?: continue
                    val md = MessageDigest.getInstance("SHA-256").digest(bytes)
                    val hex = md.joinToString("") { "%02x".format(it) }
                    val key = if (suffixNote && sec.name == ".debug_info.dwo") ".debug_info" else normalizeDwo(sec.name)
                    // Keep both variants; prefer non-dwo sections already present.
                    if (map.containsKey(key) && suffixNote) {
                        map["${sec.name}"] = SectionBlob(sec.name, bytes, sec.size, sec.address, hex)
                    } else {
                        map[key] = SectionBlob(sec.name, bytes, sec.size, sec.address, hex)
                    }
                }
            }
        }

        private fun normalizeDwo(name: String): String = when (name) {
            ".debug_info.dwo" -> ".debug_info.dwo"
            ".debug_abbrev.dwo" -> ".debug_abbrev.dwo"
            ".debug_line.dwo" -> ".debug_line.dwo"
            ".debug_str_offsets.dwo" -> ".debug_str_offsets.dwo"
            ".debug_str.dwo" -> ".debug_str.dwo"
            ".debug_rnglists.dwo" -> ".debug_rnglists.dwo"
            ".debug_addr.dwo" -> ".debug_addr.dwo"
            else -> name
        }
    }
}
