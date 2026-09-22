package compass.dwarf

import compass.elf.ElfFile
import compass.util.ByteReader
import compass.util.ParseException

/** Raw debug sections from one ELF object, with GNU split-DWARF aliases. */
class Sections private constructor(private val raw: Map<String, ByteArray>) {
    fun has(name: String): Boolean = (raw[name]?.isNotEmpty()) == true
    fun bytes(name: String): ByteArray = raw[name] ?: ByteArray(0)
    fun reader(name: String): ByteReader? = raw[name]?.takeIf { it.isNotEmpty() }?.let { ByteReader(it, 0, it.size) }
    fun size(name: String): Int = raw[name]?.size ?: 0
    fun names(): Set<String> = raw.keys.filter { (raw[it]?.isNotEmpty()) == true }.toSet()

    companion object {
        private val NAMES = listOf(
            "debug_info", "debug_abbrev", "debug_str", "debug_str_offsets",
            "debug_line", "debug_line_str", "debug_addr", "debug_ranges",
            "debug_rnglists", "debug_str_sup", "debug_info.dwo", "debug_abbrev.dwo",
            "debug_str.dwo", "debug_str_offsets.dwo", "debug_line.dwo",
            "debug_line_str.dwo", "debug_rnglists.dwo"
        )

        fun from(elf: ElfFile, dwo: Boolean): Sections {
            val map = LinkedHashMap<String, ByteArray>()
            for (key in NAMES) {
                val candidates = when {
                    key.endsWith(".dwo") -> {
                        val stem = key.removeSuffix(".dwo")
                        listOf(".debug_$key", ".zdebug_$key", ".debug_$stem", ".zdebug_$stem")
                    }
                    else -> {
                        listOf(".debug_$key", ".debug_$key.dwo", ".zdebug_$key")
                    }
                }
                for (c in candidates) {
                    val sec = elf.section(c) ?: continue
                    val data = try { elf.readSectionBytes(sec) } catch (_: Exception) { continue }
                    if (data.isNotEmpty()) {
                        map[key] = data
                        break
                    }
                }
            }
            return Sections(map)
        }
    }
}

/** Header info for a .debug_addr contribution. */
data class AddrTable(val base: Long, val addresses: List<Long>)

object AddrTables {
    /** Parse the whole .debug_addr into contributions starting at each DW_AT_addr_base. */
    fun parseAll(s: Sections, le: Boolean): Map<Long, List<Long>> {
        val r = s.reader("debug_addr") ?: return emptyMap()
        val out = LinkedHashMap<Long, List<Long>>()
        while (r.remaining() > 0) {
            val base = r.position.toLong()
            val startPos = r.position
            try {
                val list = ArrayList<Long>()
                if (r.remaining() < 8) break
                // DWARF5 contributions have a header; bare GNU tables do not. Try to detect.
                // We record both: parse a best-effort DWARF5 header, fallback to raw table.
                val unitLength = r.u32(le)
                if (unitLength in 12..r.remaining().toLong() + 4 && r.remaining() >= 4) {
                    val version = r.u16(le)
                    if (version in 3..6) {
                        r.u8(); r.u8() // address_size, segment_selector_size
                        val dataEnd = r.position - 6 + unitLength.toInt()
                        while (r.position < dataEnd - 7) list.add(r.u64(le))
                        r.position = dataEnd
                        out[base] = list
                        continue
                    }
                }
                // GNU / raw: entire section is addresses; keys map to GNU addr_base offsets.
                r.position = startPos
                while (r.remaining() >= 8) list.add(r.u64(le))
                out[0L] = list
                break
            } catch (_: Exception) {
                r.position = startPos
                break
            }
        }
        return out
    }

    fun lookup(tables: Map<Long, List<Long>>, base: Long, index: Long): Long {
        val list = tables[base] ?: throw ParseException("no .debug_addr contribution at base 0x${base.toString(16)}")
        val idx = index.toInt()
        if (idx < 0 || idx >= list.size) throw ParseException("addrx index $index out of range (base 0x${base.toString(16)}, n=${list.size})")
        return list[idx]
    }
}
