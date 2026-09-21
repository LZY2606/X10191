package compass.elf

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

class ElfParseException(message: String) : Exception(message)

data class ElfSection(
    val index: Int,
    val name: String,
    val type: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Long,
    val entsize: Long,
) {
    val isNobits: Boolean get() = type == SHT_NOBITS

    companion object {
        const val SHT_NOBITS = 8L
    }
}

data class ElfSegment(
    val type: Long,
    val vaddr: Long,
    val offset: Long,
    val filesz: Long,
    val memsz: Long,
)

/** Minimal, bounds-checked ELF32/ELF64 reader (little- and big-endian). */
class ElfFile private constructor(
    val bytes: ByteArray,
    val is64: Boolean,
    val order: ByteOrder,
    val sections: List<ElfSection>,
    val segments: List<ElfSegment>,
    val entry: Long,
    val elfType: Int,
) {
    private val byName: Map<String, ElfSection> = sections.associateBy { it.name }

    fun section(name: String): ElfSection? = byName[name]

    /** Raw bytes of a section. SHT_NOBITS sections have no file bytes; returns empty. */
    fun sectionBytes(name: String): ByteArray? {
        val s = byName[name] ?: return null
        return sectionBytes(s)
    }

    fun sectionBytes(s: ElfSection): ByteArray {
        if (s.isNobits) return ByteArray(0)
        if (s.size < 0 || s.offset < 0 || s.offset + s.size > bytes.size) {
            throw ElfParseException("section ${s.name} out of file bounds")
        }
        return bytes.copyOfRange(s.offset.toInt(), (s.offset + s.size).toInt())
    }

    fun sha256(): String = digest(bytes)

    companion object {
        const val MAX_SECTIONS = 1_000_000

        fun parse(bytes: ByteArray): ElfFile {
            if (bytes.size < 16) throw ElfParseException("file too small for ELF header")
            if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
                bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
            ) throw ElfParseException("not an ELF file (bad magic)")
            val is64 = when (bytes[4]) {
                1.toByte() -> false
                2.toByte() -> true
                else -> throw ElfParseException("unknown ELF class ${bytes[4]}")
            }
            val order = when (bytes[5]) {
                1.toByte() -> ByteOrder.LITTLE_ENDIAN
                2.toByte() -> ByteOrder.BIG_ENDIAN
                else -> throw ElfParseException("unknown ELF data encoding ${bytes[5]}")
            }
            val buf = ByteBuffer.wrap(bytes).order(order)

            fun u16(off: Int): Int {
                checkBounds(off, 2, bytes.size); return buf.getShort(off).toInt() and 0xFFFF
            }
            fun u32(off: Int): Long {
                checkBounds(off, 4, bytes.size); return buf.getInt(off).toLong() and 0xFFFFFFFFL
            }
            fun u64(off: Int): Long {
                checkBounds(off, 8, bytes.size); return buf.getLong(off)
            }

            val elfType = u16(16)
            val entry: Long
            val phoff: Long
            val shoff: Long
            val phentsize: Int
            val phnum: Int
            val shentsize: Int
            var shnum: Int
            var shstrndx: Int
            if (is64) {
                entry = u64(24); phoff = u64(32); shoff = u64(40)
                phentsize = u16(54); phnum = u16(56); shentsize = u16(58)
                shnum = u16(60); shstrndx = u16(62)
            } else {
                entry = u32(24); phoff = u32(28); shoff = u32(32)
                phentsize = u16(42); phnum = u16(44); shentsize = u16(46)
                shnum = u16(48); shstrndx = u16(50)
            }

            // Extended numbering: real counts live in section header 0.
            if (shoff != 0L && (shnum == 0 || shstrndx == 0xFFFF) && shentsize >= (if (is64) 64 else 40)) {
                if (shnum == 0) shnum = u32(shoff.toInt() + 32).toInt()
                if (shstrndx == 0xFFFF) shstrndx = u32(shoff.toInt() + 40).toInt()
            }
            if (shnum > MAX_SECTIONS) throw ElfParseException("unreasonable section count $shnum")

            data class Raw(val nameOff: Long, val type: Long, val addr: Long, val off: Long,
                           val size: Long, val link: Long, val entsize: Long)
            val raw = mutableListOf<Raw>()
            if (shoff != 0L && shnum > 0) {
                if (shentsize < (if (is64) 64 else 40)) throw ElfParseException("bad shentsize $shentsize")
                if (shoff + shentsize.toLong() * shnum > bytes.size) {
                    throw ElfParseException("section header table out of bounds")
                }
                for (i in 0 until shnum) {
                    val o = (shoff + i.toLong() * shentsize).toInt()
                    if (is64) {
                        raw.add(Raw(u32(o), u32(o + 4), u64(o + 16), u64(o + 24), u64(o + 32), u32(o + 40), u64(o + 56)))
                    } else {
                        raw.add(Raw(u32(o), u32(o + 4), u32(o + 12), u32(o + 16), u32(o + 20), u32(o + 24), u32(o + 36)))
                    }
                }
            }

            // Resolve names via shstrtab.
            val sections = raw.mapIndexed { i, r ->
                val nm = if (shstrndx in raw.indices) {
                    val str = raw[shstrndx]
                    if (str.off < 0 || str.off >= bytes.size) ""
                    else cString(bytes, str.off.toInt() + r.nameOff.toInt().coerceAtLeast(0),
                        (str.off + str.size).toInt().coerceAtMost(bytes.size))
                } else ""
                ElfSection(i, nm, r.type, r.addr, r.off, r.size, r.link, r.entsize)
            }

            val segments = mutableListOf<ElfSegment>()
            if (phoff != 0L && phnum > 0) {
                val minPh = if (is64) 56 else 32
                if (phentsize < minPh) throw ElfParseException("bad phentsize $phentsize")
                if (phoff + phentsize.toLong() * phnum > bytes.size) {
                    throw ElfParseException("program header table out of bounds")
                }
                for (i in 0 until phnum) {
                    val o = (phoff + i.toLong() * phentsize).toInt()
                    if (is64) {
                        segments.add(ElfSegment(u32(o), u64(o + 16), u64(o + 8), u64(o + 32), u64(o + 40)))
                    } else {
                        segments.add(ElfSegment(u32(o), u32(o + 4), u32(o + 8), u32(o + 16), u32(o + 20)))
                    }
                }
            }

            return ElfFile(bytes, is64, order, sections, segments, entry, elfType)
        }

        private fun checkBounds(off: Int, len: Int, size: Int) {
            if (off < 0 || len < 0 || off + len > size) throw ElfParseException("read past end of file at $off")
        }

        /** Read a NUL-terminated string from [buf] at absolute [off], not past [limit]. */
        fun cString(buf: ByteArray, off: Int, limit: Int = buf.size): String {
            if (off < 0 || off >= limit) return ""
            var end = off
            while (end < limit && buf[end] != 0.toByte()) end++
            return String(buf, off, end - off, Charsets.UTF_8)
        }

        fun digest(bytes: ByteArray): String {
            val md = MessageDigest.getInstance("SHA-256")
            return md.digest(bytes).joinToString("") { "%02x".format(it) }
        }
    }
}
